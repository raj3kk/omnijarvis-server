/**
 * crypto.ts — Ed25519 verify + sign + base64 helpers (WebCrypto, Workers + Node).
 *
 * Message directions (M-4, supersedes the old design correction below):
 * - DEVICE -> HUB: HELLO, STEP_RESULT, /api/sync calls. Device holds its
 *   private key (Android Keystore); hub VERIFIES with the registered
 *   public key.
 * - HUB -> DEVICE: EXECUTE_STEP. Hub SIGNS with its own Ed25519 key
 *   (Workers secret HUB_SIGN_SECRET, PKCS8 base64); device verifies with
 *   the hub public key delivered at pairing (register response) or via
 *   HELLO_ACK bootstrap. Verify-fail -> step rejected, never executed.
 *
 * Old design correction (superseded by M-4, kept for history): EXECUTE_STEP
 * used to flow unsigned over the WS session established with a signed
 * HELLO. That left replay + stale-queue open; hub signing closes both.
 *
 * Canonical signed string (frozen):
 *   device_id + "\n" + nonce + "\n" + ts + "\n" + payload_raw
 * payload_raw is the EXACT string the sender built (no re-serialization
 * on the other side — key-order fragility se bachne ke liye).
 * - nonce: 128-bit hex, one-time (DO SQLite, 5-min expiry).
 * - ts: unix ms; window ±5 min (clock skew).
 */

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function canonicalString(
  deviceId: string,
  nonce: string,
  ts: number,
  payloadRaw: string,
): string {
  return `${deviceId}\n${nonce}\n${ts}\n${payloadRaw}`;
}

export async function importPublicKey(publicKeyB64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(publicKeyB64);
  return await crypto.subtle.importKey("raw", raw.buffer as ArrayBuffer, { name: "Ed25519" }, false, [
    "verify",
  ]);
}

export async function verifySignature(
  publicKeyB64: string,
  signatureB64: string,
  deviceId: string,
  nonce: string,
  ts: number,
  payloadRaw: string,
): Promise<boolean> {
  try {
    const key = await importPublicKey(publicKeyB64);
    const sig = base64ToBytes(signatureB64);
    const data = new TextEncoder().encode(canonicalString(deviceId, nonce, ts, payloadRaw));
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig.buffer as ArrayBuffer, data);
  } catch {
    return false; // fail-closed: malformed key/signature = reject
  }
}

export function isTimestampFresh(ts: number, nowMs: number, windowMs = 300_000): boolean {
  return Math.abs(nowMs - ts) <= windowMs;
}

export function randomNonceHex(bytes = 16): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- M-4: hub-side signing (HUB -> DEVICE EXECUTE_STEP) ---

/** Hub key version label (frozen, M-4 §3.1). Rotation = new id + re-pair. */
export const HUB_KEY_ID = "hub-1";

/**
 * Import the hub private key from the HUB_SIGN_SECRET Workers secret
 * (PKCS8 DER, base64). Sign-only. Throws on malformed secret — the
 * caller treats that as sign-fail (fail-closed: never send unsigned).
 */
export async function importPrivateKey(secretB64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(secretB64);
  // extractable=true: deriveHubPublicKeyB64 needs a JWK export of the
  // PUBLIC coordinate ("x") from this key. The CryptoKey object never
  // leaves the isolate and only "x" is ever exported — the private
  // value ("d") is never read out, logged, or returned.
  return await crypto.subtle.importKey(
    "pkcs8",
    raw.buffer as ArrayBuffer,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
}

/**
 * Derive the hub public key (raw 32-byte, base64) from an imported
 * private key, via its JWK "x" coordinate. Public value — safe to
 * return in register / HELLO_ACK responses and to log.
 */
export async function deriveHubPublicKeyB64(privateKey: CryptoKey): Promise<string> {
  const jwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  if (!jwk.x) throw new Error("private key has no public coordinate");
  // JWK "x" is base64url; our wire format is standard base64.
  return jwk.x.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (jwk.x.length % 4)) % 4);
}

/**
 * Sign a hub->device message: canonical string + Ed25519 -> base64.
 * Reuses canonicalString() — same string both directions (§3.1).
 */
export async function signHubMessage(
  privateKey: CryptoKey,
  deviceId: string,
  nonce: string,
  ts: number,
  payloadRaw: string,
): Promise<string> {
  const data = new TextEncoder().encode(canonicalString(deviceId, nonce, ts, payloadRaw));
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, data);
  return bytesToBase64(new Uint8Array(sig));
}

export interface HubEnv {
  HUB_SIGN_SECRET?: string;
}

export interface HubPublicKey {
  publicKeyB64: string;
  keyId: string;
}

/**
 * Shared helper (single place — no duplication between hub.ts register
 * and JarvisHub.ts HELLO_ACK): derive the hub public key from the
 * Workers secret. Returns null when the secret is missing/invalid —
 * callers omit the key fields (pairing still succeeds; the device
 * bootstraps the key from HELLO_ACK, or rejects steps until it has one).
 * The private value is never returned, logged, or stored.
 */
export async function getHubPublicKey(env: HubEnv): Promise<HubPublicKey | null> {
  if (!env.HUB_SIGN_SECRET) return null;
  try {
    const priv = await importPrivateKey(env.HUB_SIGN_SECRET);
    return { publicKeyB64: await deriveHubPublicKeyB64(priv), keyId: HUB_KEY_ID };
  } catch {
    return null;
  }
}
