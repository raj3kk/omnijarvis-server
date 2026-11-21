/**
 * crypto.ts — Ed25519 verify + base64 helpers (WebCrypto, Workers + Node).
 *
 * DESIGN CORRECTION vs Pehle-Jaanch §3.5 wording: signed messages flow
 * DEVICE -> HUB (HELLO, STEP_RESULT, /api/sync calls). The device holds
 * the private key (Android Keystore); the hub holds the public key and
 * VERIFIES. EXECUTE_STEP flows HUB -> DEVICE over the WS session that
 * was itself established with a signed HELLO — the hub cannot sign with
 * the device key (it never has the private key), and does not need to:
 * the channel is authenticated at establishment (TLS + known hub URL).
 *
 * Canonical signed string (frozen):
 *   device_id + "\n" + nonce + "\n" + ts + "\n" + payload_raw
 * payload_raw is the EXACT string the device sends (no re-serialization
 * on the hub — key-order fragility se bachne ke liye).
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
