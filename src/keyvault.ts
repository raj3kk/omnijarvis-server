/**
 * keyvault.ts — AES-GCM encrypt/decrypt for per-tenant BYOK Gemini keys.
 *
 * Design (Pehle-Jaanch §1 S-2): keys live encrypted in D1
 * `tenants.gemini_key_enc` — never plaintext in logs/repo/DB.
 * Master key = Workers secret KEY_ENC_SECRET (32-byte base64, set by the
 * deploy script, stored in the 0600 env file — never printed).
 * Envelope: base64( iv 12B || ciphertext ) — AES-GCM, random IV per key.
 * Master key rotation: old envelopes become undecryptable — the tenant
 * must re-enter their key (`key_decrypt_failed` error, documented).
 * WebCrypto (Workers + Node 22) — no dependency.
 */
import { base64ToBytes, bytesToBase64 } from "./crypto";

export async function importMasterKey(secretB64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(secretB64);
  if (raw.length !== 32) throw new Error("master key must be 32 bytes");
  return await crypto.subtle.importKey("raw", raw.buffer as ArrayBuffer, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encryptTenantKey(master: CryptoKey, plaintext: string): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const ct = new Uint8Array(
    (await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
      master,
      new TextEncoder().encode(plaintext),
    )) as ArrayBuffer,
  );
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return bytesToBase64(out);
}

export async function decryptTenantKey(master: CryptoKey, stored: string): Promise<string> {
  const raw = base64ToBytes(stored);
  if (raw.length < 13) throw new Error("bad envelope");
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as ArrayBuffer },
    master,
    ct.buffer as ArrayBuffer,
  );
  return new TextDecoder().decode(pt);
}
