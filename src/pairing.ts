/**
 * pairing.ts — pairing token issue / 6-digit derivation / register.
 *
 * Flow (Pehle-Jaanch §3.5, refined): init -> QR/6-digit -> confirm ->
 * register. Token D1 `pairing_tokens` me rehta hai (5-min TTL, one-time
 * use — register ke baad delete). 6-digit = first-6-digits of
 * SHA-256(token) as uint32 mod 1,000,000, zero-padded — dono taraf same
 * code dikhta hai; token khud kabhi screen par nahi aata.
 */
import { randomNonceHex } from "./crypto";
import type { D1Like } from "./db";

export const PAIRING_TOKEN_TTL_MS = 300_000; // 5 min

export async function deriveSixDigit(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const view = new DataView(digest);
  const num = view.getUint32(0, false) % 1_000_000;
  return String(num).padStart(6, "0");
}

export function newPairingToken(): string {
  return randomNonceHex(16); // 128-bit hex
}

/**
 * Tenant fallback (2b-1): the app cannot know its Supabase tenant id at
 * pairing time — `licences` has user_id (auth UUID), no tenant_id, and
 * `verifyLicenceKey` returns a boolean only. So when init arrives
 * without a tenant_id, derive a stable, non-reversible D1-local label
 * from the licence key. Phase 4 (real tenants from owner_email)
 * migrates this; until then the value is a label only — D1 has no FK
 * into Supabase tenants.
 */
export async function deriveTenantId(licenceKey: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(licenceKey));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `lic-${hex.slice(0, 16)}`;
}

export async function issuePairingToken(
  db: D1Like,
  deviceId: string,
  tenantId: string,
): Promise<{ token: string; code: string; expiresAt: number }> {
  const token = newPairingToken();
  const expiresAt = Date.now() + PAIRING_TOKEN_TTL_MS;
  await db
    .prepare("INSERT INTO pairing_tokens (token, device_id, tenant_id, expires_at) VALUES (?, ?, ?, ?)")
    .bind(token, deviceId, tenantId, expiresAt)
    .run();
  return { token, code: await deriveSixDigit(token), expiresAt };
}

export interface PairingTokenRow {
  token: string;
  device_id: string;
  tenant_id: string;
  expires_at: number;
}

export async function consumePairingToken(
  db: D1Like,
  token: string,
): Promise<PairingTokenRow | null> {
  const row = await db
    .prepare("SELECT token, device_id, tenant_id, expires_at FROM pairing_tokens WHERE token = ?")
    .bind(token)
    .first<PairingTokenRow>();
  if (!row) return null;
  // One-time use: delete first (race-safe enough for pairing; a replayed
  // token finds no row on the second attempt).
  await db.prepare("DELETE FROM pairing_tokens WHERE token = ?").bind(token).run();
  if (row.expires_at < Date.now()) return null;
  return row;
}

export async function registerDevice(
  db: D1Like,
  deviceId: string,
  tenantId: string,
  publicKeyB64: string,
): Promise<void> {
  const now = Date.now();
  await db
    .prepare(
      "INSERT INTO devices (device_id, tenant_id, public_key, paired_at, last_seen, enabled) " +
        "VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(device_id) DO UPDATE SET public_key = excluded.public_key, last_seen = excluded.last_seen",
    )
    .bind(deviceId, tenantId, publicKeyB64, now, now, 1)
    .run();
}
