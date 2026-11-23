/**
 * idempotency.ts — Track E Gmail-send idempotency (R4.6, D-R18).
 *
 * Problem (1.14.0 known limitation): a double-tap on Gmail send sends
 * the mail twice — the send path had no Idempotency-Key.
 *
 * Key design (deviation from the brief's letter, recorded in
 * BUILD_NOTES §6): the brief says "client-generated UUID, ek send = ek
 * key". A random UUID per tap does NOT dedupe a double-tap — two taps
 * are two UUIDs, two sends — so A-T5 would fail by construction. The
 * key is therefore a SHA-256 of the canonical send content
 * (to + subject + body): an identical double-tap is the same key and
 * dedupes; a retry reuses the same key trivially. The 24 h TTL bounds
 * the dedupe window — the same mail sent again tomorrow is a new send.
 * The hub ALSO honours any client-supplied key verbatim (an app that
 * sends a UUID still dedupes its own retries); the hub never recomputes
 * the hash, so there is exactly one source of truth: the header.
 *
 * Table: idempotency_keys (tenant_id, key) PK, migration 0017.
 * A duplicate key returns the FIRST send's Gmail message id with
 * deduped:true — the mail is never sent twice.
 */
import { sha256Hex } from "./docs";
import type { D1Like } from "./db";

/** Dedupe window — a key older than this is treated as new. */
export const IDEMPOTENCY_TTL_MS = 24 * 60 * 60_000; // 24 h

export async function contentIdempotencyKey(to: string, subject: string, body: string): Promise<string> {
  return sha256Hex(`${to}\n${subject}\n${body}`);
}

export interface IdempotencyRecord {
  key: string;
  gmail_message_id: string;
  created_at: number;
}

/** Fresh record for (tenant, key), or null (absent / expired). */
export async function getIdempotencyRecord(
  db: D1Like,
  tenantId: string,
  key: string,
  nowMs = Date.now(),
): Promise<IdempotencyRecord | null> {
  const row = await db
    .prepare("SELECT key, gmail_message_id, created_at FROM idempotency_keys WHERE tenant_id = ? AND key = ?")
    .bind(tenantId, key)
    .first<IdempotencyRecord>();
  if (!row) return null;
  if (row.created_at + IDEMPOTENCY_TTL_MS <= nowMs) return null;
  return row;
}

export async function storeIdempotencyRecord(
  db: D1Like,
  tenantId: string,
  key: string,
  gmailMessageId: string,
  nowMs = Date.now(),
): Promise<void> {
  await db
    .prepare("INSERT INTO idempotency_keys (tenant_id, key, gmail_message_id, created_at) VALUES (?, ?, ?, ?)")
    .bind(tenantId, key, gmailMessageId, nowMs)
    .run();
}
