/**
 * sync.ts — D1 sync proxy (phone -> Workers -> D1).
 *
 * Auth: device paired hona chahiye (D1 devices lookup) + request signed
 * hona chahiye (device Ed25519 key, canonical string — crypto.ts).
 * Sync scope (Pehle-Jaanch §3.4): traces + counters + job acks.
 * Chat history (30 turns) device-local rehti hai — sync nahi hoti.
 *
 * Conflict rule (frozen): SERVER-WINS. Device apna last_seq bhejta hai;
 * server apna last_seq deta hai; device ka seq peeche ho to device apna
 * local state server copy se overwrite karta hai (client-side rule —
 * yahan sirf seq numbers exchange hote hain).
 */

import { isTimestampFresh, verifySignature } from "./crypto";
import { getDevice, insertTrace, type D1Like } from "./db";

export interface SyncRequest {
  device_id: string;
  table: "traces" | "counters";
  rows: Record<string, unknown>[];
  last_seq: number;
  nonce: string;
  ts: number;
  sig: string; // base64 Ed25519 over canonical(device_id, nonce, ts, rawRowsJson)
}

export interface SyncResult {
  ok: boolean;
  server_seq: number;
  accepted: number;
  error?: string;
}

export async function handleSync(db: D1Like, req: SyncRequest, rawRowsJson: string): Promise<SyncResult> {
  const device = await getDevice(db, req.device_id);
  if (!device || device.enabled === 0) {
    return { ok: false, server_seq: 0, accepted: 0, error: "device_not_paired" };
  }
  if (!isTimestampFresh(req.ts, Date.now())) {
    return { ok: false, server_seq: 0, accepted: 0, error: "stale_timestamp" };
  }
  const valid = await verifySignature(
    device.public_key,
    req.sig,
    req.device_id,
    req.nonce,
    req.ts,
    rawRowsJson,
  );
  if (!valid) {
    return { ok: false, server_seq: 0, accepted: 0, error: "bad_signature" };
  }
  let accepted = 0;
  if (req.table === "traces") {
    for (const row of req.rows) {
      const kind = typeof row.kind === "string" ? row.kind : "unknown";
      const detail = (row.detail as Record<string, unknown>) ?? {};
      await insertTrace(db, device.tenant_id, req.device_id, kind, detail);
      accepted++;
    }
  } else {
    // counters: rows are { replies, e2b_runs } increments for current YYYY-MM.
    const period = new Date().toISOString().slice(0, 7);
    let replies = 0;
    let e2bRuns = 0;
    for (const row of req.rows) {
      replies += typeof row.replies === "number" ? row.replies : 0;
      e2bRuns += typeof row.e2b_runs === "number" ? row.e2b_runs : 0;
    }
    if (replies !== 0 || e2bRuns !== 0) {
      await db
        .prepare(
          "INSERT INTO usage_counters (tenant_id, period, replies, e2b_runs) VALUES (?, ?, ?, ?) " +
            "ON CONFLICT(tenant_id, period) DO UPDATE SET " +
            "replies = usage_counters.replies + excluded.replies, " +
            "e2b_runs = usage_counters.e2b_runs + excluded.e2b_runs",
        )
        .bind(device.tenant_id, period, replies, e2bRuns)
        .run();
      accepted = req.rows.length;
    }
  }
  const seqRow = await db
    .prepare("SELECT last_seq FROM sync_state WHERE device_id = ? AND table_name = ?")
    .bind(req.device_id, req.table)
    .first<{ last_seq: number }>();
  const serverSeq = seqRow ? seqRow.last_seq : 0;
  await db
    .prepare(
      "INSERT INTO sync_state (device_id, table_name, last_seq) VALUES (?, ?, ?) " +
        "ON CONFLICT(device_id, table_name) DO UPDATE SET last_seq = excluded.last_seq",
    )
    .bind(req.device_id, req.table, Math.max(serverSeq, req.last_seq))
    .run();
  return { ok: true, server_seq: Math.max(serverSeq, req.last_seq), accepted };
}
