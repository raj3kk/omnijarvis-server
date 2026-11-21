import { describe, expect, it } from "vitest";
import { FakeD1 } from "./fake-d1";
import { handleSync, type SyncRequest } from "../src/sync";
import { registerDevice } from "../src/pairing";
import { canonicalString } from "../src/crypto";
import { genDeviceKey } from "./helpers";

async function signedSyncReq(
  key: Awaited<ReturnType<typeof genDeviceKey>>,
  deviceId: string,
  table: "traces" | "counters",
  rows: Record<string, unknown>[],
): Promise<SyncRequest> {
  const raw = JSON.stringify(rows);
  const ts = Date.now();
  const nonce = "nonce-" + Math.random().toString(36).slice(2);
  const sig = await key.sign(canonicalString(deviceId, nonce, ts, raw));
  return { device_id: deviceId, table, rows, last_seq: 1, nonce, ts, sig };
}

describe("sync proxy", () => {
  it("unpaired device -> device_not_paired", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    const req = await signedSyncReq(key, "dev-ghost", "traces", [{ kind: "x", detail: {} }]);
    const res = await handleSync(db, req, JSON.stringify(req.rows));
    expect(res.ok).toBe(false);
    expect(res.error).toBe("device_not_paired");
  });

  it("bad signature -> bad_signature", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "tenant-1", key.publicKeyB64);
    const req = await signedSyncReq(key, "dev-1", "traces", [{ kind: "x", detail: {} }]);
    req.rows = [{ kind: "tampered", detail: {} }]; // rows changed after signing
    const res = await handleSync(db, req, JSON.stringify(req.rows));
    expect(res.ok).toBe(false);
    expect(res.error).toBe("bad_signature");
  });

  it("stale timestamp -> stale_timestamp", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "tenant-1", key.publicKeyB64);
    const req = await signedSyncReq(key, "dev-1", "traces", [{ kind: "x", detail: {} }]);
    req.ts = Date.now() - 10 * 60_000;
    const res = await handleSync(db, req, JSON.stringify(req.rows));
    expect(res.ok).toBe(false);
    expect(res.error).toBe("stale_timestamp");
  });

  it("valid traces sync -> accepted + rows in D1", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "tenant-1", key.publicKeyB64);
    const rows = [
      { kind: "step_result", detail: { ok: true } },
      { kind: "step_result", detail: { ok: false } },
    ];
    const req = await signedSyncReq(key, "dev-1", "traces", rows);
    const res = await handleSync(db, req, JSON.stringify(rows));
    expect(res.ok).toBe(true);
    expect(res.accepted).toBe(2);
    const stored = await db.prepare("SELECT * FROM traces").bind().all();
    expect(stored.results.length).toBe(2);
  });

  it("counters sync -> usage_counters increment across syncs", async () => {
    const db = new FakeD1();
    const key = await genDeviceKey();
    await registerDevice(db, "dev-1", "tenant-1", key.publicKeyB64);
    const rows = [{ replies: 5, e2b_runs: 2 }];
    const req1 = await signedSyncReq(key, "dev-1", "counters", rows);
    expect((await handleSync(db, req1, JSON.stringify(rows))).ok).toBe(true);
    const req2 = await signedSyncReq(key, "dev-1", "counters", rows);
    expect((await handleSync(db, req2, JSON.stringify(rows))).ok).toBe(true);
    const counters = await db.prepare("SELECT * FROM usage_counters").bind().all();
    expect(counters.results.length).toBe(1);
    const row = counters.results[0] as Record<string, unknown>;
    expect(row.replies).toBe(10);
    expect(row.e2b_runs).toBe(4);
  });
});
