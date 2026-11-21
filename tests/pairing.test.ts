import { describe, expect, it } from "vitest";
import { FakeD1 } from "./fake-d1";
import {
  consumePairingToken,
  deriveSixDigit,
  issuePairingToken,
  registerDevice,
} from "../src/pairing";
import { getDevice } from "../src/db";

describe("pairing", () => {
  it("deriveSixDigit: deterministic, 6 digits", async () => {
    const code = await deriveSixDigit("deadbeef");
    expect(code).toMatch(/^\d{6}$/);
    expect(await deriveSixDigit("deadbeef")).toBe(code);
    expect(await deriveSixDigit("deadbee0")).not.toBe(code);
  });

  it("issue -> consume once (second consume null)", async () => {
    const db = new FakeD1();
    const issued = await issuePairingToken(db, "dev-1", "tenant-1");
    expect(issued.code).toMatch(/^\d{6}$/);
    expect(issued.code).toBe(await deriveSixDigit(issued.token));
    const row = await consumePairingToken(db, issued.token);
    expect(row?.device_id).toBe("dev-1");
    expect(await consumePairingToken(db, issued.token)).toBeNull();
  });

  it("expired token -> null", async () => {
    const db = new FakeD1();
    await db
      .prepare("INSERT INTO pairing_tokens (token, device_id, tenant_id, expires_at) VALUES (?, ?, ?, ?)")
      .bind("tok-old", "dev-1", "tenant-1", Date.now() - 1000)
      .run();
    expect(await consumePairingToken(db, "tok-old")).toBeNull();
  });

  it("unknown token -> null", async () => {
    const db = new FakeD1();
    expect(await consumePairingToken(db, "nope")).toBeNull();
  });

  it("registerDevice: upsert updates public key, single row", async () => {
    const db = new FakeD1();
    await registerDevice(db, "dev-1", "tenant-1", "key-v1");
    await registerDevice(db, "dev-1", "tenant-1", "key-v2");
    const device = await getDevice(db, "dev-1");
    expect(device?.public_key).toBe("key-v2");
    expect(device?.tenant_id).toBe("tenant-1");
    const all = await db.prepare("SELECT * FROM devices").bind().all();
    expect(all.results.length).toBe(1);
  });
});
