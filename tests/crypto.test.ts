import { describe, expect, it } from "vitest";
import {
  canonicalString,
  isTimestampFresh,
  randomNonceHex,
  verifySignature,
} from "../src/crypto";
import { genDeviceKey } from "./helpers";

describe("crypto (Ed25519)", () => {
  it("sign -> verify round-trip passes", async () => {
    const key = await genDeviceKey();
    const payload = '{"hello":true}';
    const sig = await key.sign(canonicalString("dev-1", "abc123", 1700000000000, payload));
    expect(await verifySignature(key.publicKeyB64, sig, "dev-1", "abc123", 1700000000000, payload)).toBe(
      true,
    );
  });

  it("tampered payload -> false", async () => {
    const key = await genDeviceKey();
    const sig = await key.sign(canonicalString("dev-1", "abc123", 1700000000000, '{"hello":true}'));
    expect(
      await verifySignature(key.publicKeyB64, sig, "dev-1", "abc123", 1700000000000, '{"hello":false}'),
    ).toBe(false);
  });

  it("wrong device_id -> false", async () => {
    const key = await genDeviceKey();
    const sig = await key.sign(canonicalString("dev-1", "abc123", 1700000000000, "x"));
    expect(await verifySignature(key.publicKeyB64, sig, "dev-2", "abc123", 1700000000000, "x")).toBe(
      false,
    );
  });

  it("malformed key/signature -> false (fail-closed)", async () => {
    expect(await verifySignature("!!!not-base64!!!", "abcd", "d", "n", 1, "x")).toBe(false);
    const key = await genDeviceKey();
    expect(await verifySignature(key.publicKeyB64, "!!!", "d", "n", 1, "x")).toBe(false);
  });

  it("timestamp freshness: now true, ±6min false, ±4min true", () => {
    const now = Date.now();
    expect(isTimestampFresh(now, now)).toBe(true);
    expect(isTimestampFresh(now - 6 * 60_000, now)).toBe(false);
    expect(isTimestampFresh(now + 6 * 60_000, now)).toBe(false);
    expect(isTimestampFresh(now - 4 * 60_000, now)).toBe(true);
  });

  it("randomNonceHex: 32 hex chars, unique", () => {
    const a = randomNonceHex();
    const b = randomNonceHex();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});
