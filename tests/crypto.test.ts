import { describe, expect, it } from "vitest";
import {
  canonicalString,
  deriveHubPublicKeyB64,
  getHubPublicKey,
  importPrivateKey,
  isTimestampFresh,
  randomNonceHex,
  signHubMessage,
  verifySignature,
} from "../src/crypto";
import { genDeviceKey, genHubKey } from "./helpers";

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

describe("crypto (M-4 hub signing)", () => {
  it("signHubMessage -> verifySignature round-trip passes", async () => {
    const hub = await genHubKey();
    const priv = await importPrivateKey(hub.privateKeyB64);
    const payload = '{"kind":"CRON_COMMAND","command":"open youtube","job_id":"job-1"}';
    const sig = await signHubMessage(priv, "dev-1", "aabbccddeeff00112233445566778899", 1700000000000, payload);
    expect(
      await verifySignature(hub.publicKeyB64, sig, "dev-1", "aabbccddeeff00112233445566778899", 1700000000000, payload),
    ).toBe(true);
  });

  it("hub sign: tampered payload -> false", async () => {
    const hub = await genHubKey();
    const priv = await importPrivateKey(hub.privateKeyB64);
    const sig = await signHubMessage(priv, "dev-1", "n1", 1700000000000, '{"kind":"CRON_COMMAND"}');
    expect(await verifySignature(hub.publicKeyB64, sig, "dev-1", "n1", 1700000000000, '{"kind":"OTHER"}')).toBe(
      false,
    );
  });

  it("hub sign: wrong device_id -> false", async () => {
    const hub = await genHubKey();
    const priv = await importPrivateKey(hub.privateKeyB64);
    const sig = await signHubMessage(priv, "dev-1", "n1", 1700000000000, "x");
    expect(await verifySignature(hub.publicKeyB64, sig, "dev-2", "n1", 1700000000000, "x")).toBe(false);
  });

  it("hub sign: wrong nonce / wrong ts -> false", async () => {
    const hub = await genHubKey();
    const priv = await importPrivateKey(hub.privateKeyB64);
    const sig = await signHubMessage(priv, "dev-1", "n1", 1700000000000, "x");
    expect(await verifySignature(hub.publicKeyB64, sig, "dev-1", "n2", 1700000000000, "x")).toBe(false);
    expect(await verifySignature(hub.publicKeyB64, sig, "dev-1", "n1", 1700000000001, "x")).toBe(false);
  });

  it("deriveHubPublicKeyB64 matches the generated public key", async () => {
    const hub = await genHubKey();
    const priv = await importPrivateKey(hub.privateKeyB64);
    expect(await deriveHubPublicKeyB64(priv)).toBe(hub.publicKeyB64);
  });

  it("importPrivateKey: malformed secret throws (fail-closed)", async () => {
    await expect(importPrivateKey("!!!not-base64!!!")).rejects.toThrow();
    await expect(importPrivateKey("aGVsbG8=")).rejects.toThrow(); // valid b64, not PKCS8
  });

  it("getHubPublicKey: missing secret -> null; valid -> key + hub-1; bad -> null", async () => {
    expect(await getHubPublicKey({})).toBeNull();
    expect(await getHubPublicKey({ HUB_SIGN_SECRET: "!!!bad!!!" })).toBeNull();
    const hub = await genHubKey();
    const got = await getHubPublicKey({ HUB_SIGN_SECRET: hub.privateKeyB64 });
    expect(got).toEqual({ publicKeyB64: hub.publicKeyB64, keyId: "hub-1" });
  });
});
