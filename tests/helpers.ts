/** Test helpers: real Ed25519 keypair (WebCrypto) + signing. */
import { base64ToBytes, bytesToBase64 } from "../src/crypto";

export interface DeviceKey {
  publicKeyB64: string;
  sign: (data: string) => Promise<string>;
}

export async function genDeviceKey(): Promise<DeviceKey> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array(
    (await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer,
  );
  return {
    publicKeyB64: bytesToBase64(raw),
    sign: async (data: string) => {
      const sig = await crypto.subtle.sign(
        { name: "Ed25519" },
        kp.privateKey,
        new TextEncoder().encode(data),
      );
      return bytesToBase64(new Uint8Array(sig));
    },
  };
}

export function b64decodeToString(b64: string): string {
  return new TextDecoder().decode(base64ToBytes(b64));
}

/** Hub signing key (M-4): Ed25519 keypair, private as PKCS8 base64
 * (the HUB_SIGN_SECRET format) + raw public key base64. */
export interface HubKey {
  privateKeyB64: string;
  publicKeyB64: string;
}

export async function genHubKey(): Promise<HubKey> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", kp.privateKey)) as ArrayBuffer);
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", kp.publicKey)) as ArrayBuffer);
  return { privateKeyB64: bytesToBase64(pkcs8), publicKeyB64: bytesToBase64(raw) };
}
