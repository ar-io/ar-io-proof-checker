// Negative-path tests: the verifier must REJECT exactly the things a hostile
// gateway could throw at it — tampered payloads, forged signatures, mismatched
// content, and unknown spec versions. A verifier that only accepts good input
// proves nothing.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { contentHashes, specVersionSupported, verifyEnvelope } from "../src/verifier";
import type { Envelope } from "../src/types";

interface Vector {
  inputs: { envelope_pre_signature: Record<string, unknown> };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: { payload_hash_hex: string; signature_hex: string };
}

const registeredPath = fileURLToPath(
  new URL("../test-vectors/envelope-asset-registered-01.json", import.meta.url),
);

function goodEnvelope(): Envelope {
  const v = JSON.parse(readFileSync(registeredPath, "utf8")) as Vector;
  return {
    ...(v.inputs.envelope_pre_signature as unknown as Envelope),
    payload_hash: v.expected_outputs.payload_hash_hex,
    public_key: v.fixed_keypair.ed25519_public_hex,
    signature: v.expected_outputs.signature_hex,
  };
}

describe("specVersionSupported", () => {
  it("accepts the current major", () => {
    expect(specVersionSupported("ario.agent/v1")).toBe(true);
  });
  it("rejects unknown majors and garbage", () => {
    expect(specVersionSupported("ario.agent/v2")).toBe(false);
    expect(specVersionSupported("ario.agent/v0")).toBe(false);
    expect(specVersionSupported("evil")).toBe(false);
    expect(specVersionSupported("")).toBe(false);
  });
});

describe("verifyEnvelope rejects tampering", () => {
  it("accepts an untouched envelope (control)", async () => {
    const result = await verifyEnvelope(goodEnvelope());
    expect(result.ok).toBe(true);
  });

  it("rejects a mutated payload (payload_hash no longer matches)", async () => {
    const env = goodEnvelope();
    (env.payload as { size_bytes: number }).size_bytes = 999999;
    const result = await verifyEnvelope(env);
    expect(result.payloadHashOk).toBe(false);
    expect(result.ok).toBe(false);
  });

  it("rejects a forged signature", async () => {
    const env = goodEnvelope();
    env.signature = env.signature.replace(/^../, "00");
    const result = await verifyEnvelope(env);
    expect(result.signatureOk).toBe(false);
    expect(result.ok).toBe(false);
  });

  it("rejects a swapped public key (signature no longer verifies)", async () => {
    const env = goodEnvelope();
    env.public_key = env.public_key.replace(/^../, env.public_key.startsWith("0") ? "ff" : "00");
    const result = await verifyEnvelope(env);
    expect(result.signatureOk).toBe(false);
    expect(result.ok).toBe(false);
  });

  it("rejects an unknown spec_version even if otherwise well-formed", async () => {
    const env = goodEnvelope();
    env.spec_version = "ario.agent/v2";
    const result = await verifyEnvelope(env);
    expect(result.specVersionOk).toBe(false);
    expect(result.ok).toBe(false);
  });

  it("does not throw on malformed signature/key hex — returns not-verified", async () => {
    const env = goodEnvelope();
    env.signature = "not-hex";
    env.public_key = "also-not-hex";
    const result = await verifyEnvelope(env);
    expect(result.signatureOk).toBe(false);
    expect(result.ok).toBe(false);
  });
});

describe("content-hash bind (the lying-gateway defense)", () => {
  it("confirms the registered hash binds to the asset_registered envelope", async () => {
    const env = goodEnvelope();
    const hashes = contentHashes(env);
    expect(hashes).toHaveLength(1);
    expect(hashes[0].role).toBe("asset");

    const result = await verifyEnvelope(env, hashes[0].hash);
    expect(result.contentHashOk).toBe(true);
    expect(result.contentRole).toBe("asset");
    expect(result.ok).toBe(true);
  });

  it("rejects a non-matching content hash (gateway pointed us at the wrong tx)", async () => {
    const env = goodEnvelope();
    const result = await verifyEnvelope(env, "f".repeat(64));
    expect(result.contentHashOk).toBe(false);
    expect(result.contentRole).toBeNull();
    // The envelope itself is still cryptographically valid — it just isn't about
    // the bytes the user holds. ok (crypto validity) stays true; the UI must
    // gate the verdict on contentHashOk, not ok alone.
    expect(result.ok).toBe(true);
  });

  it("matches by case-insensitive hex", async () => {
    const env = goodEnvelope();
    const upper = contentHashes(env)[0].hash.toUpperCase();
    const result = await verifyEnvelope(env, upper);
    expect(result.contentHashOk).toBe(true);
  });

  it("reports null content bind when no hash is supplied", async () => {
    const result = await verifyEnvelope(goodEnvelope());
    expect(result.contentHashOk).toBeNull();
  });
});
