// Conformance gate. Runs every vendored ar-io-agent envelope vector through the
// client-side verifier and asserts byte-for-byte agreement with the expected
// canonical bytes, hashes, and signature — plus a passing verdict. A single
// mismatch fails CI. This is the contract that keeps this independent verifier
// in lockstep with the Go reference implementation.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { bytesToHex, sha256Hex, utf8 } from "../src/crypto";
import { contentHashes, jcs, verifyEnvelope } from "../src/verifier";
import type { Envelope } from "../src/types";

interface Vector {
  vector_id: string;
  inputs: { envelope_pre_signature: Record<string, unknown> };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: {
    payload_jcs_bytes_hex: string;
    payload_hash_hex: string;
    envelope_for_sig_jcs_bytes_hex: string;
    signature_hex: string;
  };
}

const vectorsDir = fileURLToPath(new URL("../test-vectors/", import.meta.url));

function loadVectors(): Vector[] {
  return readdirSync(vectorsDir)
    .filter((f) => f.startsWith("envelope-") && f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(`${vectorsDir}${f}`, "utf8")) as Vector);
}

// Reconstruct the full signed envelope exactly as it would appear on-chain:
// the pre-signature envelope plus the three fields the signer adds.
function reconstruct(v: Vector): Envelope {
  return {
    ...(v.inputs.envelope_pre_signature as unknown as Envelope),
    payload_hash: v.expected_outputs.payload_hash_hex,
    public_key: v.fixed_keypair.ed25519_public_hex,
    signature: v.expected_outputs.signature_hex,
  };
}

const vectors = loadVectors();

describe("envelope conformance vs ar-io-agent test-vectors", () => {
  it("loads the vendored corpus", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(6);
  });

  for (const v of vectors) {
    describe(v.vector_id, () => {
      const env = reconstruct(v);

      it("JCS(payload) matches expected canonical bytes", () => {
        expect(bytesToHex(utf8(jcs(env.payload)))).toBe(v.expected_outputs.payload_jcs_bytes_hex);
      });

      it("SHA-256(JCS(payload)) matches payload_hash", async () => {
        expect(await sha256Hex(utf8(jcs(env.payload)))).toBe(v.expected_outputs.payload_hash_hex);
        expect(env.payload_hash).toBe(v.expected_outputs.payload_hash_hex);
      });

      it("JCS(envelope minus signature) matches expected canonical bytes", () => {
        const { signature: _sig, ...forSig } = env;
        expect(bytesToHex(utf8(jcs(forSig)))).toBe(v.expected_outputs.envelope_for_sig_jcs_bytes_hex);
      });

      it("verifies (spec_version + payload_hash + Ed25519 signature)", async () => {
        const result = await verifyEnvelope(env);
        expect(result.errors).toEqual([]);
        expect(result.specVersionOk).toBe(true);
        expect(result.payloadHashOk).toBe(true);
        expect(result.signatureOk).toBe(true);
        expect(result.ok).toBe(true);
      });

      it("binds each committed content hash back to the envelope", async () => {
        for (const { role, hash } of contentHashes(env)) {
          const result = await verifyEnvelope(env, hash);
          expect(result.ok).toBe(true);
          expect(result.contentHashOk).toBe(true);
          expect(result.contentRole).toBe(role);
        }
      });
    });
  }
});
