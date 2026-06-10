// Conformance gate. Runs every vendored ar-io-agent envelope vector through the
// client-side verifier and asserts byte-for-byte agreement with the expected
// canonical bytes, hashes, and signature — plus a passing verdict. A single
// mismatch fails CI. This is the contract that keeps this independent verifier
// in lockstep with the Go reference implementation.

import { createHash } from "node:crypto";
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

// Pinned from test-vectors/CORPUS-v1.md (corpus tag test-vectors-v1.0; see
// test-vectors/VENDORING.md). A drifted vendored copy fails here before any
// crypto runs. Identical table to the Python kernel's test_conformance.py.
const CORPUS_SHA256: Record<string, string> = {
  "envelope-asset-missing-01.json": "fecb29289df2b6ea210b51737e6cdf10438ec996add050b053247cc567fe2e27",
  "envelope-asset-registered-01.json": "3b99fc850edba7775a4df970e406fcb2d787fc10594cd7f969936938b881b9a9",
  "envelope-key-retired-01.json": "2e89bc2b1986e3545d0aae94f850d675f9f16fc384b311cc75090a5e275eaf33",
  "envelope-policy-changed-01.json": "62a460fb4e0e49c2ef28acc73ddea1163f801ccef6c0e247679e65e6c655509c",
  "envelope-tamper-detected-01.json": "5f4b8b1dab9c50ca97ff0349e39481ee33f9a19991632d13fb71fd940a88fcd0",
  "envelope-verification-checkpoint-01.json": "393c04e411807481587c591ccb1e637cb072f40940cbc9d25e53dd29253bb56d",
  "merkle-tree-00-leaves.json": "705adf82ce9cc46d0e45fce216cb205d5755e2d41975b66444f1765a982faa95",
  "merkle-tree-01-leaves.json": "bdbb57ad29272054c5dcc655c2279c4debec9c4c67ea85f17490760a19b52923",
  "merkle-tree-02-leaves.json": "9c33d0fcb57655729a0e657b8b4313de806e397949465d310338db5dd56a573b",
  "merkle-tree-03-leaves.json": "f4cc12cd11cb3a49225edff2c18ab9f516992f8d6c13e7baadb627f1c7efe8eb",
  "merkle-tree-07-leaves.json": "8372c63f3d5a61c8dfc0939fb5776b8041960313df4f9334e620d398326bdd1c",
  "merkle-tree-1024-leaves.json": "e732c755539b84e20b80d15e5a7989e2d6736153d9d78c944ed6e7ee98627254",
  "merkle-tree-16-leaves.json": "b58b31340bef317fd32734be7e3ff58b0d4a4d0cb03a7b16f08056161c7ae72c",
  "README.md": "7d21d23fcbf9996e9e7a710099bb59b4cb501720ded57aac65edde43de10ef44",
};

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

// The gate before the gate: the vendored corpus must BE test-vectors-v1.0,
// byte-for-byte, before any conformance claim means anything.
describe("corpus integrity (test-vectors-v1.0)", () => {
  for (const [name, expected] of Object.entries(CORPUS_SHA256)) {
    it(`${name} matches its pinned digest`, () => {
      const digest = createHash("sha256").update(readFileSync(`${vectorsDir}${name}`)).digest("hex");
      expect(digest, `vendored ${name} drifted from test-vectors-v1.0`).toBe(expected);
    });
  }

  it("the corpus is complete — no missing or extra vector files", () => {
    const onDisk = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();
    const pinned = Object.keys(CORPUS_SHA256).filter((f) => f.endsWith(".json")).sort();
    expect(onDisk).toEqual(pinned);
    expect(onDisk.filter((f) => f.startsWith("envelope-"))).toHaveLength(6);
    expect(onDisk.filter((f) => f.startsWith("merkle-tree-"))).toHaveLength(7);
  });
});

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
