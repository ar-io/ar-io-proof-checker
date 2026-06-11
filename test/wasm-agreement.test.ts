// The JS↔WASM agreement gate (Lane H Phase 2): the @ar-io/proof JS verifier
// and the WASM build of the Go reference kernel (ar-io-agent pkg/proof at the
// commit pinned in wasm/PIN) must return IDENTICAL verdicts across the full
// conformance corpus AND the adversarial negatives — including co-signed
// envelopes, with no exceptions (the pin includes the agent#12 co_signatures
// fix). A disagreement is cross-implementation drift: build failure, same
// spirit as the Python kernel's cross-product gate.
//
// The binary itself is corpus-law: its SHA-256 is pinned in wasm/PIN and
// re-verified here before any verdict is compared.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { verifyEnvelope, type Envelope } from "@ar-io/proof";
import { loadGoVerifier, verifyEnvelopeWasm } from "../src/verifier-wasm";

const wasmPath = fileURLToPath(new URL("../src/wasm/ario-proof.wasm", import.meta.url));
const pinPath = fileURLToPath(new URL("../wasm/PIN", import.meta.url));
const vectorsDir = fileURLToPath(new URL("../packages/proof/test-vectors/", import.meta.url));

const wasmBytes = readFileSync(wasmPath);

interface Vector {
  vector_id: string;
  inputs: { envelope_pre_signature: Record<string, unknown> };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: { payload_hash_hex: string; signature_hex: string };
}

function loadVectors(): Vector[] {
  return readdirSync(vectorsDir)
    .filter((f) => f.startsWith("envelope-") && f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(`${vectorsDir}${f}`, "utf8")) as Vector);
}

function signedEnvelope(v: Vector): Envelope {
  return {
    ...(v.inputs.envelope_pre_signature as unknown as Envelope),
    payload_hash: v.expected_outputs.payload_hash_hex,
    public_key: v.fixed_keypair.ed25519_public_hex,
    signature: v.expected_outputs.signature_hex,
  };
}

// Both verifiers, same input; assert the verdicts agree (and match `expectOk`
// where the correct answer is known).
async function agree(env: Envelope, expectOk: boolean, label: string): Promise<void> {
  const js = await verifyEnvelope(env);
  const wasm = await verifyEnvelopeWasm(env, undefined, wasmBytes);
  expect(wasm.ok, `${label}: JS=${js.ok} WASM=${wasm.ok} (wasm errors: ${wasm.errors})`).toBe(js.ok);
  expect(js.ok, `${label}: expected ok=${expectOk} (js errors: ${js.errors})`).toBe(expectOk);
}

const vectors = loadVectors();

describe("wasm binary provenance", () => {
  it("matches the SHA-256 pinned in wasm/PIN", () => {
    const pinned = /^wasm_sha256=([0-9a-f]{64})$/m.exec(readFileSync(pinPath, "utf8"))?.[1];
    expect(pinned, "wasm/PIN has no wasm_sha256").toBeTruthy();
    expect(createHash("sha256").update(wasmBytes).digest("hex")).toBe(pinned);
  });

  it("instantiates and exposes the kernel's accepted majors", async () => {
    await loadGoVerifier(wasmBytes);
    expect((globalThis as Record<string, unknown>).__arioProofGo).toBeTruthy();
  });
});

describe("JS↔WASM agreement: conformance corpus (positives)", () => {
  it("has the full envelope corpus", () => {
    expect(vectors).toHaveLength(6);
  });

  for (const v of vectors) {
    it(`${v.vector_id}: both verify`, async () => {
      await agree(signedEnvelope(v), true, v.vector_id);
    });

    it(`${v.vector_id} + co_signatures: both verify (signed scope excludes it)`, async () => {
      const env = signedEnvelope(v);
      env.co_signatures = [{ public_key: "ab".repeat(32), signature: "cd".repeat(64) }];
      await agree(env, true, `${v.vector_id}+cosig`);
    });
  }
});

describe("JS↔WASM agreement: adversarial negatives", () => {
  for (const v of vectors) {
    const id = v.vector_id;

    it(`${id}: tampered payload — both reject`, async () => {
      const env = signedEnvelope(v);
      env.payload = { ...env.payload, _injected: "x" };
      await agree(env, false, `${id} tampered-payload`);
    });

    it(`${id}: forged signature — both reject`, async () => {
      const env = signedEnvelope(v);
      const flipped = (parseInt(env.signature.slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, "0");
      env.signature = flipped + env.signature.slice(2);
      await agree(env, false, `${id} forged-sig`);
    });

    it(`${id}: swapped public key — both reject`, async () => {
      const env = signedEnvelope(v);
      env.public_key = "00".repeat(32);
      await agree(env, false, `${id} swapped-key`);
    });

    it(`${id}: unknown spec_version — both reject`, async () => {
      const env = signedEnvelope(v);
      env.spec_version = "ario.agent/v99";
      await agree(env, false, `${id} unknown-spec`);
    });

    it(`${id}: spec-legal minor is accepted by NEITHER as-signed (signed scope changed)`, async () => {
      // v1.<minor> is registry-legal in both, but rewriting spec_version after
      // signing breaks the signature — both must reject for that reason.
      const env = signedEnvelope(v);
      env.spec_version = "ario.agent/v1.1";
      await agree(env, false, `${id} rewritten-minor`);
    });

    it(`${id}: co-signed THEN tampered — both reject`, async () => {
      const env = signedEnvelope(v);
      env.co_signatures = [{ public_key: "ab".repeat(32), signature: "cd".repeat(64) }];
      env.payload = { ...env.payload, _injected: "x" };
      await agree(env, false, `${id} cosig-tampered`);
    });

    it(`${id}: extra signed-scope field — both reject`, async () => {
      const env = signedEnvelope(v) as Envelope & { extra_field?: string };
      env.extra_field = "x";
      await agree(env, false, `${id} extra-field`);
    });
  }

  it("malformed input (non-object): both reject without throwing", async () => {
    for (const bad of [null, 42, "x", []] as unknown[]) {
      const js = await verifyEnvelope(bad as never);
      const wasm = await verifyEnvelopeWasm(bad as never, undefined, wasmBytes);
      expect(js.ok).toBe(false);
      expect(wasm.ok).toBe(false);
    }
  });
});
