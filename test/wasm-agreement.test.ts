// The JS↔WASM agreement gate (Lane H Phase 2): the @ar.io/proof JS verifier
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

import { verifyEnvelope, type Envelope } from "@ar.io/proof";
import { loadGoVerifier, verifyEnvelopeWasm } from "../src/verifier-wasm";

const wasmPath = fileURLToPath(new URL("../src/wasm/ario-proof.wasm", import.meta.url));
const pinPath = fileURLToPath(new URL("../wasm/PIN", import.meta.url));
const vectorsDir = fileURLToPath(new URL("./fixtures/", import.meta.url));

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

// Both verifiers, same input; assert the `ok` verdicts agree (and match
// `expectOk`). Used for the adversarial NEGATIVES: the Go kernel is fail-FAST
// (stops at the first failed check), so the WASM adapter's per-check tri-state
// is a fail-CLOSED approximation that legitimately differs from the JS
// verifier's exhaustive tri-state on multi-failure inputs (e.g. an unknown
// spec_version short-circuits before payload is checked). `ok` is the
// load-bearing cross-kernel invariant on that path.
async function agree(env: Envelope, expectOk: boolean, label: string): Promise<void> {
  const js = await verifyEnvelope(env);
  const wasm = await verifyEnvelopeWasm(env, undefined, wasmBytes);
  expect(wasm.ok, `${label}: JS=${js.ok} WASM=${wasm.ok} (wasm errors: ${wasm.errors})`).toBe(js.ok);
  expect(js.ok, `${label}: expected ok=${expectOk} (js errors: ${js.errors})`).toBe(expectOk);
}

// Stronger check for the SUCCESS / undetermined path (no failure
// short-circuit, so both verifiers reach every check): assert the FULL
// tri-state agrees — specVersionOk, payloadHashOk (incl. the null
// "semantics-undetermined" value for external commitment), and signatureOk.
async function agreeTriState(env: Envelope, label: string): Promise<void> {
  const js = await verifyEnvelope(env);
  const wasm = await verifyEnvelopeWasm(env, undefined, wasmBytes);
  expect(js.ok, `${label}: JS rejected a valid envelope: ${js.errors}`).toBe(true);
  expect(wasm.ok, `${label}: WASM=${wasm.ok} vs JS=${js.ok} (wasm: ${wasm.errors})`).toBe(js.ok);
  expect(wasm.specVersionOk, `${label}: specVersionOk`).toBe(js.specVersionOk);
  expect(
    wasm.payloadHashOk,
    `${label}: payloadHashOk (JS=${js.payloadHashOk} WASM=${wasm.payloadHashOk})`,
  ).toBe(js.payloadHashOk);
  expect(wasm.signatureOk, `${label}: signatureOk`).toBe(js.signatureOk);
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
    it(`${v.vector_id}: both verify (full tri-state agrees)`, async () => {
      await agreeTriState(signedEnvelope(v), v.vector_id);
    });

    it(`${v.vector_id} + co_signatures: both verify (signed scope excludes it)`, async () => {
      const env = signedEnvelope(v);
      env.co_signatures = [{ public_key: "ab".repeat(32), signature: "cd".repeat(64) }];
      await agreeTriState(env, `${v.vector_id}+cosig`);
    });
  }
});

// External commitment (envelope-spec §3) — the path where payloadHashOk is
// `null` (signature-valid, semantics-undetermined). A signed ario.events/v1
// envelope carries NO inline payload; verified without its committed record,
// both kernels must accept it AND report payloadHashOk=null. This is the case
// the @ar.io/proof@0.2.0 tri-state widening exists for, and the reason the
// WASM bridge now returns `hasPayload`.
describe("JS↔WASM agreement: external commitment (tri-state incl. null)", () => {
  const eventsVector = JSON.parse(
    readFileSync(`${vectorsDir}events-event-01.json`, "utf8"),
  ) as { spec_version: string; expected_outputs: { envelope_jcs_bytes_hex: string } };
  const eventsEnv = JSON.parse(
    Buffer.from(eventsVector.expected_outputs.envelope_jcs_bytes_hex, "hex").toString("utf8"),
  ) as Envelope;

  it("is an ario.events/v1 external-commitment envelope (no inline payload)", () => {
    expect(eventsVector.spec_version).toBe("ario.events/v1");
    expect("payload" in eventsEnv).toBe(false);
  });

  it("both accept signature-only and report payloadHashOk=null, full tri-state agrees", async () => {
    const js = await verifyEnvelope(eventsEnv);
    expect(js.ok).toBe(true);
    expect(js.payloadHashOk, "JS: external commitment, no record → undetermined").toBe(null);
    await agreeTriState(eventsEnv, "events-event-01 external-commitment");
  });
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
