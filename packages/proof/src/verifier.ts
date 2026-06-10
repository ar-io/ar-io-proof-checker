// Independent client-side implementation of the ar.io agent envelope
// verification algorithm (ar-io-agent docs/artifact.md §6, docs/auditor-recipe.md
// Recipe 1). This is deliberately a second implementation of the same algorithm
// the Go agent runs — a second, conformance-tested verifier is what demonstrates
// the product's claim: verification needs no ar.io code in the trust path.
//
// Conformance is enforced by test/conformance.test.ts, which runs every
// ar-io-agent test vector through this code and asserts byte-for-byte agreement.

import canonicalize from "canonicalize";

import { ed25519Verify, sha256Hex, utf8 } from "./crypto";
import type { ContentRole, Envelope, VerificationResult } from "./types";

// Fail-closed accepted-profile registry (envelope-spec §2, artifact.md §13):
// exactly the accepted profile majors, nothing else. Minors within an accepted
// major ("ario.agent/v1.<minor>") are additive and tolerated — matching the Go
// reference kernel's semantics (pkg/proof isSupportedSpec) so the JS and
// WASM-Go verifiers agree. Accepting a new profile (e.g. ario.mlflow/v1) is a
// deliberate one-entry addition HERE and only here — mlflow-dialect behaviors
// (like its underscore-key strip) must never leak into the agent profile.
const ACCEPTED_SPEC_MAJORS = ["ario.agent/v1"];

// RFC 8785 (JCS) canonicalization. The `canonicalize` package is the reference
// JS implementation; correctness is pinned by the conformance vectors.
export function jcs(value: unknown): string {
  const canonical = canonicalize(value);
  if (typeof canonical !== "string") {
    throw new Error("jcs: canonicalize returned a non-string (input not JSON-serializable?)");
  }
  return canonical;
}

export function specVersionSupported(specVersion: string): boolean {
  if (typeof specVersion !== "string" || specVersion === "") return false;
  return ACCEPTED_SPEC_MAJORS.some((m) => specVersion === m || specVersion.startsWith(`${m}.`));
}

// The content hash(es) an envelope commits to, by event type — the values a
// reverse lookup can match the user's in-browser file hash against.
//   asset_registered -> payload.hash            (the registered, known-good bytes)
//   asset_missing    -> payload.baseline.hash   (last known-good bytes that vanished)
//   tamper_detected  -> payload.observed.hash   (the tampered bytes that were flagged)
//                    -> payload.baseline.hash   (the known-good bytes it diverged from)
// Other event types commit to no asset content hash.
export function contentHashes(env: Envelope): { role: ContentRole; hash: string }[] {
  const p = env.payload as {
    hash?: unknown;
    baseline?: { hash?: unknown };
    observed?: { hash?: unknown };
  };
  const asStr = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

  const out: { role: ContentRole; hash: string }[] = [];
  switch (env.event_type) {
    case "asset_registered": {
      const h = asStr(p.hash);
      if (h) out.push({ role: "asset", hash: h });
      break;
    }
    case "asset_missing": {
      const h = asStr(p.baseline?.hash);
      if (h) out.push({ role: "baseline", hash: h });
      break;
    }
    case "tamper_detected": {
      const obs = asStr(p.observed?.hash);
      if (obs) out.push({ role: "observed", hash: obs });
      const base = asStr(p.baseline?.hash);
      if (base) out.push({ role: "baseline", hash: base });
      break;
    }
  }
  return out;
}

// Verify an envelope. The three load-bearing checks (spec_version, payload_hash,
// signature) establish that the envelope is authentic. When `expectedContentHash`
// is supplied (the in-browser hash of the user's file), an additional bind check
// confirms the bytes the user holds are the bytes this envelope is about — this
// is the step that makes a lying gateway tag worthless.
export async function verifyEnvelope(
  env: Envelope,
  expectedContentHash?: string,
): Promise<VerificationResult> {
  const errors: string[] = [];

  // Guard a malformed input (null / non-object / array) up front — every field
  // access below assumes an object. A hostile gateway or a hand-edited report
  // can supply anything; treat it as "not verified," never a thrown exception.
  if (env === null || typeof env !== "object" || Array.isArray(env)) {
    return {
      ok: false,
      specVersionOk: false,
      payloadHashOk: false,
      signatureOk: false,
      contentHashOk: expectedContentHash === undefined ? null : false,
      contentRole: null,
      errors: ["envelope is not a JSON object"],
    };
  }

  const specVersionOk = specVersionSupported(env.spec_version);
  if (!specVersionOk) errors.push(`unsupported spec_version: ${JSON.stringify(env.spec_version)}`);

  // Check 1 — Record Matches: payload_hash == SHA-256(JCS(payload)).
  let payloadHashOk = false;
  try {
    const recomputed = await sha256Hex(utf8(jcs(env.payload)));
    payloadHashOk = recomputed === env.payload_hash;
    if (!payloadHashOk) {
      errors.push(`payload_hash mismatch: envelope=${env.payload_hash} recomputed=${recomputed}`);
    }
  } catch (e) {
    errors.push(`payload canonicalization failed: ${stringifyErr(e)}`);
  }

  // Check 2 — Signature Confirmed: Ed25519 over the signed scope, which is
  // JCS(envelope minus `signature` minus `co_signatures`) per envelope-spec §2.
  // The co_signatures carve-out (§7.1) lets a countersignature be added without
  // invalidating the primary signature; the field is reserved/default-absent.
  // The corpus has no co-signed vectors, so this strip is pinned by an explicit
  // unit test rather than by conformance.
  let signatureOk = false;
  try {
    const { signature: _signature, co_signatures: _coSignatures, ...envelopeForSig } = env;
    signatureOk = await ed25519Verify(env.signature, utf8(jcs(envelopeForSig)), env.public_key);
    if (!signatureOk) errors.push("Ed25519 signature verification failed");
  } catch (e) {
    errors.push(`signature verification error: ${stringifyErr(e)}`);
  }

  // Check 3 (optional) — Content Bind: the user's bytes match a hash this
  // envelope commits to. The tag got us here; only this proves the bytes match.
  let contentHashOk: boolean | null = null;
  let contentRole: ContentRole | null = null;
  if (expectedContentHash !== undefined) {
    const want = expectedContentHash.toLowerCase();
    const match = contentHashes(env).find((c) => c.hash.toLowerCase() === want);
    contentHashOk = match !== undefined;
    contentRole = match ? match.role : null;
    if (!contentHashOk) {
      errors.push("provided content hash does not match any hash this envelope commits to");
    }
  }

  return {
    ok: specVersionOk && payloadHashOk && signatureOk,
    specVersionOk,
    payloadHashOk,
    signatureOk,
    contentHashOk,
    contentRole,
    errors,
  };
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
