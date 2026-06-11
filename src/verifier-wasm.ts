// Optional "verify with the Go reference implementation" path: a lazy-loaded
// WASM build of ar-io-agent's pkg/proof — the SAME kernel `ariod verify` runs
// (pinned commit + reproducible build recorded in wasm/PIN). All crypto runs
// inside the WASM; this adapter only shuttles JSON in and a verdict out, then
// derives the granular VerificationResult booleans from the kernel's fail-fast
// error, fail-closed (an unreached check is reported false, never true).
//
// Invariant #1 holds: the ~3.5 MB binary (~1 MB compressed) ships as one of
// this app's OWN assets and is fetched only on first use — the base bundle
// stays light and no external request is ever made. The JS verifier
// (@ar-io/proof) remains the default and the headline; this is the
// belt-and-suspenders cross-check, gated for agreement with the JS verdicts
// in test/wasm-agreement.test.ts.

import { contentHashes, type ContentRole, type Envelope, type VerificationResult } from "@ar-io/proof";

import wasmUrl from "./wasm/ario-proof.wasm?url";

interface GoVerdict {
  ok: boolean;
  error: string | null;
}

interface GoApi {
  verifyEnvelope: (envelopeJson: string) => GoVerdict;
}

declare global {
  // Set by wasm/main.go before it parks; constructor by wasm_exec.js.
  var __arioProofGo: GoApi | undefined;
  var Go: (new () => { importObject: WebAssembly.Imports; run(i: WebAssembly.Instance): Promise<void> }) | undefined;
}

let singleton: Promise<GoApi> | null = null;

// Load + instantiate the Go verifier once; concurrent callers share the same
// in-flight promise, and a failed load clears it so a retry is possible.
// `bytes` lets non-browser callers (the agreement gate) supply the binary
// directly instead of fetching.
export function loadGoVerifier(bytes?: BufferSource): Promise<GoApi> {
  singleton ??= instantiate(bytes).catch((e: unknown) => {
    singleton = null;
    throw e;
  });
  return singleton;
}

async function instantiate(bytes?: BufferSource): Promise<GoApi> {
  // Side-effect import: defines globalThis.Go (the Go runtime shim, vendored
  // from the exact toolchain that built the binary — see wasm/PIN).
  await import("./wasm/wasm_exec.js");
  const GoCtor = globalThis.Go;
  if (!GoCtor) throw new Error("wasm_exec.js did not define Go");
  const go = new GoCtor();

  const instance = bytes
    ? (await WebAssembly.instantiate(bytes, go.importObject)).instance
    : (await WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject)).instance;

  // run() resolves only when the program exits (it parks forever); the API
  // global is set synchronously before the park, but give the scheduler a
  // bounded grace period rather than assuming.
  void go.run(instance);
  for (let i = 0; i < 100; i++) {
    if (globalThis.__arioProofGo) return globalThis.__arioProofGo;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("Go verifier did not initialize");
}

// Same shape as @ar-io/proof's verifyEnvelope. The Go kernel is fail-fast
// (one error, no granular booleans), so per-check flags are classified from
// the error text — fail-closed: checks the kernel never reached are false.
export async function verifyEnvelopeWasm(
  env: Envelope,
  expectedContentHash?: string,
  bytes?: BufferSource,
): Promise<VerificationResult> {
  const api = await loadGoVerifier(bytes);

  let verdict: GoVerdict;
  try {
    verdict = api.verifyEnvelope(JSON.stringify(env));
  } catch (e) {
    verdict = { ok: false, error: e instanceof Error ? e.message : String(e) };
  }

  const flags = classify(verdict);

  // Content bind: a plain field comparison (no crypto), evaluated here so the
  // toggle reports the same bind semantics as the JS path. The cryptographic
  // claims above are exclusively the Go kernel's.
  let contentHashOk: boolean | null = null;
  let contentRole: ContentRole | null = null;
  if (expectedContentHash !== undefined) {
    const want = expectedContentHash.toLowerCase();
    const match =
      env !== null && typeof env === "object" && !Array.isArray(env)
        ? contentHashes(env).find((c) => c.hash.toLowerCase() === want)
        : undefined;
    contentHashOk = match !== undefined;
    contentRole = match ? match.role : null;
  }

  return {
    ok: verdict.ok,
    ...flags,
    contentHashOk,
    contentRole,
    errors: verdict.error === null ? [] : [verdict.error],
  };
}

function classify(v: GoVerdict): Pick<VerificationResult, "specVersionOk" | "payloadHashOk" | "signatureOk"> {
  if (v.ok) return { specVersionOk: true, payloadHashOk: true, signatureOk: true };
  const e = v.error ?? "";
  if (e.includes("unsupported spec_version")) {
    return { specVersionOk: false, payloadHashOk: false, signatureOk: false };
  }
  if (e.includes("payload")) {
    return { specVersionOk: true, payloadHashOk: false, signatureOk: false };
  }
  if (e.includes("signature") || e.includes("public_key")) {
    return { specVersionOk: true, payloadHashOk: true, signatureOk: false };
  }
  // Parse failures / unknown: nothing was confirmed.
  return { specVersionOk: false, payloadHashOk: false, signatureOk: false };
}
