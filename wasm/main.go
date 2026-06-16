//go:build js && wasm

// The WASM bridge for the "verify with the Go reference implementation"
// toggle: a thin syscall/js wrapper around ar-io-agent's pkg/proof — the SAME
// kernel `ariod verify` runs, compiled for the browser. All crypto stays in
// Go; the JS adapter (src/verifier-wasm.ts) only shuttles JSON in and a
// verdict out. Built reproducibly at the agent commit pinned in ./PIN by
// scripts/build-wasm.sh; the JS↔WASM agreement gate
// (test/wasm-agreement.test.ts) asserts both verifiers return identical
// verdicts across the conformance corpus and the adversarial negatives.
package main

import (
	"syscall/js"

	"github.com/ar-io/ar-io-agent/pkg/proof"
)

// verifyEnvelope takes one argument — the envelope as a JSON string — and
// returns {ok: bool, error: string|null, hasPayload: bool}. pkg/proof.Verify-
// Envelope is all-or-nothing by design (fail-fast with a reason), so the
// granular per-check booleans of the JS VerificationResult are derived in the
// adapter from the error text, fail-closed. `hasPayload` reports whether the
// verified envelope carried an inline `payload` — the adapter needs it to
// distinguish a fully-bound inline verdict (payloadHashOk=true) from an
// external-commitment one verified signature-only (payloadHashOk=null,
// "semantics-undetermined"), matching the JS verifier's tri-state.
func verifyEnvelope(_ js.Value, args []js.Value) any {
	if len(args) != 1 || args[0].Type() != js.TypeString {
		return map[string]any{"ok": false, "error": "verifyEnvelope expects one JSON-string argument", "hasPayload": false}
	}
	env, err := proof.VerifyEnvelope([]byte(args[0].String()))
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error(), "hasPayload": false}
	}
	_, hasPayload := env["payload"]
	return map[string]any{"ok": true, "error": nil, "hasPayload": hasPayload}
}

func main() {
	js.Global().Set("__arioProofGo", js.ValueOf(map[string]any{
		"verifyEnvelope": js.FuncOf(verifyEnvelope),
		"specMajors":     js.ValueOf(toAnySlice(proof.SupportedSpecMajor)),
	}))
	// Park forever: the exported funcs must outlive main.
	select {}
}

func toAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
