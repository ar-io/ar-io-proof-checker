# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **client-side, zero-upload reverse-provenance checker**: drop a file in the browser, it's hashed locally (WebCrypto SHA-256, never uploaded), the hash is queried against Arweave for matching ar.io provenance envelopes, each signature is verified **in the browser**, and the artifact's on-chain history is rendered. It is the inverse of `ariod verify <tx_id>` (identifier → artifact); here you start from the **bytes** and the content hash is the join key.

Single-page app, **vanilla TypeScript + Vite**, minimal runtime dependencies (see "Dependency discipline" below — the discipline is about *trust-path* deps, not a raw count). **BSL 1.1** (see License) — but the verifier stays open: the trust-path kernel is the external MIT [`@ar.io/proof`](https://www.npmjs.com/package/@ar.io/proof) package, not bundled app code. It is one of the ar.io verification stack siblings; the kernel is homed in [`ar-io-proof`](https://github.com/ar-io/ar-io-proof), and it depends on [`ar-io-agent`](https://github.com/ar-io/ar-io-agent) **for specification only — no code dependency** (envelope schema, the `Asset-Hash` tag convention).

## Non-negotiable invariants

These are the product, not preferences. Don't regress them:

1. **Zero upload / read-only.** The file never leaves the browser. The *only* bytes that go out are the 64-hex hash (inside a GraphQL query), `/raw/<tx_id>` fetches, and — default chain only, when a user-initiated check exhausts every configured gateway — one `GET /ar-io/peers` to a gateway already in the chain (registry-driven fallback discovery; deliberate amendment, 2026-06-10). **No request of any kind fires before the user supplies a file**, no backend, no account, no telemetry, no other external requests (fonts are self-hosted, the logo is inlined — see Brand). A user-typed gateway list is respected strictly: no peers fetch, no silent additions.
2. **Trust comes from the payload check, not the tag.** Arweave tags are unsigned search hints. Every candidate tx is fetched and re-verified: recompute `payload_hash = SHA-256(JCS(payload))`, Ed25519-verify against the envelope's embedded `public_key`, and confirm the payload's content hash equals the user's file hash. A gateway that lies in a tag must never be able to produce a "verified" verdict (it lands in `rejected`).
3. **Scope honesty is load-bearing.** The tool proves *"this artifact has a verifiable history"* — never *"this is the live production version"* or *"this file is safe."* Every verdict surface, and the exported report, must keep that line crisp. Absence of a record is **not** evidence of tampering. See `proof-checker.md` §8 in `ar-io-agent` for the exact copy.
4. **Conformance is the contract.** The verifier (`@ar.io/proof`) is an independent re-implementation of the Go agent's algorithm; it reproduces every `test-vectors-v1.2` vector byte-for-byte — that gate runs in `ar-io-proof`'s CI. This app pins it two ways: it consumes the published, conformance-gated kernel, and its own `wasm-agreement.test.ts` cross-checks that kernel against a WASM build of the Go reference (identical verdicts over the corpus + adversarial negatives, or CI fails).
5. **Verification needs no key/identity binding from us.** The tool shows the signing key; binding it to a real-world identity is out-of-band (a lying party can sign a valid envelope for *your* hash). Never collapse the verdict to "verified = trusted."

## Commands

```bash
npm install
npm run dev        # Vite dev server → http://localhost:5173
npm run test       # vitest: conformance + verifier + provenance + report
npm run test:watch
npm run typecheck  # tsc --noEmit (strict)
npm run build      # tsc --noEmit && vite build → dist/ (permaweb-deployable)
npm run preview    # serve the production build
```

Run a single test file: `npx vitest run test/report.test.ts`.

Live / opt-in checks (network-dependent, never part of `npm test` or CI):

```bash
ARIO_LIVE_E2E=1 npx vitest run test/live.e2e.test.ts   # real gateways + on-chain samples + 3 GiB streaming-hash check
node scripts/browser-e2e.mjs                            # real headless-Chromium run of the production build incl. the WASM toggle (see script header for setup)
```

Rebuilding the WASM-Go verifier (only needed when the pinned agent commit changes):

```bash
AGENT_SRC=../ar-io-agent bash scripts/build-wasm.sh    # reproducible build at the commit pinned in wasm/PIN → src/wasm/ario-proof.wasm
```

## Architecture

The flow is: **file → hash → discover → fetch → verify → history → render**, with report export/import bolted onto the result. The verification kernel is the **published [`@ar.io/proof`](https://www.npmjs.com/package/@ar.io/proof) npm package** (`"@ar.io/proof": "^0.2.0"` — full-family: inline AND external commitment, `ario.events/v1` accepted); the app is an ordinary consumer. **The kernel source lives in [`ar-io-proof`](https://github.com/ar-io/ar-io-proof) (`ts/`), not here** — moved out as of the TS-kernel-home lane (an app never owns a kernel). `verifyEnvelope`, `contentHashes`, the RFC 9162 Merkle primitives, the envelope types, and the crypto helpers all come from that package; to change kernel behavior, work in `ar-io-proof` and bump the dep. The `@ar.io/proof` signed-scope / spec-registry / co-signatures rules and the byte-for-byte corpus gate live there too.

### WASM-Go reference verifier (the optional toggle)

`src/wasm/ario-proof.wasm` is a **reproducible build of ar-io-agent's `pkg/proof`** — the same kernel `ariod verify` runs — at the agent commit pinned in `wasm/PIN` (commit + Go version + build flags + binary SHA-256; the agreement gate re-verifies the digest every test run). `wasm/main.go` is the thin `syscall/js` bridge; `scripts/build-wasm.sh` rebuilds it via a detached git worktree of the sibling agent checkout (shared-checkout discipline: the agent repo is read/build-only, never disturbed). `src/wasm/wasm_exec.js` is the Go runtime shim vendored from the exact toolchain that built the binary.

`src/verifier-wasm.ts` is the lazy adapter: same `verifyEnvelope` shape as `@ar.io/proof`, crypto exclusively inside the WASM, per-check booleans classified fail-closed from the kernel's fail-fast error, content bind computed adapter-side (field comparison, not crypto). The bridge returns `hasPayload` so the adapter reports `payloadHashOk: null` (semantics-undetermined) for an external-commitment envelope verified signature-only, matching the `@ar.io/proof@0.2.0` tri-state. **The JS verifier remains the default and the headline** — the toggle is cross-implementation confirmation, never a replacement, and its failure to load never blocks a verdict. Invariant #1 holds: the ~3.5 MB binary (~1 MB gz) is fetched on first use only, from the app's OWN assets (it ships in `dist/`); the adapter + shim are code-split lazy chunks, so the base bundle stays ~23 KB gz.

**The agreement gate** (`test/wasm-agreement.test.ts`) asserts the JS and WASM verifiers return IDENTICAL verdicts across the full corpus AND the adversarial negatives — including co-signed envelopes, with **no exceptions** (the pin includes the agent#12 `co_signatures` fix). A disagreement is cross-implementation drift = build failure. When re-pinning: bump `wasm/PIN`'s `agent_commit`, run `scripts/build-wasm.sh`, commit binary + PIN together.

### App (`src/`)

| Module | Role |
|---|---|
| `hash.ts` | **Streaming** in-browser SHA-256: `file.stream()` chunks feed `hash-wasm`'s incremental hasher, memory stays flat at any file size, progress is reported via callback. No size refusal — `fileSizeAdvisory` is honest-time advisory only. Not trust-path crypto (see "Dependency discipline"); the streaming output is pinned against WebCrypto in `test/hash.streaming.test.ts`. |
| `gateway.ts` | The only outbound traffic. Every operation takes an ordered **gateway list** and falls through on failure (network/5xx/timeout); discovery additionally falls through on an *empty* result, so "no match" means "none of the configured gateways know these bytes" — first non-empty view wins, views stay atomic (no cross-gateway union). `findEnvelopeTxs` unions GraphQL queries over the three content-hash tags (`Asset-Hash`/`Observed-Hash`/`Baseline-Hash`) per gateway and dedupes; the serving gateway is surfaced (`Discovery.gateway`). `findAssetEventTxs` queries all of an asset's events by `Asset-Id` (+ block timestamps). `fetchEnvelope` does `/raw/<tx>` with per-gateway fallback (404 falls through — propagation lag). The default chain is **deployment-aware**: `defaultGatewayChain` puts the gateway *serving the app* first (derived from `window.location.hostname` — ArNS/sandbox subdomain parent; zero requests, null on localhost/IP/apex), then the static anchors `turbo-gateway.com`, `arweave.net`. `fetchRegistryPeers` extends the chain from `GET /ar-io/peers` (plain HTTP + CORS-open on gateways; no AO, no SDK) — top-`dataWeight`, https-only, capped at `REGISTRY_PEER_LIMIT`; consulted ONLY when the configured chain is exhausted and only ever appended after it, so a poisoned peer list can never preempt the anchors. Peers are search hints, never trust. |
| `provenance.ts` | Orchestration → `ProvenanceReport` (`verdict` ∈ provenance-found / tampered-bytes / no-match / error, `matches`, `histories`, `rejected`). `buildAssetHistory` reconstructs a per-asset timeline; `assessContinuity` checks per-type `previous_hash` chains **conservatively** — an unresolved link is `partial`, NEVER implied tampering. |
| `report.ts` | Exportable, **self-verifiable** `ario.proof-checker.report/v1`. `buildReport` embeds the raw verified envelopes + hash; `verifyReport` re-runs verification against that embedded evidence with no network (round-trip); `reportToJson` / `reportToHtml` (HTML-escaped — reports can embed attacker-chosen strings). Unsigned by design (we have no key); integrity = re-verification. |
| `render.ts` | All DOM. **Always `textContent`, never `innerHTML`** — envelope fields are untrusted. Verdict banner + honest copy, per-asset timeline, multi-match grouping, report action bar, and the re-import verification view. |
| `main.ts` | Wires drop zone / file input / gateway field / report re-import. |
| `types.ts` | Checker-specific types (`AssetEvent`, `AssetHistory`, `ChainContinuity`); re-exports the kernel types (`Envelope`, `VerificationResult`, …) from `@ar.io/proof` so app modules keep one import home. |

`test/` mirrors the app layer: `gateway.test.ts` (list normalization, fetch timeout, per-gateway allSettled resilience, multi-gateway fallback incl. empty-fallthrough and view atomicity, serving-gateway derivation, registry-peers parsing), `provenance.test.ts` (orchestration, continuity, candidate cap, tie-break, registry-extension semantics — stubbed fetch), `report.test.ts` (schema, caps, round-trip self-verification incl. no-match + malformed-embedded, HTML-escaping), `hash.test.ts` (advisory copy), `hash.streaming.test.ts` (the WebCrypto cross-check across sizes incl. the SHA-256 block boundary, a stream-only Blob double proving the file is never materialized, monotonic progress). UI-layer tests use **happy-dom** via a `// @vitest-environment happy-dom` directive: `render.dom.test.ts` (verdict attribution, missing-subject guard, truncation note, multi-gateway surfacing, error verdict, popup→download fallback) and `main.dom.test.ts` (run-token race guard, input reset, keyboard activation). The cross-implementation tests consume the npm kernel: `wasm-agreement.test.ts` (JS `@ar.io/proof` ⇄ WASM-Go, identical verdicts over the corpus + adversarial negatives) and `differential.probe.test.ts` (validly-signed exotic envelopes). Kernel/conformance tests proper live in `ar-io-proof`, not here.

## Dependency discipline

The "minimal dependencies" rule is about **trust-path deps, not all deps**. A dependency is trust-path if a bug in it could validate a forgery — produce a "verified" verdict for bytes the agent's key never signed. Today that set is exactly: `canonicalize` (JCS), `@noble/ed25519`, and our own `verifier.ts`. Additions to that set need extraordinary justification; everything else is measured against the bar below.

**`hash-wasm` (streaming SHA-256) clears that bar.** Rationale, recorded when it was added:

1. **SHA-256 is not in the cryptographic trust path.** A buggy hash can only cause *false negatives* (no match / failed content-bind), never a false-positive verdict — the signature check still has to pass against the envelope's key. The user can independently cross-check the displayed hash with `sha256sum`. The verifier and Ed25519 stay `@noble/ed25519` for exactly the reason hash-wasm doesn't qualify there: a bug in *those* would validate a forgery.
2. **Pure-JS was 2–5× slower**, which would make multi-GB models unusable — the whole motivation for streaming.
3. **Vendoring a WASM build transfers trust to our own compile/audit process** for no net improvement, plus ongoing maintenance.

Future deps should be measured the same way: trust-path → near-prohibited; outside it → justify on real product value and record the reasoning here.

## Test fixtures

The **authoritative** `test-vectors` corpus and the byte-for-byte conformance gate live in `ar-io-proof` (the verification home), not here — the checker is an ordinary consumer of `@ar.io/proof`. For its own behavioral tests (provenance orchestration, report round-trip, the JS⇄WASM agreement gate, the differential probe), the checker keeps **6 `ario.agent/v1` (inline) vectors + 1 `ario.events/v1` external-commitment vector as fixtures** under `test/fixtures/` (copied from the corpus; see `test/fixtures/README.md`). These are fixtures, not a corpus — there is deliberately no digest-pinning ceremony here; that discipline runs upstream.

## Brand (ar.io brand-kit — follow exactly)

Source of truth: `https://ar.io/brand-kit/agents.json`. It defines **only** these — match them precisely:

- **Colors:** Primary `#5427C8` (CTAs/links/accents), Lavender `#DFD6F7` (secondary/backgrounds), Black `#23232D` (text), White `#FFFFFF` (bg), Card Surface `#F0F0F0` (cards).
- **Type:** headlines **Besley 800**; body/UI **Plus Jakarta Sans**. Both **self-hosted** (latin woff2 in `src/fonts/`, OFL) — never a Google Fonts CDN link (that would break invariant #1).
- **Logo:** dark variant on light bg (`ario-full-black.svg`, vendored in `src/brand/`, inlined into CSS as a data URI). Don't alter proportions/colors/orientation. Prefer SVG.
- **Wordmark:** lowercase `ar.io` (sentence-start `Ar.io` only).

The kit defines **no** border, muted-text, hover, state, spacing, or radius tokens. Where the UI needs those, **derive from the brand palette** (neutrals = Black at reduced alpha; affirmative/positive = Primary purple; info tints = Lavender) rather than inventing colors. The **one** unavoidable non-brand color is a single functional **alert red** for the tamper/error states (the kit has no danger color); keep it to that one use. Keep brand tokens in `:root` in `src/styles.css`.

## Gotchas

- **JCS ≠ `JSON.stringify`.** Canonicalization (RFC 8785) sorts keys and has specific escaping; the `canonicalize` package handles it and the vectors pin it. A wrong `payload_hash` is almost always a canonicalization mistake.
- **Strip `signature` before signature verification** (it signs "envelope minus signature").
- **GraphQL lag:** freshly-anchored txs may not be tag-indexed for seconds–minutes; `/raw` is immediate. "no-match" can mean "not indexed yet" — though discovery now asks *every* configured gateway before saying it (empty results fall through), so the verdict copy says "none of the queried gateways."
- **File size is never refused.** The old B11 guard (refuse > 2 GB) protected against the `arrayBuffer()` OOM that streaming removed; its character changed from "refuse" to "advisory + progress." Don't reintroduce a cap — communicate time honestly instead.
- **Same hash, many txs is normal** (re-registration, multi-tenant, or the same bytes as a tamper baseline) — and is also an attack surface (anyone can tag any hash). Group by signer; verify each; never let an untrusted signer's claim drive the headline verdict. (The per-signer attribution of the verdict is a known sharp edge — see `ar-io-agent` memory.)
- **Coverage caveat:** reverse lookup only finds events anchored *after* the `Asset-Hash` tags shipped in `ar-io-agent`; older envelopes verify fine via identifier flows but won't surface here.
