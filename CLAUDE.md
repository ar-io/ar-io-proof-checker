# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **client-side, zero-upload reverse-provenance checker**: drop a file in the browser, it's hashed locally (WebCrypto SHA-256, never uploaded), the hash is queried against Arweave for matching ar.io provenance envelopes, each signature is verified **in the browser**, and the artifact's on-chain history is rendered. It is the inverse of `ariod verify <tx_id>` (identifier → artifact); here you start from the **bytes** and the content hash is the join key.

Single-page app, **vanilla TypeScript + Vite**, minimal runtime dependencies (see "Dependency discipline" below — the discipline is about *trust-path* deps, not a raw count). MIT-licensed (making the verifier open is the point). It is one of the ar.io verification stack siblings and depends on [`ar-io-agent`](../ar-io-agent) **for specification only — no code dependency** (envelope schema, the `Asset-Hash` tag convention, and the conformance test vectors).

## Non-negotiable invariants

These are the product, not preferences. Don't regress them:

1. **Zero upload / read-only.** The file never leaves the browser. The *only* bytes that go out are the 64-hex hash (inside a GraphQL query), `/raw/<tx_id>` fetches, and — default chain only, when a user-initiated check exhausts every configured gateway — one `GET /ar-io/peers` to a gateway already in the chain (registry-driven fallback discovery; deliberate amendment, 2026-06-10). **No request of any kind fires before the user supplies a file**, no backend, no account, no telemetry, no other external requests (fonts are self-hosted, the logo is inlined — see Brand). A user-typed gateway list is respected strictly: no peers fetch, no silent additions.
2. **Trust comes from the payload check, not the tag.** Arweave tags are unsigned search hints. Every candidate tx is fetched and re-verified: recompute `payload_hash = SHA-256(JCS(payload))`, Ed25519-verify against the envelope's embedded `public_key`, and confirm the payload's content hash equals the user's file hash. A gateway that lies in a tag must never be able to produce a "verified" verdict (it lands in `rejected`).
3. **Scope honesty is load-bearing.** The tool proves *"this artifact has a verifiable history"* — never *"this is the live production version"* or *"this file is safe."* Every verdict surface, and the exported report, must keep that line crisp. Absence of a record is **not** evidence of tampering. See `proof-checker.md` §8 in `ar-io-agent` for the exact copy.
4. **Conformance is the contract.** The verifier is an independent re-implementation of the Go agent's algorithm; it MUST reproduce every `test-vectors/` vector byte-for-byte. CI fails on a single mismatch.
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

The flow is: **file → hash → discover → fetch → verify → history → render**, with report export/import bolted onto the result. The verification kernel lives in the **`@ar-io/proof` npm workspace package** (`packages/proof/` — v1.2 Lane H); the app consumes it as a workspace dependency.

### `packages/proof/` — the `@ar-io/proof` kernel (MIT, publishable; NOT yet published)

| Module | Role |
|---|---|
| `src/crypto.ts` | Low-level primitives. The **only** third-party crypto dep is `@noble/ed25519`; SHA-256/512 come from WebCrypto (the ed25519 SHA-512 hook is wired to `crypto.subtle`, so no `@noble/hashes`). Hex/utf8 helpers. `ed25519Verify` never throws — malformed input is "not verified," never a crash. |
| `src/verifier.ts` | **Load-bearing.** Independent impl of `ar-io-agent` `artifact.md` §6 / `auditor-recipe.md` Recipe 1. `verifyEnvelope(env, expectedHash?)` runs the three checks (spec registry, `payload_hash`, Ed25519) plus the optional content-hash bind. The signed scope strips `signature` **and `co_signatures`** (envelope-spec v1.1 §2/§7.1 — pinned by a unit test, the corpus has no co-signed vectors). `specVersionSupported` is a **fail-closed registry** (`ACCEPTED_SPEC_MAJORS`) with additive minors tolerated, matching the Go reference's semantics; the mlflow profile is a later one-entry addition and its dialect behaviors (underscore-key strip) must never leak in. JCS via the `canonicalize` package. `contentHashes()` maps each event type to the payload field(s) the bytes can match (asset_registered→`hash`; asset_missing→`baseline.hash`; tamper_detected→`observed.hash`+`baseline.hash`). |
| `src/merkle.ts` | RFC 9162 binary Merkle tree (leaf/node domain separation, largest-pow2 split, audit paths, fail-closed `verifyInclusion`) — faithful port of the Go `pkg/merkle`, in lockstep with Python's `ario_proof.merkle`, gated against the 7 Merkle vectors. |
| `src/types.ts` / `src/index.ts` | Envelope wire types (incl. reserved `co_signatures`) and the public API surface. |
| `test-vectors/` | The **full** `test-vectors-v1.0` corpus (6 envelope + 7 Merkle vectors), vendored byte-for-byte — see `VENDORING.md` for provenance + re-sync. Per-file SHA-256s re-verified on every test run (`test/conformance.test.ts`), same table as the Python `ar-io-proof` kernel. |
| `test/` | `conformance.test.ts` (corpus integrity + byte-exact conformance), `verifier.test.ts` (negative paths + co_signatures scope + registry), `crypto.test.ts`. |

Workspace consumption resolves the package's TS source via its `exports` map; `npm run build:proof` emits `dist/` ESM + declarations (the publishable shape, exercised in CI). **Before any npm publish:** coordinator green light + confirm the real scope (`@ar.io/` vs `@ar-io/`).

### WASM-Go reference verifier (the optional toggle)

`src/wasm/ario-proof.wasm` is a **reproducible build of ar-io-agent's `pkg/proof`** — the same kernel `ariod verify` runs — at the agent commit pinned in `wasm/PIN` (commit + Go version + build flags + binary SHA-256; the agreement gate re-verifies the digest every test run). `wasm/main.go` is the thin `syscall/js` bridge; `scripts/build-wasm.sh` rebuilds it via a detached git worktree of the sibling agent checkout (shared-checkout discipline: the agent repo is read/build-only, never disturbed). `src/wasm/wasm_exec.js` is the Go runtime shim vendored from the exact toolchain that built the binary.

`src/verifier-wasm.ts` is the lazy adapter: same `verifyEnvelope` shape as `@ar-io/proof`, crypto exclusively inside the WASM, per-check booleans classified fail-closed from the kernel's fail-fast error, content bind computed adapter-side (field comparison, not crypto). **The JS verifier remains the default and the headline** — the toggle is cross-implementation confirmation, never a replacement, and its failure to load never blocks a verdict. Invariant #1 holds: the ~3.5 MB binary (~1 MB gz) is fetched on first use only, from the app's OWN assets (it ships in `dist/`); the adapter + shim are code-split lazy chunks, so the base bundle stays ~23 KB gz.

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
| `types.ts` | Checker-specific types (`AssetEvent`, `AssetHistory`, `ChainContinuity`); re-exports the kernel types (`Envelope`, `VerificationResult`, …) from `@ar-io/proof` so app modules keep one import home. |

`test/` mirrors the app layer: `gateway.test.ts` (list normalization, fetch timeout, per-gateway allSettled resilience, multi-gateway fallback incl. empty-fallthrough and view atomicity, serving-gateway derivation, registry-peers parsing), `provenance.test.ts` (orchestration, continuity, candidate cap, tie-break, registry-extension semantics — stubbed fetch), `report.test.ts` (schema, caps, round-trip self-verification incl. no-match + malformed-embedded, HTML-escaping), `hash.test.ts` (advisory copy), `hash.streaming.test.ts` (the WebCrypto cross-check across sizes incl. the SHA-256 block boundary, a stream-only Blob double proving the file is never materialized, monotonic progress). UI-layer tests use **happy-dom** via a `// @vitest-environment happy-dom` directive: `render.dom.test.ts` (verdict attribution, missing-subject guard, truncation note, multi-gateway surfacing, error verdict, popup→download fallback) and `main.dom.test.ts` (run-token race guard, input reset, keyboard activation). Kernel tests live in `packages/proof/test/` (see above).

## Dependency discipline

The "minimal dependencies" rule is about **trust-path deps, not all deps**. A dependency is trust-path if a bug in it could validate a forgery — produce a "verified" verdict for bytes the agent's key never signed. Today that set is exactly: `canonicalize` (JCS), `@noble/ed25519`, and our own `verifier.ts`. Additions to that set need extraordinary justification; everything else is measured against the bar below.

**`hash-wasm` (streaming SHA-256) clears that bar.** Rationale, recorded when it was added:

1. **SHA-256 is not in the cryptographic trust path.** A buggy hash can only cause *false negatives* (no match / failed content-bind), never a false-positive verdict — the signature check still has to pass against the envelope's key. The user can independently cross-check the displayed hash with `sha256sum`. The verifier and Ed25519 stay `@noble/ed25519` for exactly the reason hash-wasm doesn't qualify there: a bug in *those* would validate a forgery.
2. **Pure-JS was 2–5× slower**, which would make multi-GB models unusable — the whole motivation for streaming.
3. **Vendoring a WASM build transfers trust to our own compile/audit process** for no net improvement, plus ongoing maintenance.

Future deps should be measured the same way: trust-path → near-prohibited; outside it → justify on real product value and record the reasoning here.

## Test vectors

The corpus lives at `packages/proof/test-vectors/` — the **full `test-vectors-v1.0` tag** vendored byte-for-byte from `ar-io-agent` (MIT-carved-out dir). Provenance, the pinned tag/commit, and the governed re-sync procedure are in `packages/proof/test-vectors/VENDORING.md`; `packages/proof/test/conformance.test.ts` re-verifies every per-file SHA-256 on each run, so a drifted copy fails CI before any crypto runs. **Corpus bytes are law** — never edit a vector; byte changes upstream require a major tag + RFC per `ar-io-agent/docs/stack/governance.md` §4.

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
