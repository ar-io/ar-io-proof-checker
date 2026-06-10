# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **client-side, zero-upload reverse-provenance checker**: drop a file in the browser, it's hashed locally (WebCrypto SHA-256, never uploaded), the hash is queried against Arweave for matching ar.io provenance envelopes, each signature is verified **in the browser**, and the artifact's on-chain history is rendered. It is the inverse of `ariod verify <tx_id>` (identifier → artifact); here you start from the **bytes** and the content hash is the join key.

Single-page app, **vanilla TypeScript + Vite**, minimal runtime dependencies (see "Dependency discipline" below — the discipline is about *trust-path* deps, not a raw count). MIT-licensed (making the verifier open is the point). It is one of the ar.io verification stack siblings and depends on [`ar-io-agent`](../ar-io-agent) **for specification only — no code dependency** (envelope schema, the `Asset-Hash` tag convention, and the conformance test vectors).

## Non-negotiable invariants

These are the product, not preferences. Don't regress them:

1. **Zero upload / read-only.** The file never leaves the browser. The *only* bytes that go out are the 64-hex hash (inside a GraphQL query) and `/raw/<tx_id>` fetches. No backend, no account, no telemetry, **no external requests of any kind** (fonts are self-hosted, the logo is inlined — see Brand).
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

## Architecture (`src/`)

The flow is: **file → hash → discover → fetch → verify → history → render**, with report export/import bolted onto the result.

| Module | Role |
|---|---|
| `crypto.ts` | Low-level primitives. The **only** third-party crypto dep is `@noble/ed25519`; SHA-256/512 come from WebCrypto (the ed25519 SHA-512 hook is wired to `crypto.subtle`, so no `@noble/hashes`). Hex/utf8 helpers. `ed25519Verify` never throws — malformed input is "not verified," never a crash. |
| `verifier.ts` | **Load-bearing.** Independent impl of `ar-io-agent` `artifact.md` §6 / `auditor-recipe.md` Recipe 1. `verifyEnvelope(env, expectedHash?)` runs the three checks (spec major, `payload_hash`, Ed25519) plus the optional content-hash bind. JCS via the `canonicalize` package. `contentHashes()` maps each event type to the payload field(s) the bytes can match (asset_registered→`hash`; asset_missing→`baseline.hash`; tamper_detected→`observed.hash`+`baseline.hash`). |
| `hash.ts` | **Streaming** in-browser SHA-256: `file.stream()` chunks feed `hash-wasm`'s incremental hasher, memory stays flat at any file size, progress is reported via callback. No size refusal — `fileSizeAdvisory` is honest-time advisory only. Not trust-path crypto (see "Dependency discipline"); the streaming output is pinned against WebCrypto in `test/hash.streaming.test.ts`. |
| `gateway.ts` | The only outbound traffic. Every operation takes an ordered **gateway list** and falls through on failure (network/5xx/timeout); discovery additionally falls through on an *empty* result, so "no match" means "none of the configured gateways know these bytes" — first non-empty view wins, views stay atomic (no cross-gateway union). `findEnvelopeTxs` unions GraphQL queries over the three content-hash tags (`Asset-Hash`/`Observed-Hash`/`Baseline-Hash`) per gateway and dedupes; the serving gateway is surfaced (`Discovery.gateway`). `findAssetEventTxs` queries all of an asset's events by `Asset-Id` (+ block timestamps). `fetchEnvelope` does `/raw/<tx>` with per-gateway fallback (404 falls through — propagation lag). Defaults: `turbo-gateway.com`, `arweave.net`. Registry-driven gateway discovery is deliberately absent (an automatic list fetch would violate invariant #1); revisit at P5 as a user-triggered action. |
| `provenance.ts` | Orchestration → `ProvenanceReport` (`verdict` ∈ provenance-found / tampered-bytes / no-match / error, `matches`, `histories`, `rejected`). `buildAssetHistory` reconstructs a per-asset timeline; `assessContinuity` checks per-type `previous_hash` chains **conservatively** — an unresolved link is `partial`, NEVER implied tampering. |
| `report.ts` | Exportable, **self-verifiable** `ario.proof-checker.report/v1`. `buildReport` embeds the raw verified envelopes + hash; `verifyReport` re-runs verification against that embedded evidence with no network (round-trip); `reportToJson` / `reportToHtml` (HTML-escaped — reports can embed attacker-chosen strings). Unsigned by design (we have no key); integrity = re-verification. |
| `render.ts` | All DOM. **Always `textContent`, never `innerHTML`** — envelope fields are untrusted. Verdict banner + honest copy, per-asset timeline, multi-match grouping, report action bar, and the re-import verification view. |
| `main.ts` | Wires drop zone / file input / gateway field / report re-import. |
| `types.ts` | `Envelope`, `VerificationResult`, `AssetEvent`, `AssetHistory`, etc. |

`test/` mirrors this: `conformance.test.ts` (the byte-exact gate over `test-vectors/`), `verifier.test.ts` (negative paths — tampered payload / forged sig / swapped key / bad hex / non-object guard), `crypto.test.ts` (strict hex), `gateway.test.ts` (list normalization, fetch timeout, per-gateway allSettled resilience, multi-gateway fallback incl. empty-fallthrough and view atomicity), `provenance.test.ts` (orchestration, continuity, candidate cap, tie-break — stubbed fetch), `report.test.ts` (schema, caps, round-trip self-verification incl. no-match + malformed-embedded, HTML-escaping), `hash.test.ts` (advisory copy), `hash.streaming.test.ts` (the WebCrypto cross-check across sizes incl. the SHA-256 block boundary, a stream-only Blob double proving the file is never materialized, monotonic progress). UI-layer tests use **happy-dom** via a `// @vitest-environment happy-dom` directive: `render.dom.test.ts` (verdict attribution, missing-subject guard, truncation note, multi-gateway surfacing, popup→download fallback) and `main.dom.test.ts` (run-token race guard, input reset, keyboard activation).

## Dependency discipline

The "minimal dependencies" rule is about **trust-path deps, not all deps**. A dependency is trust-path if a bug in it could validate a forgery — produce a "verified" verdict for bytes the agent's key never signed. Today that set is exactly: `canonicalize` (JCS), `@noble/ed25519`, and our own `verifier.ts`. Additions to that set need extraordinary justification; everything else is measured against the bar below.

**`hash-wasm` (streaming SHA-256) clears that bar.** Rationale, recorded when it was added:

1. **SHA-256 is not in the cryptographic trust path.** A buggy hash can only cause *false negatives* (no match / failed content-bind), never a false-positive verdict — the signature check still has to pass against the envelope's key. The user can independently cross-check the displayed hash with `sha256sum`. The verifier and Ed25519 stay `@noble/ed25519` for exactly the reason hash-wasm doesn't qualify there: a bug in *those* would validate a forgery.
2. **Pure-JS was 2–5× slower**, which would make multi-GB models unusable — the whole motivation for streaming.
3. **Vendoring a WASM build transfers trust to our own compile/audit process** for no net improvement, plus ongoing maintenance.

Future deps should be measured the same way: trust-path → near-prohibited; outside it → justify on real product value and record the reasoning here.

## Test vectors

`test-vectors/` is **vendored from `ar-io-agent`** (MIT-carved-out dir) — see its README for the source commit. To re-sync: copy `ar-io-agent/test-vectors/envelope-*.json` here and bump the recorded SHA. `ar-io-agent`'s own CI guards that corpus, so it can't drift silently upstream; the conformance test guards it downstream.

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
