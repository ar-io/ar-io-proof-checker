# ar-io-proof-checker

> **Reverse-provenance checker** — drop a file in, discover its on-chain ar.io provenance.

Drag a file into the page. It is hashed **in your browser** (the bytes never leave
your machine). The hash is used to query Arweave for matching ar.io provenance
envelopes, each signature is verified **client-side**, and the artifact's on-chain
history is rendered.

This is the inverse of `ariod verify <tx_id>`: instead of starting from an
identifier and fetching the artifact, you start from the **artifact** — the bytes
you're actually holding — and the content hash becomes the join key into the
on-chain record.

## What it proves — and what it does not

This tool proves **"this artifact has a verifiable history."** It does **not** prove
"this is the version currently running in production," and it does not mean
"safe / good / approved." Provenance is history, not endorsement.

- ✓ These exact bytes have a signed, on-chain provenance record.
- ✓ Who registered them (tenant / agent public key) and when.
- ✓ The latest event on the asset's chain (verified / tampered / missing).
- ✓ Whether these bytes match a *tamper* record (a useful negative result).
- ✗ **Not** "this is the live production version."
- ✗ **Not** "this file is safe."

Absence of a record is **not** proof of tampering — it may mean the bytes were never
registered, were registered by an agent predating content-hash tagging, or none of
the queried gateways have indexed the transaction yet (every configured gateway is
asked before "no match" is declared).

## Trust model

- **Read-only, client-side, zero-upload.** The file never leaves the browser. The
  only bytes that go out are the 64-character hash (inside a GraphQL query) and the
  subsequent `/raw/<tx_id>` fetches. No backend, no account, no telemetry.
- **Trust comes from the payload check, not the tag.** Arweave tags are unsigned
  search hints. After fetching a candidate transaction, the checker re-verifies
  that `payload.hash == <the hash it computed from your bytes>` **and** Ed25519-verifies
  the signature against the envelope's embedded `public_key`. A gateway that lies in
  a tag cannot produce a "verified" verdict.
- **No ar.io service in the trust path.** You can point it at any Arweave gateway —
  or several: the gateway field takes a comma-separated list, tried in order with
  fallback on failure *and* on empty results. The default chain is
  deployment-aware: when the app is served through an ar.io gateway (ArNS, e.g.
  `proof-checker.<gateway>`), that gateway heads the list, followed by the static
  anchors `turbo-gateway.com` and `arweave.net`. If every default gateway is
  exhausted, the tool discovers a few more from the ar.io registry (the chain's
  own `GET /ar-io/peers`) and tries those too — discovered peers are appended
  after the anchors, never before, and a user-typed list is respected strictly
  (no discovery, no silent additions). The UI shows which gateway served the
  result, but no gateway is trusted either way — verification is pure client-side
  cryptography against the public key in the envelope, re-run on every envelope
  regardless of source.
- **You still establish that the key is the agent's key.** The tool shows the signing
  public key; binding it to a real-world identity is out-of-band (same as
  `ariod verify`). See `ar-io-agent`'s `docs/auditor-recipe.md` §4.

## How it works

```
file ──file.stream()──▶ streaming SHA-256 (WASM, in-browser, flat memory)
                          │ 64-hex hash
                          ▼
   GraphQL POST  transactions(tags:[App-Name=ario-agent, Asset-Hash=<hash>])
     (each configured gateway in order; falls through on failure or empty)
                          │ candidate tx_ids
                          ▼
   GET <gateway>/raw/<tx_id>  ──▶ envelope JSON   (per-tx gateway fallback)
                          │
                          ▼
   verify (client-side):  JCS-canonicalize → recompute payload_hash
                          → Ed25519-verify against public_key
                          → confirm payload.hash == your hash
                          ▼
   render provenance timeline + honest verdict
```

**Any file size.** Hashing streams through an incremental WASM SHA-256
([`hash-wasm`](https://github.com/Daninet/hash-wasm) — deliberately *not* a
trust-path dependency; a hash bug can only cause a false negative, never a false
"verified"), so memory stays flat for multi-GB models. Nothing is refused on size;
large files get an honest time advisory and a live progress line instead.

## Relationship to ar-io-agent

Depends on [`ar-io-agent`](../ar-io-agent) **for specification only — no code dependency**:

- the envelope schema (`docs/artifact.md`),
- the conformance **test vectors** (the full `test-vectors-v1.0` corpus, vendored
  under [`packages/proof/test-vectors/`](packages/proof/test-vectors/) with per-file
  SHA gating — see that directory's `VENDORING.md`),
- the `Asset-Hash` / `Observed-Hash` / `Baseline-Hash` tag convention
  (`docs/artifact.md` §11), introduced for exactly this tool.

The verifier here is an **independent implementation** of the same algorithm,
packaged as the [`@ar-io/proof`](packages/proof/) npm workspace (the TypeScript
sibling of the Python [`ar-io-proof`](https://github.com/ar-io/ar-io-proof) kernel;
MIT; not yet published). That is deliberate: a second, conformance-tested
implementation is what demonstrates the product's core claim — auditor-independent
verification with no ar.io code in the trust path. Conformance is enforced in CI:
the verifier must reproduce every test vector byte-for-byte, or the build fails.

**And you can cross-check the implementations against each other, live.** The
"Verify with Go reference (WASM)" button re-verifies the matched envelopes with a
WASM build of ar-io-agent's actual `pkg/proof` kernel — the same code `ariod verify`
runs — built reproducibly at a pinned agent commit ([`wasm/PIN`](wasm/PIN)) and
served from this app's own assets, loaded only on demand (~1 MB compressed; the
base bundle stays light). The JS verifier remains the default; CI additionally
enforces that both implementations return identical verdicts across the whole
conformance corpus and a battery of adversarial negatives.

> **Coverage note:** reverse lookup only finds events anchored on or after the
> `ar-io-agent` release that introduced the content-hash tags. Older envelopes remain
> fully verifiable through the identifier-based flows (`ariod verify <tx_id>`); they
> just won't surface in a hash-based search.

## Exportable reports

Every check can be exported as evidence:

- **Download report (JSON)** — a versioned, typed `ario.proof-checker.report/v1` artifact. It embeds the **raw verified envelopes** and the file hash, so it is **self-verifiable offline**: anyone can re-run the same signature + payload-hash + content checks with any conformant verifier, and it can be dropped back into this tool ("Verify a saved report") to re-verify with no network and no original file.
- **Open printable report** — a human-readable HTML view (Print → Save as PDF). On-chain-derived strings are HTML-escaped.

Unlike `ar-io-verify`'s operator-signed `VerificationBundleV1`, this report is **unsigned by design** — the proof-checker has no signing identity and puts no service in the trust path. Its integrity comes from *re-verification*, not from trusting its issuer. The §scope disclaimers (verifiable-history ≠ live/safe; key identity is out-of-band; absence ≠ tampering) are embedded in the artifact so they travel with it.

## Development

```bash
npm install
npm run dev        # local dev server
npm run test       # conformance + verifier tests (vitest)
npm run typecheck  # tsc --noEmit
npm run build      # static bundle into dist/ (permaweb-deployable)
```

### Try it with sample data

[`samples/`](samples/) has ready-made files that exercise each verdict against
real on-chain data (keep the gateway field at its defaults) — a
verifiable file, a known-good baseline, a tampered version, and an unregistered
one. They are **manual demo fixtures, not part of `npm test`** (the test suite is
hermetic); see [`samples/README.md`](samples/README.md) for expected verdicts and
caveats.

## License

MIT — see [LICENSE](LICENSE). Making the verifier open is the whole point.
