# @ar-io/proof

> TypeScript kernel of the ar.io verification stack — verify a Verifiable Event
> Envelope with no ar.io service in the trust path.

The verification primitives for the envelope family specified in
`ar-io-agent/docs/envelope-spec.md` (ario.agent/v1 profile per `artifact.md`):

- **RFC 8785 (JCS)** canonicalization (`jcs`)
- **SHA-256** (`sha256Hex`) via WebCrypto
- **Ed25519** signature verification (`ed25519Verify`, via `@noble/ed25519` with
  the SHA-512 hook wired to WebCrypto)
- **`verifyEnvelope(env, expectedContentHash?)`** — the three load-bearing checks
  (spec-version registry, `payload_hash` recompute, Ed25519 over the signed
  scope) plus the optional content-hash bind
- **`contentHashes(env)`** — which payload hash(es) an envelope commits to, by
  event type (the reverse-provenance join keys)

This is the TypeScript sibling of the Python [`ar-io-proof`](https://github.com/ar-io/ar-io-proof)
kernel and the Go reference (`ar-io-agent/pkg/proof`). All three are independent
implementations of the same algorithm, each conformance-gated **byte-for-byte**
against the shared `test-vectors-v1.0` corpus — that mutual gate is the
product's core claim: verification needs no ar.io code in the trust path.

## Signed scope

The primary signature covers `JCS(envelope minus signature minus co_signatures)`
(envelope-spec §2, §7.1). The `co_signatures` carve-out lets a countersignature
be added without invalidating the primary signature; the field is reserved and
default-absent, and its absence is never a failure.

## Spec-version acceptance

Fail-closed registry (`specVersionSupported`): exactly the accepted majors —
`ario.agent/v1` and additive minors within it (`ario.agent/v1.<minor>`),
matching the Go reference's semantics. Unknown majors and other profiles are
rejected. The mlflow profile (`ario.mlflow/v1`) is a deliberate later one-entry
addition, **not** implemented here — mlflow-dialect behaviors (e.g. the
underscore-key strip) must not leak into the agent profile.

## Workspace status

Lives as an npm workspace inside `ar-io-proof-checker` (v1.2 wave decision —
no separate repo yet); the checker consumes it as its verifier. **Not yet
published to npm.** Before any publish: confirm the real npm scope (`@ar.io/`
vs `@ar-io/`), flip `exports` to the built `dist/` output (`npm run build`
emits ESM + type declarations), and get the coordinator's green light.

MIT — verification must be open. See `LICENSE`.
