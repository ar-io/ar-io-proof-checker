# Vendored test vectors

These envelope conformance vectors are **copied verbatim** from `ar-io-agent`'s
[`test-vectors/`](../../ar-io-agent/test-vectors/) directory. They are the source of
truth for the canonical envelope bytes that this tool's client-side verifier must
reproduce.

- **Source repo:** `ar-io-agent`
- **Synced from commit:** `80b8681d7420964b5f922ad6b6e8c9aca21ae4c5`
- **License:** MIT (the `ar-io-agent` repo carves out `test-vectors/` and the
  verifier-relevant directories as MIT per-directory grants — see that repo's
  `docs/distribution.md` §licensing — so vendoring them here is clean).

## Why vendored rather than referenced

Keeping a copy makes this repo self-contained: CI does not need an `ar-io-agent`
checkout to run the conformance suite. The trade-off is drift risk, which is bounded
two ways:

1. `ar-io-agent`'s own CI regenerates and diffs this corpus on every push, so the
   upstream copy can't silently change.
2. To re-sync, copy `ar-io-agent/test-vectors/envelope-*.json` here and update the
   commit SHA above in the same change.

## What each vector contains

Each `envelope-<event>-NN.json` has:

- `inputs.envelope_pre_signature` — the envelope before the signing fields are added.
- `fixed_keypair.ed25519_public_hex` — the deterministic public key used to sign.
- `expected_outputs`:
  - `payload_jcs_bytes_hex` — JCS-canonical bytes of `payload`.
  - `payload_hash_hex` — `SHA-256(payload_jcs_bytes)`.
  - `envelope_for_sig_jcs_bytes_hex` — JCS-canonical bytes of the envelope **minus**
    `signature` (this is what the signature commits to).
  - `signature_hex` — the Ed25519 signature over `envelope_for_sig_jcs_bytes`.

The conformance test reconstructs the full signed envelope
(`envelope_pre_signature` + `payload_hash` + `public_key` + `signature`) and asserts
the verifier reproduces every one of those expected outputs byte-for-byte **and**
returns a passing verdict.

Merkle-tree vectors are intentionally not vendored yet — this tool verifies envelopes
(Recipe 1); inclusion-proof bundles (Recipe 2) are a later phase.
