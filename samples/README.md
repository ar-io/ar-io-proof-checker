# Sample files (manual demo fixtures)

Drop these into the running app (`npm run dev`, or a deployed build) to see each
verdict. **Keep the gateway field at its defaults (`turbo-gateway.com, arweave.net`).**

> These are **manual / demo fixtures, not automated tests.** The automated suite
> (`npm test`) is hermetic — it uses the vendored `test-vectors/` and a mocked
> `fetch`, and never touches the network. These samples, by contrast, depend on a
> gateway having **indexed** real on-chain envelopes, so they are deliberately
> kept out of CI.

## Expected verdicts

| File | SHA-256 (first 16) | Verdict | Notes |
|---|---|---|---|
| `sample-verifiable.txt` | `05e4c476d27dfc0c` | ✓ **Provenance found** | Pristine registration — 1 match, clean timeline. |
| `sample-demo-original.txt` | `ca7f889b3492748a` | ✓ **Provenance found** | Registered *and* the known-good baseline of a later tamper — timeline shows 2 events, your file badged on both. |
| `sample-demo-tampered.txt` | `0009bc6efe3a3871` | ⚠ **Matches a TAMPER record** | The tampered content — binds the tamper's `Observed-Hash`. |
| `sample-no-provenance.txt` | `7025acc5c65cb6ab` | ✗ **No provenance found** | Never anchored. The honest "no record ≠ tampering" case. |

## On-chain provenance (anchored to Arweave, permanent)

- Registrations: `SPl3o8ZOclpO4IJxwVFvTbDl4kmEFQfQX7GLA4bCB0M`, `6hmk0iHDPvGN_eKRlMMNnu3qqGy0jBYcHuDSRXZ14fY`
- Tamper: `5ZLKG45CODwNRaaE8LSc3tvaQAO8Xdc91KWfFC9vGw8`
- Demo identity: tenant `proofcheck-demo`, agent `pc-samples-2` (a throwaway demo agent — not a real operator).

## Caveats

- **Do not edit the bytes.** Even adding a trailing newline changes the hash and
  the file will read as "no provenance found."
- **Gateway-dependent.** A "found" verdict requires the queried gateway to have
  indexed the envelopes above. The default `turbo-gateway.com` has them (and with multi-gateway fallback, an unindexed first gateway falls through). If a
  sample unexpectedly reads "no match," it's almost always gateway/indexing — not
  a bug in the app (the bytes are permanently on Arweave regardless).
- Regenerate or add fixtures by registering files with `ariod` (with `Asset-Hash`
  tagging) and anchoring them live; then record the new hashes + tx ids here.
