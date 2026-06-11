# Test fixtures

Sample signed envelopes used by this app's own behavioral tests (provenance
orchestration, report round-trip, the differential probe, and the JS↔WASM
agreement gate). They are copied from the **authoritative** `test-vectors-v1.0`
corpus, which lives in [`ar-io-proof`](https://github.com/ar-io/ar-io-proof)
(the polyglot verification home) — not here.

These are **fixtures, not a corpus**: the proof-checker is an ordinary consumer
of `@ar.io/proof`, so it carries a few sample envelopes to drive its tests. The
conformance gate (every kernel reproduces every corpus vector byte-for-byte)
runs in `ar-io-proof` against the one authoritative copy. There is deliberately
no digest-pinning ceremony here.
