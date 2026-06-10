# Vendoring provenance

This directory is a byte-for-byte copy of `ar-io-agent/test-vectors/` at the annotated git
tag **`test-vectors-v1.0`** (tag object `b5e7df690b4e2840f483927b3758c8b5c24f4601`, commit
`133761633b76f158a22524eb8effbb57a89343de`).

The corpus files themselves are untouched — including `README.md` and `CORPUS-v1.md`, whose
SHA-256 digests are pinned in [`CORPUS-v1.md`](CORPUS-v1.md)'s table — which is why this
provenance note lives in a separate file instead of being appended to the vendored README.

`test/conformance.test.ts` re-verifies every digest in the CORPUS-v1.md table on each test
run, so a drifted vendored copy fails CI. The same discipline (and the same pinned digests)
is used by the Python sibling kernel, `ar-io-proof`.

## Re-syncing

Per `ar-io-agent/docs/stack/governance.md` §4: additive corpus changes arrive as minor tags
(`test-vectors-v1.x`); byte changes to existing vectors are a major tag + 30-day RFC. To
re-sync:

```bash
git -C ../../../ar-io-agent archive <new-tag> test-vectors | tar -x -C .
```

(run from `packages/proof/`), then update the tag/commit recorded here and the expected
digests in `test/conformance.test.ts`, in the same commit.
