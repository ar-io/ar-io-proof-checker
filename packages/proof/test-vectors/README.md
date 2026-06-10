# test-vectors

Cross-language conformance vectors for the `ario.agent/v1` spec. Generated
by `tools/gen-vectors/gen_vectors.py` from a fixed Ed25519 seed.

A verifier in any language is **conformant** iff it produces byte-identical
output for every vector here without modification. See
[`docs/artifact.md` §15](../docs/artifact.md#15-test-vectors) for the
file format.

## Regenerating

```bash
make vectors
```

## File naming

- `envelope-<event-type>-NN.json` — one signed-envelope vector
- `merkle-tree-NN-leaves.json` — Merkle tree + inclusion proofs at that leaf count

Vectors are stable. **Do not edit by hand.** Re-run `make vectors` to
regenerate after the producer-side Python tool changes; both must change
together. If a verifier in any language disagrees with a vector, the
verifier is wrong — pin the bug in the verifier, not the vector.
