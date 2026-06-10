# Conformance corpus — v1.0

> **Corpus tag: `test-vectors-v1.0`** (annotated git tag on the commit that adds this file). Locked at the standards ratification of 2026-06-10 per [`docs/stack/governance.md`](../docs/stack/governance.md) §4: corpus changes from here are minor bumps (`test-vectors-v1.x`); any change to the bytes of a file listed below is major (`test-vectors-v2.0`, 30-day RFC). Every conformant downstream pins a corpus tag and records which.

## Scope

This corpus is the **`ario.agent/v1` profile vectors** (signed-envelope + RFC-9162 Merkle), generated — never hand-edited — by `tools/gen-vectors/gen_vectors.py` from a fixed Ed25519 seed, in the [`docs/artifact.md` §15](../docs/artifact.md) file format. It is the agent half of the family conformance suite defined in [`docs/envelope-spec.md` §6](../docs/envelope-spec.md) (ratified v1.0); the mlflow-profile half (external-commitment envelopes exercised by the bidirectional cross-product tests) lives in the sibling `ar-io-mlflow` repo. A kernel is conformant for the modes it accepts iff it reproduces its pinned corpus byte-for-byte ([`docs/stack/architecture.md`](../docs/stack/architecture.md) K3).

## Contents at v1.0 (14 files)

| File | SHA-256 |
|---|---|
| `envelope-asset-missing-01.json` | `fecb29289df2b6ea210b51737e6cdf10438ec996add050b053247cc567fe2e27` |
| `envelope-asset-registered-01.json` | `3b99fc850edba7775a4df970e406fcb2d787fc10594cd7f969936938b881b9a9` |
| `envelope-key-retired-01.json` | `2e89bc2b1986e3545d0aae94f850d675f9f16fc384b311cc75090a5e275eaf33` |
| `envelope-policy-changed-01.json` | `62a460fb4e0e49c2ef28acc73ddea1163f801ccef6c0e247679e65e6c655509c` |
| `envelope-tamper-detected-01.json` | `5f4b8b1dab9c50ca97ff0349e39481ee33f9a19991632d13fb71fd940a88fcd0` |
| `envelope-verification-checkpoint-01.json` | `393c04e411807481587c591ccb1e637cb072f40940cbc9d25e53dd29253bb56d` |
| `merkle-tree-00-leaves.json` | `705adf82ce9cc46d0e45fce216cb205d5755e2d41975b66444f1765a982faa95` |
| `merkle-tree-01-leaves.json` | `bdbb57ad29272054c5dcc655c2279c4debec9c4c67ea85f17490760a19b52923` |
| `merkle-tree-02-leaves.json` | `9c33d0fcb57655729a0e657b8b4313de806e397949465d310338db5dd56a573b` |
| `merkle-tree-03-leaves.json` | `f4cc12cd11cb3a49225edff2c18ab9f516992f8d6c13e7baadb627f1c7efe8eb` |
| `merkle-tree-07-leaves.json` | `8372c63f3d5a61c8dfc0939fb5776b8041960313df4f9334e620d398326bdd1c` |
| `merkle-tree-1024-leaves.json` | `e732c755539b84e20b80d15e5a7989e2d6736153d9d78c944ed6e7ee98627254` |
| `merkle-tree-16-leaves.json` | `b58b31340bef317fd32734be7e3ff58b0d4a4d0cb03a7b16f08056161c7ae72c` |
| `README.md` | `7d21d23fcbf9996e9e7a710099bb59b4cb501720ded57aac65edde43de10ef44` |

One envelope vector per `ario.agent/v1` event type (six), plus Merkle trees at leaf counts 0, 1, 2, 3, 7, 16, and 1024 (each with inclusion proofs).

## Verifying a vendored copy

```bash
sha256sum envelope-*.json merkle-*.json README.md   # compare against the table above
```

Known downstream pins: `ar-io-proof` (Python kernel, vendors at `test-vectors-v1.0`), `ar-io-proof-checker` (JS verifier conformance gate), `ar-io-mlflow` cross-product, `tools/ans104-conformance`.
