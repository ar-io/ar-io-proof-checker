# @ar.io/proof

Verify [ar.io verification-stack](https://github.com/ar-io) provenance records — **with no ar.io code or service in the trust path**.

This is the TypeScript verification kernel for the *Verifiable Event Envelope* family: the signed JSON records that tools like the [`ariod` verification agent](https://github.com/ar-io/ar-io-agent) and the [MLflow plugin](https://github.com/ar-io/ar-io-mlflow) anchor permanently to Arweave. Given an envelope (fetched from any Arweave gateway), this package answers: *is it authentic, and does it commit to the bytes I'm holding?*

- **RFC 8785 (JCS)** canonicalization
- **SHA-256** payload binding (WebCrypto)
- **Ed25519** signature verification ([`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519))
- **RFC 9162** binary Merkle inclusion proofs (checkpoint leaves)
- Zero config, two small dependencies, ESM, browser + Node ≥ 20

## Install

```bash
npm install @ar.io/proof
```

## Verify an envelope

Fetch the raw transaction from any Arweave gateway and verify it client-side:

```ts
import { verifyEnvelope } from "@ar.io/proof";

const env = await (await fetch("https://arweave.net/raw/<tx_id>")).json();
const result = await verifyEnvelope(env);

result.ok;            // spec_version + payload_hash + Ed25519 all passed
result.signatureOk;   // Ed25519 over the signed scope, against env.public_key
result.payloadHashOk; // SHA-256(JCS(payload)) === env.payload_hash
result.errors;        // [] when ok — machine-readable reasons otherwise
```

`verifyEnvelope` never throws on hostile input — a malformed envelope (or a lying gateway) yields `ok: false` with reasons, not an exception.

## Bind an envelope to bytes you hold (reverse provenance)

The check that defeats a lying gateway: Arweave *tags* are unsigned search hints, so after finding a candidate envelope, confirm it actually commits to your artifact's hash:

```ts
import { sha256Hex, verifyEnvelope, contentHashes } from "@ar.io/proof";

const myHash = await sha256Hex(fileBytes); // 64-char lowercase hex

const result = await verifyEnvelope(env, myHash);
result.contentHashOk; // true ⇔ the envelope commits to exactly these bytes
result.contentRole;   // how it commits: e.g. the registered baseline,
                      // an observed (tampered) hash, …

contentHashes(env);   // all content hashes an envelope commits to, by event type
```

## Verify a Merkle inclusion proof

Agents close daily checkpoints over per-cycle leaves (RFC 9162, §2.1 domain separation — not the Bitcoin duplicate-leaf variant). Verify a leaf's inclusion against an anchored root:

```ts
import { leafHash, verifyInclusion, hexToBytes } from "@ar.io/proof";

const ok = await verifyInclusion(
  await leafHash(leafBytes), // Uint8Array leaf hash
  leafIndex,                 // 0-based position
  totalLeaves,
  auditPath.map(hexToBytes), // sibling hashes, leaf → root
  hexToBytes(expectedRootHex),
);
```

## API

| Export | What it does |
|---|---|
| `verifyEnvelope(env, expectedContentHash?)` | The three load-bearing checks (spec-version registry, payload-hash recompute, Ed25519 over the signed scope) + optional content bind. Returns `VerificationResult`. |
| `contentHashes(env)` | The content hash(es) an envelope commits to, by event type — the reverse-provenance join keys. |
| `specVersionSupported(v)` | Fail-closed accept-check: `ario.agent/v1` and additive minors (`ario.agent/v1.<n>`). Unknown majors/profiles are rejected. |
| `jcs(value)` | RFC 8785 canonical JSON bytes. |
| `sha256Hex(bytes)` / `sha256Bytes(bytes)` | SHA-256 via WebCrypto. |
| `ed25519Verify(sig, msg, pubKey)` | Raw Ed25519 verification. |
| `leafHash` / `nodeHash` / `merkleRoot` / `auditPath` / `verifyInclusion` / `EMPTY_TREE_ROOT_HEX` | RFC 9162 binary Merkle tree primitives. |
| `utf8` / `bytesToHex` / `hexToBytes` | Encoding helpers. |
| `Envelope` / `VerificationResult` / `ContentRole` / `Subject` | Types. |

### Signed scope

The primary signature covers `JCS(envelope minus signature minus co_signatures)` ([envelope-spec](https://github.com/ar-io/ar-io-proof/blob/main/specs/envelope-spec.md) §2/§7.1). The reserved `co_signatures` carve-out lets countersignatures be added later without invalidating the primary signature.

## Why you can trust it (without trusting us)

Three **independent implementations** of this kernel exist — this package, the Python [`ar-io-proof`](https://pypi.org/project/ar-io-proof/) (PyPI), and the Go reference ([`ar-io-agent/pkg/proof`](https://github.com/ar-io/ar-io-agent/tree/main/pkg/proof), MIT-carved) — and every one is conformance-gated **byte-for-byte** in CI against the shared, frozen [`test-vectors-v1.0` corpus](https://github.com/ar-io/ar-io-proof/tree/main/test-vectors) (per-file SHA-256 pins). The [proof-checker web app](https://github.com/ar-io/ar-io-proof-checker) additionally runs this kernel and a WASM build of the Go reference against each other live, asserting identical verdicts across the corpus plus adversarial negatives.

That mutual gate is the point: anyone can verify ar.io provenance records with **no ar.io code in the trust path** — write your own verifier against the [public specs](https://github.com/ar-io/ar-io-proof/tree/main/specs) and the corpus will tell you if it's conformant.

## What this package deliberately does NOT do

- **Single-envelope scope.** Chain walking (`previous_hash`), checkpoint reconciliation, and gateway/transport logic are consumer-layer concerns composed above the kernel.
- **Provenance is history, not endorsement.** A verified envelope proves *these bytes have this signed, anchored history* — never "safe," "approved," or "currently in production."
- **Key identity is out-of-band.** The kernel proves the signature matches `env.public_key`; binding that key to a real-world identity is yours to establish.

## Requirements

ESM-only. Needs WebCrypto (`globalThis.crypto.subtle`): any modern browser, Node.js ≥ 20 (≥ 19 works), Deno, Bun, workers.

## License

MIT — verification must be open.
