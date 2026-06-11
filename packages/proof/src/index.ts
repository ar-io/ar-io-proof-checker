// @ar.io/proof — TypeScript kernel of the ar.io verification stack.
//
// The verification primitives for the Verifiable Event Envelope family
// (ar-io-agent docs/envelope-spec.md), ario.agent/v1 profile: RFC 8785 (JCS)
// canonicalization, SHA-256, Ed25519 envelope verification, and the
// content-hash extraction used for reverse provenance lookup. Sibling of the
// Python `ar-io-proof` kernel and the Go `pkg/proof` reference; conformance
// is byte-for-byte against the shared `test-vectors-v1.0` corpus.
//
// Scope boundary (envelope-spec §10 #13): this package verifies a SINGLE
// envelope. Chain walking (previous_hash), checkpoint reconciliation, and
// gateway/transport concerns are consumer-layer logic composed above it.

export { contentHashes, jcs, specVersionSupported, verifyEnvelope } from "./verifier";
export { bytesToHex, ed25519Verify, hexToBytes, sha256Bytes, sha256Hex, utf8 } from "./crypto";
export {
  EMPTY_TREE_ROOT_HEX,
  auditPath,
  leafHash,
  merkleRoot,
  nodeHash,
  verifyInclusion,
} from "./merkle";
export type { ContentRole, Envelope, Subject, VerificationResult } from "./types";
