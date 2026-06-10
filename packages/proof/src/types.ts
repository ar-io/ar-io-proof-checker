// Wire types for ar.io Verifiable Event Envelopes (ar-io-agent
// docs/envelope-spec.md; the ario.agent/v1 profile detail is artifact.md
// §3–§4). We model only the fields the verifier consumes; unknown fields are
// preserved by structural typing (envelopes are verified over their canonical
// bytes, not this interface).

export interface Subject {
  type: string;
  tenant_id: string;
  agent_id: string;
}

export interface Envelope {
  spec_version: string;
  event_id: string;
  event_type: string;
  subject: Subject;
  payload_hash: string;
  payload: Record<string, unknown>;
  previous_hash: string;
  signed_at: string;
  public_key: string;
  signature: string;
  // Reserved, default-absent (envelope-spec §7.1): countersignatures over the
  // same skeleton. OUTSIDE the signed scope — the primary signature covers the
  // envelope minus `signature` AND minus `co_signatures`, so a countersignature
  // can be added without invalidating the primary. Absence implies a single
  // signer and MUST NOT be treated as a failure.
  co_signatures?: unknown[];
}

// Which payload field a matched content hash came from. tamper_detected commits
// to both the tampered ("observed") bytes and the known-good ("baseline") bytes.
export type ContentRole = "asset" | "baseline" | "observed";

export interface VerificationResult {
  // Cryptographic validity: spec_version + payload_hash + Ed25519 signature all
  // passed. This is "the envelope is authentic," independent of the user's bytes.
  ok: boolean;
  specVersionOk: boolean;
  payloadHashOk: boolean;
  signatureOk: boolean;
  // Content bind: did the hash the caller supplied (e.g. the in-browser hash of
  // a user's file) match a hash this envelope commits to? null when no hash was
  // supplied (verifying an envelope on its own). This is the check that defeats
  // a lying gateway — the tag only got us to the candidate.
  contentHashOk: boolean | null;
  contentRole: ContentRole | null;
  errors: string[];
}
