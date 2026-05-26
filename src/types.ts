// Wire types for ar.io agent provenance envelopes. Mirrors ar-io-agent's
// docs/artifact.md §3–§4. We model only the fields the verifier and the
// reverse-lookup UI consume; unknown fields are preserved by structural typing
// (envelopes are verified over their canonical bytes, not this interface).

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
  // Content bind: did the hash the caller supplied (the in-browser hash of the
  // user's file) match a hash this envelope commits to? null when no hash was
  // supplied (e.g. verifying an envelope on its own). This is the check that
  // defeats a lying gateway — the tag only got us to the candidate.
  contentHashOk: boolean | null;
  contentRole: ContentRole | null;
  errors: string[];
}
