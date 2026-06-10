// App-layer types. The envelope wire types and verification result live in the
// @ar-io/proof kernel package (packages/proof) and are re-exported here so app
// modules keep one import home; the types below are checker-specific (timeline
// reconstruction and UI grouping), deliberately OUTSIDE the kernel's
// single-envelope scope boundary.

import type { ContentRole, Envelope, VerificationResult } from "@ar-io/proof";

export type { ContentRole, Envelope, Subject, VerificationResult } from "@ar-io/proof";

// One verified event in an asset's on-chain timeline.
export interface AssetEvent {
  txId: string;
  envelope: Envelope;
  verification: VerificationResult;
  // Arweave block timestamp (unix seconds) — the trusted "when," populated once
  // the tx is mined (~2 min). null while still in the mempool; fall back to the
  // envelope's advisory signed_at for ordering/display (artifact.md §6, App. A).
  blockTimestamp: number | null;
  blockHeight: number | null;
  // Does the user's dropped file match THIS specific event, and as what role?
  // null for the asset's other historical events (different bytes).
  matchedRole: ContentRole | null;
}

// How completely we could reconstruct an asset's per-type previous_hash chains
// from what the gateway returned. Deliberately conservative: a chain we can't
// fully link is "partial," NEVER implied to be tampering — absence of an event
// is not evidence of one (proof-checker.md §8).
export type ChainContinuity = "linked" | "partial" | "single";

// The full on-chain history of a single asset under one (tenant, agent), built
// by querying every event carrying its Asset-Id tag and verifying each. This is
// the unit of the multi-match grouping in the UI (proof-checker.md §9).
export interface AssetHistory {
  tenantId: string;
  agentId: string;
  assetId: string;
  events: AssetEvent[]; // newest-first
  continuity: ChainContinuity;
  note: string; // human-readable continuity caveat
}
