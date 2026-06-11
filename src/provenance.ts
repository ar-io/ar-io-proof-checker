// Orchestration: file -> in-browser hash -> gateway lookup -> fetch -> verify ->
// per-asset history -> honest verdict. This is the seam the UI talks to; it
// performs no rendering.

import {
  DEFAULT_GATEWAYS,
  fetchEnvelope,
  findAssetEventTxs,
  findEnvelopeTxs,
  type AssetEventTxRef,
} from "./gateway";
import { sha256OfFile, type HashProgress } from "./hash";
import type {
  AssetEvent,
  AssetHistory,
  ChainContinuity,
  ContentRole,
  Envelope,
  VerificationResult,
} from "./types";
import { verifyEnvelope } from "@ar.io/proof";

export interface Match {
  txId: string;
  envelope: Envelope;
  verification: VerificationResult;
  role: ContentRole; // which payload field the user's bytes matched
}

export interface Rejected {
  txId: string;
  reason: string;
}

// What the verdict line says. Distinct from "is the envelope valid" — the UI
// must keep "provenance exists" and "is the live version" separate (§8).
export type Verdict =
  | "provenance-found" // bytes match a verified asset_registered / baseline
  | "tampered-bytes" // bytes match a verified tamper_detected Observed-Hash
  | "no-match" // nothing on the queried gateway referenced these bytes
  | "error"; // the lookup itself failed (network / gateway), verdict unknown

export interface ProvenanceReport {
  fileHash: string;
  gateway: string; // the GraphQL gateway whose view produced the result (see Discovery)
  graphqlGatewaysQueried: string[]; // GraphQL gateways actually asked, in order
  dataGatewaysQueried: string[]; // data gateways actually asked, in order
  registryPeersUsed?: string[]; // fallback gateways discovered via /ar-io/peers, if any were queried
  verdict: Verdict;
  matches: Match[]; // verified AND content-bound to the user's bytes
  histories: AssetHistory[]; // full timeline of each asset the bytes touched
  rejected: Rejected[]; // tag-matched candidates that failed verification/bind
  candidatesTruncated: boolean; // gateway returned more candidates than we processed
  error?: string; // populated when verdict === "error"
}

// Upper bound on candidate transactions we fetch + verify for one hash. A
// popular — or deliberately tag-spammed — hash could otherwise return hundreds
// of envelopes and turn the verifier into a slow/expensive serial fetch loop.
// When exceeded, candidatesTruncated is set so the UI can say so.
export const MAX_CANDIDATES = 50;

// The headline verdict from the roles the user's bytes bound to. Single source
// of truth shared with report.verifyReport so the two can't drift.
export function verdictFromRoles(roles: ContentRole[]): Verdict {
  if (roles.length === 0) return "no-match";
  // A tampered-bytes match (the user holds the flagged content) is the headline;
  // attribution of WHO flagged it is surfaced in the UI, not encoded here.
  if (roles.includes("observed")) return "tampered-bytes";
  return "provenance-found";
}

export interface CheckOptions {
  // Lazily supplies registry-discovered fallback gateways (fetchRegistryPeers).
  // Consulted ONLY when every configured gateway failed or none knew the
  // bytes — the configured chain always gets asked first, in full.
  registryPeers?: () => Promise<string[]>;
}

// Run the full check for a file against an ordered gateway list. The registry
// fetch (opts.registryPeers) is NOT started here — it fires only if discovery
// exhausts the configured chain, so a successful check makes no registry
// request at all.
export async function checkProvenance(
  file: Blob,
  graphqlGateways: string[] = DEFAULT_GATEWAYS,
  dataGateways: string[] = DEFAULT_GATEWAYS,
  onProgress?: HashProgress,
  opts?: CheckOptions,
): Promise<ProvenanceReport> {
  const fileHash = await sha256OfFile(file, onProgress);
  return checkProvenanceForHash(fileHash, graphqlGateways, dataGateways, opts);
}

// Same as checkProvenance but starting from an already-computed hash. Separated
// so callers (and tests) can drive the lookup/verify path without a File.
export async function checkProvenanceForHash(
  fileHash: string,
  graphqlGateways: string[] = DEFAULT_GATEWAYS,
  dataGateways: string[] = DEFAULT_GATEWAYS,
  opts?: CheckOptions,
): Promise<ProvenanceReport> {
  // Mutable copies — registry peers may extend these.
  let gqlChain = [...graphqlGateways];
  let dataChain = [...dataGateways];

  const base: Omit<ProvenanceReport, "verdict"> = {
    fileHash,
    gateway: gqlChain[0] ?? "",
    graphqlGatewaysQueried: gqlChain,
    dataGatewaysQueried: dataChain,
    matches: [],
    histories: [],
    rejected: [],
    candidatesTruncated: false,
  };

  let txs: Awaited<ReturnType<typeof findEnvelopeTxs>>["txs"] | undefined;
  let discoveryError: unknown;
  try {
    const discovery = await findEnvelopeTxs(gqlChain, fileHash);
    txs = discovery.txs;
    base.gateway = discovery.gateway;
  } catch (e) {
    discoveryError = e;
  }

  // Registry-driven extension: the configured chain is exhausted (every
  // gateway failed, or all were reachable but none knew the bytes) — extend
  // it ONCE with discovered peers and retry discovery over just those. The
  // peers are hints, never trust; their envelopes verify like any other.
  // Peers extend both chains (ar.io gateways serve GraphQL + /raw/).
  if ((discoveryError !== undefined || txs?.length === 0) && opts?.registryPeers) {
    let fresh: string[] = [];
    try {
      fresh = (await opts.registryPeers()).filter(
        (g) => !graphqlGateways.includes(g) && !dataGateways.includes(g),
      );
    } catch {
      // discovery of more gateways is best-effort; keep the original outcome.
    }
    if (fresh.length > 0) {
      gqlChain = [...graphqlGateways, ...fresh];
      dataChain = [...dataGateways, ...fresh];
      base.graphqlGatewaysQueried = gqlChain;
      base.dataGatewaysQueried = dataChain;
      base.registryPeersUsed = fresh;
      try {
        const d2 = await findEnvelopeTxs(fresh, fileHash);
        // Adopt the peer view when it found something, or when the configured
        // chain produced no view at all (then even a reachable-empty peer
        // honestly upgrades "error" to "no-match").
        if (d2.txs.length > 0 || discoveryError !== undefined) {
          txs = d2.txs;
          base.gateway = d2.gateway;
          discoveryError = undefined;
        }
      } catch {
        // every peer failed too; the original outcome stands.
      }
    }
  }

  if (discoveryError !== undefined || txs === undefined) {
    return { ...base, verdict: "error", error: stringifyErr(discoveryError) };
  }

  // Cap how many candidates we fetch + verify (DoS / spam guard, B5).
  const candidatesTruncated = txs.length > MAX_CANDIDATES;
  const candidates = candidatesTruncated ? txs.slice(0, MAX_CANDIDATES) : txs;

  const matches: Match[] = [];
  const rejected: Rejected[] = [];

  for (const tx of candidates) {
    try {
      const envelope = await fetchEnvelope(dataChain, tx.id);
      const verification = await verifyEnvelope(envelope, fileHash);
      if (verification.ok && verification.contentHashOk && verification.contentRole) {
        matches.push({ txId: tx.id, envelope, verification, role: verification.contentRole });
      } else {
        rejected.push({
          txId: tx.id,
          reason: verification.errors[0] ?? "did not bind to these bytes",
        });
      }
    } catch (e) {
      rejected.push({ txId: tx.id, reason: stringifyErr(e) });
    }
  }

  // For each distinct asset the bytes matched, reconstruct its full on-chain
  // history. A failure to build one history is non-fatal — the direct match
  // already establishes the verdict; the timeline is enrichment.
  const histories: AssetHistory[] = [];
  for (const id of assetIdentities(matches)) {
    try {
      histories.push(await buildAssetHistory(gqlChain, dataChain, id, fileHash));
    } catch {
      // leave it out; the match itself still carries the verdict.
    }
  }
  // Most recent activity first across assets.
  histories.sort((a, b) => newestStamp(b) - newestStamp(a));

  return {
    ...base,
    matches,
    histories,
    rejected,
    candidatesTruncated,
    verdict: verdictFromRoles(matches.map((m) => m.role)),
  };
}

interface AssetIdentity {
  tenantId: string;
  agentId: string;
  assetId: string;
}

// Distinct (tenant, agent, asset_id) tuples among the matched envelopes.
function assetIdentities(matches: Match[]): AssetIdentity[] {
  const seen = new Map<string, AssetIdentity>();
  for (const m of matches) {
    const assetId = (m.envelope.payload as { asset?: { asset_id?: unknown } }).asset?.asset_id;
    if (typeof assetId !== "string" || !assetId) continue;
    const id: AssetIdentity = {
      // subject may be absent on a valid envelope from a non-conforming signer
      // — fall back to "unknown" rather than throwing away the whole result (B7).
      tenantId:
        typeof m.envelope.subject?.tenant_id === "string" ? m.envelope.subject.tenant_id : "unknown",
      agentId:
        typeof m.envelope.subject?.agent_id === "string" ? m.envelope.subject.agent_id : "unknown",
      assetId,
    };
    seen.set(`${id.tenantId} ${id.agentId} ${id.assetId}`, id);
  }
  return [...seen.values()];
}

// Fetch + verify every event for one asset and assemble its timeline. Only
// cryptographically-valid events are kept; the user's hash is re-bound against
// each so the timeline can highlight which events are about their exact bytes.
export async function buildAssetHistory(
  graphqlGateways: string[],
  dataGateways: string[],
  id: AssetIdentity,
  fileHash: string,
): Promise<AssetHistory> {
  const refs = await findAssetEventTxs(graphqlGateways, id.tenantId, id.agentId, id.assetId);

  const events: AssetEvent[] = [];
  for (const ref of refs) {
    try {
      const envelope = await fetchEnvelope(dataGateways, ref.id);
      const verification = await verifyEnvelope(envelope, fileHash);
      if (!verification.ok) continue; // never put an unverified event in the timeline
      events.push({
        txId: ref.id,
        envelope,
        verification,
        blockTimestamp: blockOf(ref)?.timestamp ?? null,
        blockHeight: blockOf(ref)?.height ?? null,
        matchedRole: verification.contentHashOk ? verification.contentRole : null,
      });
    } catch {
      // skip unfetchable/unparseable events; absence is noted via continuity.
    }
  }

  // newest-first; tie-break by block height so same-timestamp events (same
  // block, or both unmined) get a deterministic order (B14).
  events.sort((a, b) => eventStamp(b) - eventStamp(a) || (b.blockHeight ?? 0) - (a.blockHeight ?? 0));
  const { continuity, note } = assessContinuity(events);
  return { ...id, events, continuity, note };
}

// Assess how completely the per-type previous_hash chains link up within the
// events we hold. Conservative by construction: an unresolved pointer means
// "earlier events weren't returned," never "tampering." Two chains are checked —
// the asset_registered chain and the combined tamper_detected/asset_missing
// chain (they are siblings on one chain per artifact.md §7).
export function assessContinuity(events: AssetEvent[]): {
  continuity: ChainContinuity;
  note: string;
} {
  if (events.length <= 1) {
    return {
      continuity: "single",
      note:
        events.length === 0
          ? "No events to reconstruct."
          : "A single event for this asset; there is no chain to reconstruct.",
    };
  }

  const registration = events.filter((e) => e.envelope.event_type === "asset_registered");
  const tamperMissing = events.filter(
    (e) => e.envelope.event_type === "tamper_detected" || e.envelope.event_type === "asset_missing",
  );

  const r = chainStatus(registration);
  const t = chainStatus(tamperMissing);
  // "linked" only if every non-trivial chain we have is fully linked.
  const linked = r !== "partial" && t !== "partial";

  return linked
    ? {
        continuity: "linked",
        note: "Full event chain reconstructed — no events are hidden between those shown.",
      }
    : {
        continuity: "partial",
        note:
          "Some events reference earlier records this gateway did not return — they may not be " +
          "indexed yet, or may be on another gateway. This is not evidence of tampering.",
      };
}

// Per-chain status: "linked" if every non-GENESIS previous_hash resolves to
// another event we hold and there is exactly one GENESIS root; "partial"
// otherwise; "single" for 0/1-event chains (trivially fine).
function chainStatus(chain: AssetEvent[]): ChainContinuity {
  if (chain.length <= 1) return "single";
  const byPayloadHash = new Map<string, AssetEvent>();
  for (const e of chain) byPayloadHash.set(e.envelope.payload_hash, e);

  let genesisRoots = 0;
  let unresolved = 0;
  for (const e of chain) {
    const prev = e.envelope.previous_hash;
    if (prev === "GENESIS") genesisRoots++;
    else if (!byPayloadHash.has(prev)) unresolved++;
  }
  if (unresolved > 0 || genesisRoots !== 1) return "partial";
  return "linked";
}

function blockOf(ref: AssetEventTxRef): { height: number; timestamp: number } | null {
  return ref.block ?? null;
}

// Sortable timestamp for an event: trusted block time when mined, else the
// advisory signed_at parsed to epoch ms (÷1000 to compare with block seconds).
function eventStamp(e: AssetEvent): number {
  if (e.blockTimestamp !== null) return e.blockTimestamp;
  const t = Date.parse(e.envelope.signed_at);
  return Number.isNaN(t) ? 0 : Math.floor(t / 1000);
}

function newestStamp(h: AssetHistory): number {
  return h.events.length ? eventStamp(h.events[0]) : 0;
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
