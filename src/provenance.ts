// Orchestration: file -> in-browser hash -> gateway lookup -> fetch -> verify ->
// honest verdict. This is the seam the UI talks to; it performs no rendering.

import { DEFAULT_GATEWAY, fetchEnvelope, findEnvelopeTxs } from "./gateway";
import { sha256OfFile } from "./hash";
import type { ContentRole, Envelope, VerificationResult } from "./types";
import { verifyEnvelope } from "./verifier";

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
  gateway: string;
  verdict: Verdict;
  matches: Match[]; // verified AND content-bound to the user's bytes
  rejected: Rejected[]; // tag-matched candidates that failed verification/bind
  error?: string; // populated when verdict === "error"
}

// Run the full check for a file against one gateway.
export async function checkProvenance(
  file: Blob,
  gateway: string = DEFAULT_GATEWAY,
): Promise<ProvenanceReport> {
  const fileHash = await sha256OfFile(file);
  return checkProvenanceForHash(fileHash, gateway);
}

// Same as checkProvenance but starting from an already-computed hash. Separated
// so callers (and tests) can drive the lookup/verify path without a File.
export async function checkProvenanceForHash(
  fileHash: string,
  gateway: string = DEFAULT_GATEWAY,
): Promise<ProvenanceReport> {
  const base: Omit<ProvenanceReport, "verdict"> = {
    fileHash,
    gateway,
    matches: [],
    rejected: [],
  };

  let txs;
  try {
    txs = await findEnvelopeTxs(gateway, fileHash);
  } catch (e) {
    return { ...base, verdict: "error", error: stringifyErr(e) };
  }

  const matches: Match[] = [];
  const rejected: Rejected[] = [];

  for (const tx of txs) {
    try {
      const envelope = await fetchEnvelope(gateway, tx.id);
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

  return { ...base, matches, rejected, verdict: verdictFor(matches) };
}

function verdictFor(matches: Match[]): Verdict {
  if (matches.length === 0) return "no-match";
  // If the bytes match the *observed* (tampered) side of a tamper event, that is
  // the headline — these are flagged-bad bytes. A baseline/asset match alongside
  // doesn't soften it.
  if (matches.some((m) => m.role === "observed")) return "tampered-bytes";
  return "provenance-found";
}

function stringifyErr(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
