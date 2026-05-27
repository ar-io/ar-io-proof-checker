// Gateway access: the only outbound traffic the tool generates. Two operations,
// both gateway-agnostic and both followed by client-side verification, so a
// hostile or buggy gateway can at worst deny or mislead — never forge a verdict.
//
//   1. GraphQL lookup of candidate transactions by content-hash tag.
//   2. Raw fetch of an envelope's bytes by tx id.
//
// v1 targets the ar.io gateway (turbo-gateway.com — the same default ariod
// verify uses). Multi-gateway fallback is Phase 4 (proof-checker.md §6, §14 #5).

import type { Envelope } from "./types";

export const DEFAULT_GATEWAY = "https://turbo-gateway.com";

// Per-request ceiling so a hung/slow gateway can't leave the UI spinning
// forever — without this a stalled fetch never settles.
export const FETCH_TIMEOUT_MS = 20_000;

// Validate + normalize a user-entered gateway. Accepts a bare host
// ("turbo-gateway.com") by assuming https, rejects non-http(s) schemes (so a
// pasted javascript:/data: URL can't flow into fetch or a link href), and
// strips trailing slashes. Throws on anything unparseable.
export function normalizeGateway(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return DEFAULT_GATEWAY;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw new Error(`invalid gateway URL: ${input}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`gateway must be http(s), got ${url.protocol}`);
  }
  return trimSlash(candidate);
}

async function fetchWithTimeout(
  url: string,
  init?: RequestInit,
  ms: number = FETCH_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (e) {
    if (controller.signal.aborted) throw new Error(`gateway request timed out after ${ms}ms`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

// The content-hash tags the agent writes (ar-io-agent artifact.md §11). A file's
// hash can appear as the registered/missing baseline (Asset-Hash), the tampered
// bytes that were flagged (Observed-Hash), or the known-good bytes a tamper
// diverged from (Baseline-Hash). Arweave GraphQL ANDs across tag names, so we
// query each name separately and union the results.
export const HASH_TAG_NAMES = ["Asset-Hash", "Observed-Hash", "Baseline-Hash"] as const;

export interface TxRef {
  id: string;
  tags: { name: string; value: string }[];
}

const GRAPHQL_QUERY = `query ($name: String!, $hash: String!) {
  transactions(
    tags: [
      { name: "App-Name", values: ["ario-agent"] }
      { name: $name, values: [$hash] }
    ]
    first: 100
    sort: HEIGHT_DESC
  ) {
    edges { node { id tags { name value } } }
  }
}`;

interface GraphQLResponse {
  data?: { transactions?: { edges?: { node?: TxRef }[] } };
  errors?: { message?: string }[];
}

async function queryByTag(gateway: string, tagName: string, hash: string): Promise<TxRef[]> {
  const res = await fetchWithTimeout(`${trimSlash(gateway)}/graphql`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ query: GRAPHQL_QUERY, variables: { name: tagName, hash } }),
  });
  if (!res.ok) throw new Error(`gateway GraphQL ${res.status} ${res.statusText}`);
  const body = (await res.json()) as GraphQLResponse;
  if (body.errors?.length) {
    throw new Error(`gateway GraphQL error: ${body.errors.map((e) => e.message).join("; ")}`);
  }
  const edges = body.data?.transactions?.edges ?? [];
  return edges.map((e) => e.node).filter((n): n is TxRef => !!n?.id);
}

// Find candidate envelope transactions whose content-hash tags reference `hash`.
// Unions across the three hash tags and dedupes by tx id. The tags are unsigned
// search hints — every returned tx must still be fetched and verified.
//
// Resilient by design: a transient failure of ONE of the three tag queries must
// not sink the whole lookup, so we use allSettled and only error if EVERY query
// failed (an honest "we couldn't reach the gateway").
export async function findEnvelopeTxs(gateway: string, hash: string): Promise<TxRef[]> {
  const settled = await Promise.allSettled(
    HASH_TAG_NAMES.map((name) => queryByTag(gateway, name, hash)),
  );
  const byId = new Map<string, TxRef>();
  let anyFulfilled = false;
  let lastError: unknown;
  for (const result of settled) {
    if (result.status === "fulfilled") {
      anyFulfilled = true;
      for (const tx of result.value) if (!byId.has(tx.id)) byId.set(tx.id, tx);
    } else {
      lastError = result.reason;
    }
  }
  if (!anyFulfilled) {
    throw lastError instanceof Error ? lastError : new Error("all gateway queries failed");
  }
  return [...byId.values()];
}

export interface AssetEventTxRef extends TxRef {
  // block is null while the tx is unmined; timestamp is unix seconds.
  block: { height: number; timestamp: number } | null;
}

const ASSET_EVENTS_QUERY = `query ($tenant: String!, $agent: String!, $asset: String!) {
  transactions(
    tags: [
      { name: "App-Name", values: ["ario-agent"] }
      { name: "Tenant-Id", values: [$tenant] }
      { name: "Agent-Id", values: [$agent] }
      { name: "Asset-Id", values: [$asset] }
    ]
    first: 100
    sort: HEIGHT_DESC
  ) {
    edges { node { id tags { name value } block { height timestamp } } }
  }
}`;

interface AssetEventsResponse {
  data?: { transactions?: { edges?: { node?: AssetEventTxRef }[] } };
  errors?: { message?: string }[];
}

// Every event anchored for a given asset under one (tenant, agent): the
// asset_registered chain plus the tamper_detected / asset_missing chain (all
// carry the Asset-Id tag). verification_checkpoint events are per-agent and
// carry no Asset-Id, so routine "verified" runs — which live as Merkle leaves
// inside checkpoints — are not returned here by design.
export async function findAssetEventTxs(
  gateway: string,
  tenantId: string,
  agentId: string,
  assetId: string,
): Promise<AssetEventTxRef[]> {
  const res = await fetchWithTimeout(`${trimSlash(gateway)}/graphql`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      query: ASSET_EVENTS_QUERY,
      variables: { tenant: tenantId, agent: agentId, asset: assetId },
    }),
  });
  if (!res.ok) throw new Error(`gateway GraphQL ${res.status} ${res.statusText}`);
  const body = (await res.json()) as AssetEventsResponse;
  if (body.errors?.length) {
    throw new Error(`gateway GraphQL error: ${body.errors.map((e) => e.message).join("; ")}`);
  }
  const edges = body.data?.transactions?.edges ?? [];
  return edges.map((e) => e.node).filter((n): n is AssetEventTxRef => !!n?.id);
}

// Fetch the raw envelope bytes for a tx id and parse as JSON. No trust is placed
// in the returned bytes here — verifyEnvelope decides whether they're authentic.
export async function fetchEnvelope(gateway: string, txId: string): Promise<Envelope> {
  const res = await fetchWithTimeout(`${trimSlash(gateway)}/raw/${encodeURIComponent(txId)}`);
  if (!res.ok) throw new Error(`fetch /raw/${txId}: ${res.status} ${res.statusText}`);
  return (await res.json()) as Envelope;
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}
