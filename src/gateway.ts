// Gateway access: the only outbound traffic the tool generates. Two operations,
// both gateway-agnostic and both followed by client-side verification, so a
// hostile or buggy gateway can at worst deny or mislead — never forge a verdict.
//
//   1. GraphQL lookup of candidate transactions by content-hash tag.
//   2. Raw fetch of an envelope's bytes by tx id.
//
// Phase 4: every operation takes an ordered gateway LIST and falls through on
// failure (network / 5xx / timeout) — and, for discovery, on an empty result
// too, so "no match" means "none of the configured gateways know these bytes"
// rather than "the first reachable gateway hadn't indexed them yet". Mirrors
// the fallback discipline of `ariod verify --gateway a,b,c`. Which gateway
// served is surfaced so the UI can attribute the result; all gateways remain
// untrusted — verification re-runs on every envelope regardless of source.

import type { Envelope } from "./types";

// Static anchors per proof-checker.md §14 #5: the ar.io gateway plus
// arweave.net, user-overridable. Both are interchangeable untrusted delivery
// surfaces (auditor-recipe.md). The full default chain prepends the gateway
// SERVING the app (see defaultGatewayChain) and can lazily extend itself from
// the ar.io registry (see fetchRegistryPeers) — but these anchors are always
// queried before any registry-discovered peer, so a poisoned peer list can
// never preempt them.
export const DEFAULT_GATEWAYS = ["https://turbo-gateway.com", "https://arweave.net"];

// How many registry-discovered peers may extend the fallback chain.
export const REGISTRY_PEER_LIMIT = 4;

// Per-request ceiling so a hung/slow gateway can't leave the UI spinning
// forever — without this a stalled fetch never settles. Per attempt, so the
// worst case grows with the gateway list; lists are short (2–3 entries).
export const FETCH_TIMEOUT_MS = 20_000;

// Validate + normalize ONE user-entered gateway. Accepts a bare host
// ("turbo-gateway.com") by assuming https, rejects non-http(s) schemes (so a
// pasted javascript:/data: URL can't flow into fetch or a link href), and
// strips trailing slashes. Throws on anything unparseable or empty.
export function normalizeGateway(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("empty gateway URL");
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

// Parse a comma-separated gateway list into an ordered, deduped array of
// normalized URLs. Empty/whitespace input falls back to the defaults; any
// invalid entry throws (a typo should be surfaced, not silently dropped from
// the fallback order).
export function normalizeGateways(input: string): string[] {
  const out: string[] = [];
  for (const part of input.split(",")) {
    if (!part.trim()) continue;
    const gw = normalizeGateway(part);
    if (!out.includes(gw)) out.push(gw);
  }
  return out.length > 0 ? out : [...DEFAULT_GATEWAYS];
}

// When the app is served through an ar.io gateway (ArNS:
// proof-checker.<gateway-host>, or an Arweave sandbox subdomain), the parent
// of the hostname IS a gateway — one that is provably up and CORS-reachable,
// because it just delivered this page. Deriving it costs zero requests.
// Returns null when there is no parent to derive (apex domains, localhost,
// IP literals); a wrong guess is harmless — it just falls through.
export function servingGatewayCandidate(hostname: string): string | null {
  if (!hostname || hostname.includes(":") || /^[0-9.]+$/.test(hostname)) return null;
  const labels = hostname.split(".");
  if (labels.length < 3 || labels.some((l) => !l)) return null;
  try {
    return normalizeGateway(labels.slice(1).join("."));
  } catch {
    return null;
  }
}

// The auto-assembled default chain: serving gateway (when derivable) first,
// then the static anchors, deduped, order-preserving.
export function defaultGatewayChain(hostname?: string): string[] {
  const chain: string[] = [];
  const serving = hostname ? servingGatewayCandidate(hostname) : null;
  if (serving) chain.push(serving);
  for (const gw of DEFAULT_GATEWAYS) if (!chain.includes(gw)) chain.push(gw);
  return chain;
}

interface PeersResponse {
  gateways?: Record<string, { url?: unknown; dataWeight?: unknown }>;
}

// Registry-driven discovery: ar.io gateways expose the peer gateways they
// know at GET /ar-io/peers (plain HTTP, CORS-open — no AO process, no SDK).
// Asks each chain gateway in order and returns up to `limit` peers from the
// first list that yields any USABLE peer (https-only, normalized, deduped
// against the chain itself), best dataWeight first; a served-but-useless list
// falls through to the next gateway. The result is a HINT for fallback depth,
// never trust: every envelope from a discovered peer is verified exactly like
// one from a configured gateway, and discovered peers are only ever appended
// AFTER the configured chain. Returns [] when no gateway yields a peer.
export async function fetchRegistryPeers(
  chain: string[],
  limit: number = REGISTRY_PEER_LIMIT,
): Promise<string[]> {
  for (const gw of chain) {
    let body: PeersResponse;
    try {
      const res = await fetchWithTimeout(`${trimSlash(gw)}/ar-io/peers`);
      if (!res.ok) continue;
      body = (await res.json()) as PeersResponse;
    } catch {
      continue;
    }
    const entries = Object.values(body.gateways ?? {})
      .filter((p): p is { url: string; dataWeight?: number } =>
        typeof p?.url === "string" && p.url.startsWith("https://"),
      )
      .sort((a, b) => (Number(b.dataWeight) || 0) - (Number(a.dataWeight) || 0));
    const out: string[] = [];
    for (const p of entries) {
      let norm: string;
      try {
        norm = normalizeGateway(p.url);
      } catch {
        continue;
      }
      if (!chain.includes(norm) && !out.includes(norm)) out.push(norm);
      if (out.length >= limit) break;
    }
    if (out.length > 0) return out;
  }
  return [];
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

// One gateway's view of the candidates for a hash: union of the three tag
// queries, deduped by tx id. The tags are unsigned search hints — every
// returned tx must still be fetched and verified.
//
// Resilient by design (B12): a transient failure of ONE of the three tag
// queries must not sink this gateway's lookup, so we use allSettled and only
// throw if EVERY query failed (an honest "we couldn't reach this gateway").
async function findEnvelopeTxsOn(gateway: string, hash: string): Promise<TxRef[]> {
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

// A discovery result attributed to the gateway whose view produced it. When
// every gateway was reachable but none knew the hash, `gateway` is the first
// reachable one (the result is equally "from" any of them: nothing).
export interface Discovery {
  txs: TxRef[];
  gateway: string;
}

// Find candidate envelope transactions whose content-hash tags reference
// `hash`, trying each gateway in order. Falls through on failure AND on an
// empty result — first non-empty view wins, and views are kept atomic (no
// cross-gateway union; verification re-runs per envelope either way, so the
// trust model is unchanged). Throws only when every gateway was unreachable.
export async function findEnvelopeTxs(gateways: string[], hash: string): Promise<Discovery> {
  let firstReachable: string | null = null;
  let lastError: unknown;
  for (const gw of gateways) {
    try {
      const txs = await findEnvelopeTxsOn(gw, hash);
      if (txs.length > 0) return { txs, gateway: gw };
      firstReachable ??= gw;
    } catch (e) {
      lastError = e;
    }
  }
  if (firstReachable !== null) return { txs: [], gateway: firstReachable };
  throw lastError instanceof Error ? lastError : new Error("all gateways failed");
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

async function findAssetEventTxsOn(
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

// Every event anchored for a given asset under one (tenant, agent): the
// asset_registered chain plus the tamper_detected / asset_missing chain (all
// carry the Asset-Id tag). verification_checkpoint events are per-agent and
// carry no Asset-Id, so routine "verified" runs — which live as Merkle leaves
// inside checkpoints — are not returned here by design.
//
// Same fallback semantics as findEnvelopeTxs: failure or an empty result falls
// through to the next gateway; first non-empty view wins.
export async function findAssetEventTxs(
  gateways: string[],
  tenantId: string,
  agentId: string,
  assetId: string,
): Promise<AssetEventTxRef[]> {
  let anyReachable = false;
  let lastError: unknown;
  for (const gw of gateways) {
    try {
      const refs = await findAssetEventTxsOn(gw, tenantId, agentId, assetId);
      if (refs.length > 0) return refs;
      anyReachable = true;
    } catch (e) {
      lastError = e;
    }
  }
  if (anyReachable) return [];
  throw lastError instanceof Error ? lastError : new Error("all gateways failed");
}

// Fetch the raw envelope bytes for a tx id, trying each gateway in order. Any
// per-gateway failure falls through: a 404 means "not propagated to that
// gateway yet — or doesn't exist there" (exactly the case multi-gateway helps
// with), and 5xx/network/timeout are ordinary transient failures. No trust is
// placed in the returned bytes here — verifyEnvelope decides authenticity.
export async function fetchEnvelope(gateways: string[], txId: string): Promise<Envelope> {
  let lastError: unknown;
  for (const gw of gateways) {
    try {
      const res = await fetchWithTimeout(`${trimSlash(gw)}/raw/${encodeURIComponent(txId)}`);
      if (!res.ok) throw new Error(`fetch /raw/${txId}: ${res.status} ${res.statusText}`);
      return (await res.json()) as Envelope;
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(`fetch /raw/${txId}: all gateways failed`);
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}
