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
  const res = await fetch(`${trimSlash(gateway)}/graphql`, {
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
export async function findEnvelopeTxs(gateway: string, hash: string): Promise<TxRef[]> {
  const lists = await Promise.all(HASH_TAG_NAMES.map((name) => queryByTag(gateway, name, hash)));
  const byId = new Map<string, TxRef>();
  for (const list of lists) {
    for (const tx of list) if (!byId.has(tx.id)) byId.set(tx.id, tx);
  }
  return [...byId.values()];
}

// Fetch the raw envelope bytes for a tx id and parse as JSON. No trust is placed
// in the returned bytes here — verifyEnvelope decides whether they're authentic.
export async function fetchEnvelope(gateway: string, txId: string): Promise<Envelope> {
  const res = await fetch(`${trimSlash(gateway)}/raw/${encodeURIComponent(txId)}`);
  if (!res.ok) throw new Error(`fetch /raw/${txId}: ${res.status} ${res.statusText}`);
  return (await res.json()) as Envelope;
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}
