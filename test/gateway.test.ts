import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_GATEWAYS,
  fetchEnvelope,
  findEnvelopeTxs,
  normalizeGateway,
  normalizeGateways,
} from "../src/gateway";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("normalizeGateway (B10)", () => {
  it("assumes https for a bare host", () => {
    expect(normalizeGateway("turbo-gateway.com")).toBe("https://turbo-gateway.com");
  });
  it("preserves an explicit scheme and strips trailing slashes", () => {
    expect(normalizeGateway("https://gw.example/")).toBe("https://gw.example");
    expect(normalizeGateway("http://localhost:1984//")).toBe("http://localhost:1984");
  });
  it("rejects non-http(s) schemes (no javascript:/data: into fetch or href)", () => {
    expect(() => normalizeGateway("javascript:alert(1)")).toThrow();
    expect(() => normalizeGateway("data:text/html,x")).toThrow();
    expect(() => normalizeGateway("ftp://x")).toThrow(/http/);
  });
});

describe("normalizeGateways (multi-gateway)", () => {
  it("parses a comma-separated list in order, normalizing each entry", () => {
    expect(normalizeGateways("gw1.example, https://gw2.example/ ,gw3.example")).toEqual([
      "https://gw1.example",
      "https://gw2.example",
      "https://gw3.example",
    ]);
  });
  it("dedupes repeated entries, keeping first position", () => {
    expect(normalizeGateways("gw.example, https://gw.example/")).toEqual(["https://gw.example"]);
  });
  it("ignores empty segments from stray commas", () => {
    expect(normalizeGateways(",gw.example,,")).toEqual(["https://gw.example"]);
  });
  it("falls back to the defaults when empty/whitespace", () => {
    expect(normalizeGateways("   ")).toEqual(DEFAULT_GATEWAYS);
  });
  it("throws on any invalid entry rather than silently dropping it", () => {
    expect(() => normalizeGateways("gw.example, javascript:alert(1)")).toThrow();
  });
});

describe("fetchEnvelope", () => {
  it("aborts and throws a timeout error when the gateway never responds (B3)", async () => {
    vi.useFakeTimers();
    // A fetch that only rejects when its AbortSignal fires.
    vi.stubGlobal("fetch", (_url: string, init?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      });
    });
    const p = fetchEnvelope(["https://gw.example"], "TX");
    const assertion = expect(p).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(21_000);
    await assertion;
  });

  it("falls through to the next gateway on 404 (propagation lag)", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      if (url.startsWith("https://gw1.example")) {
        return new Response("not found", { status: 404, statusText: "Not Found" });
      }
      return Response.json({ event_type: "asset_registered" });
    });
    const env = await fetchEnvelope(["https://gw1.example", "https://gw2.example"], "TX");
    expect(env.event_type).toBe("asset_registered");
    expect(urls).toEqual(["https://gw1.example/raw/TX", "https://gw2.example/raw/TX"]);
  });

  it("falls through on a network error and reports the last error when all fail", async () => {
    vi.stubGlobal("fetch", async (url: string) => {
      if (url.startsWith("https://gw1.example")) throw new TypeError("network down");
      return new Response("boom", { status: 502, statusText: "Bad Gateway" });
    });
    await expect(fetchEnvelope(["https://gw1.example", "https://gw2.example"], "TX")).rejects.toThrow(
      /502/,
    );
  });
});

// Routes stubbed responses by gateway host and hash-tag name.
function stubTagFetch(
  behavior: (gateway: string, tagName: string) => Response | Promise<Response>,
): void {
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? init.body : "";
    const tagName = /"name":"(Asset-Hash|Observed-Hash|Baseline-Hash)"/.exec(body)?.[1] ?? "";
    const gateway = new URL(url).origin;
    return behavior(gateway, tagName);
  });
}

function edges(...ids: string[]): Response {
  return Response.json({
    data: { transactions: { edges: ids.map((id) => ({ node: { id, tags: [] } })) } },
  });
}

const HASH = "a".repeat(64);

describe("findEnvelopeTxs multi-gateway fallback", () => {
  it("first gateway 5xx → second gateway's view wins, attributed to it", async () => {
    stubTagFetch((gw) => {
      if (gw === "https://gw1.example") {
        return new Response("boom", { status: 502, statusText: "Bad Gateway" });
      }
      return edges("TX1");
    });
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX1"]);
    expect(d.gateway).toBe("https://gw2.example");
  });

  it("first gateway reachable-but-empty → falls through; first non-empty view wins", async () => {
    stubTagFetch((gw) => (gw === "https://gw1.example" ? edges() : edges("TX2")));
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX2"]);
    expect(d.gateway).toBe("https://gw2.example");
  });

  it("all gateways reachable-but-empty → honest empty result, no error", async () => {
    stubTagFetch(() => edges());
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs).toEqual([]);
    expect(d.gateway).toBe("https://gw1.example");
  });

  it("every gateway fails → throws (error verdict upstream)", async () => {
    stubTagFetch(() => new Response("boom", { status: 502, statusText: "Bad Gateway" }));
    await expect(
      findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH),
    ).rejects.toThrow();
  });

  it("keeps per-gateway tag-query resilience: one tag 200, others 502 still serves (B12)", async () => {
    stubTagFetch((_gw, tag) => {
      if (tag === "Asset-Hash") return edges("TX1");
      return new Response("boom", { status: 502, statusText: "Bad Gateway" });
    });
    const d = await findEnvelopeTxs(["https://gw1.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX1"]);
    expect(d.gateway).toBe("https://gw1.example");
  });

  it("does not union across gateways — the serving gateway's view is atomic", async () => {
    stubTagFetch((gw) => (gw === "https://gw1.example" ? edges("TX1") : edges("TX1", "TX2")));
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX1"]);
    expect(d.gateway).toBe("https://gw1.example");
  });
});
