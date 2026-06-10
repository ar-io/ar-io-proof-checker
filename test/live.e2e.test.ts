// LIVE end-to-end tests — hit real ar.io gateways and real on-chain data.
// Opt-in only (network-dependent, so never part of `npm test` / CI):
//
//   ARIO_LIVE_E2E=1 npx vitest run test/live.e2e.test.ts
//
// Uses the samples/ fixtures, which are anchored on Arweave (see
// samples/README.md). Mirrors ar-io-agent's `make anchor-live` discipline:
// the hermetic suite proves the logic, this proves the world still matches.

import { execFileSync } from "node:child_process";
import { mkdtempSync, openAsBlob, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

import { DEFAULT_GATEWAYS, fetchRegistryPeers } from "../src/gateway";
import { sha256OfFile } from "../src/hash";
import { checkProvenance, checkProvenanceForHash } from "../src/provenance";
import { buildReport, verifyReport } from "../src/report";

const LIVE = !!process.env.ARIO_LIVE_E2E;
const NET_TIMEOUT = 120_000;

function sample(name: string): Blob {
  const p = fileURLToPath(new URL(`../samples/${name}`, import.meta.url));
  return new Blob([readFileSync(p) as unknown as BlobPart]);
}

describe.skipIf(!LIVE)("live: verdicts against real on-chain data", () => {
  it(
    "sample-verifiable.txt → provenance-found, and the report round-trips",
    async () => {
      const report = await checkProvenance(sample("sample-verifiable.txt"), DEFAULT_GATEWAYS);
      expect(report.verdict).toBe("provenance-found");
      expect(report.matches.length).toBeGreaterThan(0);
      expect(DEFAULT_GATEWAYS).toContain(report.gateway);

      const exported = buildReport(report);
      const v = await verifyReport(exported);
      expect(v.ok).toBe(true);
      expect(v.recomputedVerdict).toBe("provenance-found");
    },
    NET_TIMEOUT,
  );

  it(
    "sample-demo-tampered.txt → tampered-bytes",
    async () => {
      const report = await checkProvenance(sample("sample-demo-tampered.txt"), DEFAULT_GATEWAYS);
      expect(report.verdict).toBe("tampered-bytes");
    },
    NET_TIMEOUT,
  );

  it(
    "sample-no-provenance.txt → no-match (absence, honestly)",
    async () => {
      const report = await checkProvenance(sample("sample-no-provenance.txt"), DEFAULT_GATEWAYS);
      expect(report.verdict).toBe("no-match");
      expect(report.matches).toHaveLength(0);
    },
    NET_TIMEOUT,
  );

  it(
    "a dead first gateway falls through to a live anchor",
    async () => {
      const report = await checkProvenance(sample("sample-verifiable.txt"), [
        "https://gw-that-does-not-exist.invalid",
        ...DEFAULT_GATEWAYS,
      ]);
      expect(report.verdict).toBe("provenance-found");
      expect(DEFAULT_GATEWAYS).toContain(report.gateway);
    },
    NET_TIMEOUT,
  );
});

describe.skipIf(!LIVE)("live: registry discovery", () => {
  it(
    "GET /ar-io/peers on the anchors yields normalized https peers",
    async () => {
      const peers = await fetchRegistryPeers(DEFAULT_GATEWAYS);
      expect(peers.length).toBeGreaterThan(0);
      for (const p of peers) {
        expect(p).toMatch(/^https:\/\//);
        expect(DEFAULT_GATEWAYS).not.toContain(p);
      }
    },
    NET_TIMEOUT,
  );

  it(
    "rescues an all-dead configured chain via registry peers (error → verdict)",
    async () => {
      const fileHash = await sha256OfFile(sample("sample-verifiable.txt"));
      const report = await checkProvenanceForHash(
        fileHash,
        ["https://gw-that-does-not-exist.invalid"],
        // Discover real peers from the anchors — exactly what the app does,
        // just with a deliberately dead configured chain.
        { registryPeers: () => fetchRegistryPeers(DEFAULT_GATEWAYS) },
      );
      expect(report.registryPeersUsed?.length).toBeGreaterThan(0);
      // Random registry peers may or may not have tag-indexed this tx; the
      // guarantee is graceful degradation, not coverage: never a crash, and
      // an honest verdict either way.
      expect(["provenance-found", "no-match", "error"]).toContain(report.verdict);
    },
    NET_TIMEOUT,
  );
});

describe.skipIf(!LIVE)("live: multi-GB streaming hash", () => {
  const dir = mkdtempSync(join(tmpdir(), "ario-live-hash-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it(
    "hashes a sparse 3 GiB file with flat memory and agrees with sha256sum",
    async () => {
      const path = join(dir, "big.bin");
      // Sparse: reads as 3 GiB of zeros without occupying disk.
      execFileSync("truncate", ["-s", "3G", path]);
      const expected = execFileSync("sha256sum", [path], { encoding: "utf8" }).slice(0, 64);

      const before = process.memoryUsage().rss;
      let lastDone = 0;
      const got = await sha256OfFile(await openAsBlob(path), (done) => {
        lastDone = done;
      });
      const growth = process.memoryUsage().rss - before;

      expect(got).toBe(expected);
      expect(lastDone).toBe(3 * 1024 * 1024 * 1024);
      // The whole point: nowhere near 3 GiB materialized. Allow generous
      // headroom for chunk buffers + WASM heap.
      expect(growth).toBeLessThan(512 * 1024 * 1024);
    },
    600_000,
  );
});
