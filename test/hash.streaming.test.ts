// Streaming-hash tests. The load-bearing one is the cross-check: the
// hash-wasm streaming path must agree with WebCrypto's one-shot digest on the
// same bytes for every size we try (including chunk-boundary sizes). A
// disagreement here is a real correctness issue — escalate, don't paper over.

import { describe, expect, it } from "vitest";

import { WARN_FILE_BYTES, fileSizeAdvisory, sha256OfFile } from "../src/hash";

async function webCryptoSha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function deterministicBytes(n: number): Uint8Array {
  // Deterministic, non-trivial content — no RNG so a failure reproduces.
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + (i >> 8)) & 0xff;
  return out;
}

describe("sha256OfFile (streaming) cross-check against WebCrypto", () => {
  // 0/1, the SHA-256 block boundary (64), and a multi-chunk size.
  for (const size of [0, 1, 63, 64, 65, 1024, 5 * 1024 * 1024 + 17]) {
    it(`matches WebCrypto for ${size} bytes`, async () => {
      const bytes = deterministicBytes(size);
      const streamed = await sha256OfFile(new Blob([bytes as BlobPart]));
      expect(streamed).toBe(await webCryptoSha256(bytes));
    });
  }

  it("hashes the empty file to the canonical SHA-256 empty digest", async () => {
    expect(await sha256OfFile(new Blob([]))).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

describe("sha256OfFile streams (memory smoke)", () => {
  // A Blob stand-in whose whole-file accessors fail the test if touched: the
  // streaming path must consume chunks only. CI can't hash a 50 GB file, but
  // it CAN prove the implementation never materializes the input.
  function streamOnlyBlob(chunks: Uint8Array[]): Blob {
    const size = chunks.reduce((n, c) => n + c.byteLength, 0);
    const pending = [...chunks];
    const fail = (method: string) => {
      throw new Error(`${method}() called — streaming path must not materialize the file`);
    };
    return {
      size,
      arrayBuffer: () => fail("arrayBuffer"),
      bytes: () => fail("bytes"),
      text: () => fail("text"),
      stream: () =>
        new ReadableStream({
          pull(controller) {
            const next = pending.shift();
            if (next) controller.enqueue(next);
            else controller.close();
          },
        }),
    } as unknown as Blob;
  }

  it("hashes a many-chunk blob without ever materializing it", async () => {
    // 8 MB in 64 lazily-yielded 128 KB chunks.
    const chunk = deterministicBytes(128 * 1024);
    const chunks = Array.from({ length: 64 }, () => chunk);
    const whole = new Uint8Array(chunk.length * 64);
    chunks.forEach((c, i) => whole.set(c, i * c.length));

    const streamed = await sha256OfFile(streamOnlyBlob(chunks));
    expect(streamed).toBe(await webCryptoSha256(whole));
  });

  it("reports monotonic progress ending at (total, total)", async () => {
    const bytes = deterministicBytes(256 * 1024);
    const calls: [number, number][] = [];
    await sha256OfFile(new Blob([bytes as BlobPart]), (done, total) => calls.push([done, total]));
    expect(calls.length).toBeGreaterThan(0);
    for (let i = 1; i < calls.length; i++) expect(calls[i][0]).toBeGreaterThan(calls[i - 1][0]);
    expect(calls[calls.length - 1][0]).toBe(bytes.length);
    expect(calls.every(([, total]) => total === bytes.length)).toBe(true);
  });
});

describe("fileSizeAdvisory is advisory-only (B11 superseded)", () => {
  it("never refuses on size — there is no refuse level any more", () => {
    // 50 GB: far past the old 2 GB cap; streaming handles it, copy sets
    // expectations instead of refusing.
    const a = fileSizeAdvisory(50 * 1024 * 1024 * 1024);
    expect(a.level).toBe("warn");
    expect(a.message).toMatch(/take a few minutes/);
    expect(a.message).toMatch(/never leave the page/);
  });

  it("stays quiet below the warn threshold", () => {
    expect(fileSizeAdvisory(WARN_FILE_BYTES - 1).level).toBe("ok");
  });
});
