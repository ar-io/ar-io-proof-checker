// In-browser hashing of the dropped file. The bytes never leave the page — this
// is the whole privacy property of the tool.
//
// Hashing STREAMS: file.stream() chunks feed an incremental WASM SHA-256
// (hash-wasm), so memory stays flat regardless of file size — multi-GB models
// hash fine. There is deliberately no size refusal any more: the old
// MAX_FILE_BYTES guard (B11) was protecting against the arrayBuffer() OOM this
// replaces. We refuse no file on size; we communicate honestly about time.
//
// hash-wasm is NOT a trust-path dependency: a buggy hash can only cause a
// false negative (no match / failed content-bind), never a false-positive
// verdict, and the user can cross-check the displayed hash with sha256sum.
// The streaming output is pinned against WebCrypto's one-shot digest in
// test/hash.streaming.test.ts. See CLAUDE.md for the full rationale.

import { createSHA256 } from "hash-wasm";

// Above this, surface an honest "this will take a while" advisory before
// hashing starts. Soft only — nothing is refused.
export const WARN_FILE_BYTES = 1024 * 1024 * 1024; // 1 GB

export function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i > 0 && n < 10 ? 1 : 0)} ${units[i]}`;
}

export function fileSizeAdvisory(bytes: number): { level: "ok" | "warn"; message: string } {
  if (bytes > WARN_FILE_BYTES) {
    return {
      level: "warn",
      message: `Large file (${formatBytes(
        bytes,
      )}) — this will take a few minutes; your machine is doing the hashing locally, in chunks, and the bytes never leave the page.`,
    };
  }
  return { level: "ok", message: "" };
}

// Reports streaming-hash progress so a long hash looks like work, not a hang.
export type HashProgress = (bytesHashed: number, totalBytes: number) => void;

// SHA-256 of a file's raw bytes, matching what the agent hashes (artifact.md
// §4.5: "Hash is over raw bytes, not metadata"). No normalization, no encoding
// transforms — raw bytes only, or the hash won't match the on-chain record.
//
// Never materializes the file: chunks from file.stream() are hashed and
// dropped. WebCrypto isn't used here because crypto.subtle.digest is one-shot
// (no streaming update API).
export async function sha256OfFile(file: Blob, onProgress?: HashProgress): Promise<string> {
  const hasher = await createSHA256();
  hasher.init();
  const reader = file.stream().getReader();
  let hashed = 0;
  // When the file streams from cache, reader.read() resolves as a microtask
  // and this loop never yields a macrotask — the browser can't repaint and
  // the progress UI freezes for the entire hash (observed: a 2.5 GB hash
  // rendered nothing for 30+ s). Yield one macrotask periodically so paint
  // (and input) get a turn; the cost over multi-GB inputs is negligible.
  let lastYield = Date.now();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      hasher.update(value);
      hashed += value.byteLength;
      onProgress?.(hashed, file.size);
      if (Date.now() - lastYield > 50) {
        await new Promise((r) => setTimeout(r, 0));
        lastYield = Date.now();
      }
    }
  } finally {
    reader.releaseLock();
  }
  return hasher.digest("hex");
}
