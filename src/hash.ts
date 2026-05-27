// In-browser hashing of the dropped file. The bytes never leave the page — this
// is the whole privacy property of the tool.

import { bytesToHex } from "./crypto";

// Hashing reads the whole file into memory (arrayBuffer). Warn before it gets
// slow, and refuse past the point where the browser will likely fail to
// allocate — rather than hanging or crashing the tab (B11). Streaming for huge
// files is a future step (proof-checker.md §5).
export const WARN_FILE_BYTES = 500 * 1024 * 1024; // 500 MB
export const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GB

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

export function fileSizeAdvisory(bytes: number): { level: "ok" | "warn" | "refuse"; message: string } {
  if (bytes > MAX_FILE_BYTES) {
    return {
      level: "refuse",
      message: `This file is ${formatBytes(bytes)}. Files over ${formatBytes(
        MAX_FILE_BYTES,
      )} can't be hashed in the browser yet (in-browser hashing loads the whole file into memory; streaming is a future step). For very large artifacts, verify with the ariod CLI instead.`,
    };
  }
  if (bytes > WARN_FILE_BYTES) {
    return {
      level: "warn",
      message: `Large file (${formatBytes(bytes)}) — hashing runs in your browser and may take a while and use significant memory.`,
    };
  }
  return { level: "ok", message: "" };
}

// SHA-256 of a file's raw bytes, matching what the agent hashes (artifact.md
// §4.5: "Hash is over raw bytes, not metadata"). No normalization, no encoding
// transforms — raw bytes only, or the hash won't match the on-chain record.
//
// Phase 2 reads the whole file into memory via arrayBuffer(). For multi-GB
// models this should stream (File.stream() + an incremental WASM SHA-256) to
// keep memory flat — that's Phase 4 hardening (proof-checker.md §5).
export async function sha256OfFile(file: Blob): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return bytesToHex(new Uint8Array(digest));
}
