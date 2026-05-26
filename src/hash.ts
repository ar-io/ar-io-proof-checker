// In-browser hashing of the dropped file. The bytes never leave the page — this
// is the whole privacy property of the tool.

import { bytesToHex } from "./crypto";

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
