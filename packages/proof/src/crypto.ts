// Low-level cryptographic primitives for the verifier. Deliberately thin: the
// only third-party crypto dependency is @noble/ed25519 (single-file, audited,
// zero-dependency). SHA-256 and SHA-512 come from WebCrypto — no extra hashing
// library to trust.

import * as ed from "@noble/ed25519";

// @noble/ed25519 needs SHA-512 to verify. Wire it to WebCrypto rather than
// pulling in @noble/hashes. globalThis.crypto.subtle exists in every modern
// browser and in Node >= 19, so the same code path runs in the app and in tests.
ed.etc.sha512Async = async (...msgs: Uint8Array[]): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-512", asBufferSource(ed.etc.concatBytes(...msgs))));

// WebCrypto's digest() wants a BufferSource backed by a (non-shared) ArrayBuffer.
// Our byte arrays always are; this keeps TS 5.7's stricter Uint8Array<ArrayBufferLike>
// typing satisfied without a runtime copy.
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hexToBytes: odd-length string");
  // Full validation: parseInt() partially parses ("1g" -> 1), which would let
  // malformed hex through. A strict charset check closes that.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("hexToBytes: non-hex characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function sha256Bytes(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(bytes)));
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256Bytes(bytes));
}

// Verify an Ed25519 signature. Inputs are hex (signature, public key) as they
// appear in the envelope; message is raw bytes. Never throws — a malformed
// signature or key is "not verified," not an exception, so a hostile envelope
// can't crash the checker.
export async function ed25519Verify(
  signatureHex: string,
  message: Uint8Array,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    // zip215:false → strict RFC-8032 verification, matching the Go agent's
    // crypto/ed25519 exactly (noble defaults to the more lenient zip215:true).
    return await ed.verifyAsync(hexToBytes(signatureHex), message, hexToBytes(publicKeyHex), {
      zip215: false,
    });
  } catch {
    return false;
  }
}
