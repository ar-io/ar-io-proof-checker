// RFC 9162 binary Merkle tree — build, audit paths, inclusion verification.
//
// A faithful port of the Go reference (ar-io-agent pkg/merkle), in lockstep
// with the Python kernel's ario_proof.merkle. All hashing is SHA-256 with
// RFC 9162 §2.1 domain separation: leaves prefixed 0x00, interior nodes 0x01.
// A tree of n leaves splits into a left subtree of k leaves (the largest
// power of two < n) and a right subtree of n−k — NOT the Bitcoin
// duplicate-last-leaf variant, which produces different roots for
// non-power-of-two leaf counts.
//
// The empty tree (zero leaves) hashes to SHA-256("") — EMPTY_TREE_ROOT_HEX.
// Conformance is byte-for-byte against the 7 merkle-tree-* vectors of
// test-vectors-v1.0 (test/conformance.test.ts).

import { sha256Bytes } from "./crypto";

export const EMPTY_TREE_ROOT_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// SHA-256(0x00 || leafBytes) per RFC 9162 §2.1.
export async function leafHash(leafBytes: Uint8Array): Promise<Uint8Array> {
  return sha256Bytes(prefixed(0x00, leafBytes));
}

// SHA-256(0x01 || left || right) per RFC 9162 §2.1.
export async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = 0x01;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha256Bytes(buf);
}

// The RFC 9162 Merkle Tree Hash of already-hashed leaves. Callers pass leaf
// hashes — the output of leafHash on each leaf's canonical bytes. Zero leaves
// yields SHA-256("").
export async function merkleRoot(leafHashes: Uint8Array[]): Promise<Uint8Array> {
  const n = leafHashes.length;
  if (n === 0) return sha256Bytes(new Uint8Array(0));
  if (n === 1) return leafHashes[0];
  const k = largestPow2LessThan(n);
  return nodeHash(await merkleRoot(leafHashes.slice(0, k)), await merkleRoot(leafHashes.slice(k)));
}

// The inclusion proof for the leaf at index m, per RFC 9162 §2.1.3: sibling
// hashes bottom-up; empty for a single-leaf tree (the leaf hash itself is the
// root). Throws RangeError when m is out of range.
export async function auditPath(m: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]> {
  if (!Number.isInteger(m) || m < 0 || m >= leafHashes.length) {
    throw new RangeError("merkle: leaf index out of range");
  }
  return path(m, leafHashes);
}

async function path(m: number, leafHashes: Uint8Array[]): Promise<Uint8Array[]> {
  const n = leafHashes.length;
  if (n === 1) return [];
  const k = largestPow2LessThan(n);
  if (m < k) {
    return [...(await path(m, leafHashes.slice(0, k))), await merkleRoot(leafHashes.slice(k))];
  }
  return [...(await path(m - k, leafHashes.slice(k))), await merkleRoot(leafHashes.slice(0, k))];
}

// Verify an RFC 9162 §2.1.3 inclusion proof. `leaf` is the leaf hash
// (leafHash of the canonical leaf bytes); `path` is the audit path bottom-up;
// `expectedRoot` is the merkleRoot committed by the checkpoint envelope.
// True iff the path reconstructs the expected root. Never throws.
export async function verifyInclusion(
  leaf: Uint8Array,
  leafIndex: number,
  totalLeaves: number,
  auditPath: Uint8Array[],
  expectedRoot: Uint8Array,
): Promise<boolean> {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || totalLeaves <= 0 || leafIndex >= totalLeaves) {
    return false;
  }
  if (totalLeaves === 1) return auditPath.length === 0 && bytesEqual(leaf, expectedRoot);

  let fn = leafIndex;
  let sn = totalLeaves - 1;
  let r = leaf;

  for (const p of auditPath) {
    if (sn === 0) return false; // path longer than the tree depth — malformed
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }

  return sn === 0 && bytesEqual(r, expectedRoot);
}

function prefixed(prefix: number, bytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + bytes.length);
  buf[0] = prefix;
  buf.set(bytes, 1);
  return buf;
}

// Largest k = 2**a with k < n (0 for n < 2).
function largestPow2LessThan(n: number): number {
  if (n < 2) return 0;
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
