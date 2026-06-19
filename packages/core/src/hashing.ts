/**
 * Sanna Protocol — Hashing module
 *
 * Implements canonical JSON serialization (RFC 8785 / JCS) and
 * SHA-256 hashing per the Sanna specification v1.0, Section 3.
 */

import { createHash } from "node:crypto";
// canonicalize ships CJS — cast through unknown for Node16 module compat.
import canonicalize_ from "canonicalize";
const jcs = canonicalize_ as unknown as (input: unknown) => string | undefined;

// ── Constants ────────────────────────────────────────────────────────

/** SHA-256 of zero bytes — the "empty" sentinel used for absent fields. */
export const EMPTY_HASH =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ── Canonicalization ─────────────────────────────────────────────────

/**
 * Reject non-integer floats; coerce integer-valued floats to int (spec section 3.2).
 *
 * Mirrors Python's sanna.hashing.normalize_floats. Applied recursively to nested
 * arrays + objects. Booleans pass through unchanged (JS booleans are not Numbers,
 * unlike Python where bool is a subclass of int). BigInt is rejected explicitly
 * (JS-specific type; Sanna receipts use the Number type only).
 *
 * - Integer-valued numbers (1.0, 71.0) -> int equivalents (1, 71). In JS, 1.0
 *   and 1 are the same Number; preserved as-is.
 * - Negative zero (-0) -> 0
 * - NaN -> throw TypeError("NaN is not allowed in canonical JSON")
 * - Infinity / -Infinity -> throw TypeError("Infinity is not allowed...")
 * - Non-integer floats (1.5, 3.14) -> throw TypeError
 * - BigInt (123n) -> throw TypeError (Sanna receipts use Number, not BigInt)
 *
 * Cross-SDK byte parity (spec section 3.2): conforming implementations MUST reject
 * any JSON value that is a floating-point number in signing and hashing contexts.
 * canonicalize is a hashing context.
 */
export function normalizeFloats(obj: unknown): unknown {
  if (typeof obj === "boolean") return obj;  // pass through; JS boolean is not Number
  if (typeof obj === "bigint") {
    throw new TypeError(
      `BigInt not allowed in canonical JSON (Sanna receipts use Number type only): ${obj}n`,
    );
  }
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      if (Number.isNaN(obj)) {
        throw new TypeError("NaN is not allowed in canonical JSON");
      }
      throw new TypeError(`Infinity is not allowed in canonical JSON: ${obj}`);
    }
    if (Object.is(obj, -0)) {
      return 0;  // -0 -> 0 (matches Python normalize_floats)
    }
    if (Number.isInteger(obj)) {
      return obj;  // JS already represents 1.0 and 1 as the same Number; preserve
    }
    throw new TypeError(
      `Non-integer float not allowed in canonical JSON: ${obj}`,
    );
  }
  if (Array.isArray(obj)) {
    return obj.map((v) => normalizeFloats(v));
  }
  if (obj !== null && typeof obj === "object") {
    // Object.fromEntries makes __proto__ an own data property instead of
    // hitting the prototype setter (bracket assignment silently drops it).
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, normalizeFloats(v)]),
    );
  }
  return obj;  // null, string, undefined pass through
}

/**
 * RFC 8785 JSON Canonicalization Scheme.
 * Returns a deterministic JSON string with sorted keys and no whitespace.
 * Rejects non-integer floats per spec section 3.2.
 */
export function canonicalize(obj: unknown): string {
  const normalized = normalizeFloats(obj);
  const result = jcs(normalized);
  if (result === undefined) {
    throw new Error("canonicalize: input is not JSON-serializable");
  }
  return result;
}

// ── Hash primitives ──────────────────────────────────────────────────

/**
 * SHA-256 of raw bytes, returned as 64-char lowercase hex.
 */
export function hashBytes(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * SHA-256 of a UTF-8 string, returned as 64-char lowercase hex.
 *
 * Applies the Sanna text normalization pipeline (spec §3.3):
 *   1. NFC Unicode normalization
 *   2. Line-ending normalization (\r\n and \r → \n)
 *   3. Trailing whitespace stripped from each line
 *   4. Leading/trailing whitespace stripped from the whole string
 *   5. UTF-8 encode → SHA-256
 */
export function hashContent(data: string, truncate: number = 64): string {
  // 1. NFC normalization
  let s = data.normalize("NFC");
  // 2. Line-ending normalization
  s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  // 3. Trailing whitespace per line
  s = s
    .split("\n")
    .map((line) => line.replace(/\s+$/, ""))
    .join("\n");
  // 4. Leading/trailing strip
  s = s.trim();
  // 5. UTF-8 encode + SHA-256
  const hex = createHash("sha256").update(s, "utf-8").digest("hex");
  return hex.slice(0, truncate);
}

/**
 * Canonicalize an object then SHA-256 the canonical JSON bytes.
 * Equivalent to Python's `hash_obj()`.
 */
export function hashObj(obj: unknown): string {
  const canonical = canonicalize(obj);
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}
