/**
 * Sanna Protocol — Crypto module
 *
 * Ed25519 signing/verification using Node.js native crypto.
 * ZERO external dependencies.
 *
 * Key format: PKCS#8 PEM (private), SubjectPublicKeyInfo PEM (public),
 * compatible with Python's `cryptography` library.
 *
 * See Sanna specification v1.0, Section 5.
 */

import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";

// SAN-537: sanitizeForSigning is the signing-prep-layer name for the float
// sanitization that normalizeFloats performs at the canonical-JSON-layer.
// Post-SAN-527 (normalizeFloats added to hashing.ts), the two functions are
// functionally equivalent; this alias unifies them under both names for
// backward-compatible call-site API + clear-intent in signing paths.
//
// Behavioral note: vs the three pre-SAN-537 inline implementations, this
// alias is MORE strict at two edges:
//   - -0 normalizes to 0 (was: returned -0 unchanged)
//   - BigInt throws TypeError (was: returned unchanged; broke at canonicalize)
// Both are correctness-positive; documented in the SAN-537 commit.
//
// Error-message wording: previously constitution.ts's sanitizeForSigning
// used "in signed content" qualifier (e.g., "Non-integer float in signed
// content: 1.5"). The unified normalizeFloats uses "in canonical JSON"
// wording. Behaviorally identical; minor text change for any caller
// parsing the error string for context.
export { normalizeFloats as sanitizeForSigning } from "./hashing.js";

export type { KeyObject } from "node:crypto";

// ── Key generation ───────────────────────────────────────────────────

export interface SannaKeypair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  keyId: string;
  label?: string;
}

/**
 * Generate a new Ed25519 keypair.
 * Returns KeyObjects in PKCS#8 / SPKI PEM-compatible format.
 */
export function generateKeypair(label?: string): SannaKeypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const keyId = getKeyId(publicKey);
  return { privateKey, publicKey, keyId, label };
}

// ── Signing ──────────────────────────────────────────────────────────

/**
 * Sign data with an Ed25519 private key.
 * Returns standard Base64 (RFC 4648) with padding.
 */
export function sign(data: Buffer, privateKey: KeyObject): string {
  const sig = cryptoSign(null, data, privateKey);
  return sig.toString("base64");
}

/**
 * Verify an Ed25519 signature.
 * `signature` is standard Base64 (RFC 4648).
 */
export function verify(
  data: Buffer,
  signature: string,
  publicKey: KeyObject,
): boolean {
  // Strip whitespace per spec §5.1
  const cleaned = signature.replace(/[\t\n\r ]/g, "");
  const sigBuf = Buffer.from(cleaned, "base64");
  return cryptoVerify(null, data, publicKey, sigBuf);
}

// ── Key loading ──────────────────────────────────────────────────────

/**
 * Load an Ed25519 private key from a PKCS#8 PEM file.
 */
export function loadPrivateKey(path: string): KeyObject {
  const pem = readFileSync(path, "utf-8");
  return createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });
}

/**
 * Load an Ed25519 public key from a SubjectPublicKeyInfo PEM file.
 */
export function loadPublicKey(path: string): KeyObject {
  const pem = readFileSync(path, "utf-8");
  return createPublicKey({ key: pem, format: "pem", type: "spki" });
}

// ── Key identification ───────────────────────────────────────────────

/**
 * Compute the Sanna key_id: SHA-256 of the raw 32-byte Ed25519 public key.
 * NOT the DER/SPKI encoding — the raw key bytes only.
 */
export function getKeyId(key: KeyObject): string {
  // Derive public key if a private key was passed
  const pub = key.type === "private" ? createPublicKey(key) : key;
  // Export as raw 32-byte Ed25519 public key
  const raw = pub.export({ type: "spki", format: "der" });
  // Ed25519 SPKI DER is 44 bytes: 12-byte header + 32-byte key
  // The raw key is the last 32 bytes
  const rawKey = raw.subarray(raw.length - 32);
  return createHash("sha256").update(rawKey).digest("hex");
}

// ── PEM export helpers ───────────────────────────────────────────────

/** Export private key as PKCS#8 PEM string. */
export function exportPrivateKeyPem(key: KeyObject): string {
  return key.export({ type: "pkcs8", format: "pem" }) as string;
}

/** Export public key as SubjectPublicKeyInfo PEM string. */
export function exportPublicKeyPem(key: KeyObject): string {
  return key.export({ type: "spki", format: "pem" }) as string;
}
