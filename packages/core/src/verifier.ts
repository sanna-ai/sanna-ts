/**
 * Sanna Protocol — Receipt verifier
 *
 * Verifies receipt integrity: schema, signature, fingerprint, and consistency.
 * See Sanna specification v1.0, Sections 2, 4, and 5.
 */

import type { KeyObject } from "node:crypto";

import { canonicalize, hashObj } from "./hashing.js";
import { verify, getKeyId } from "./crypto.js";
import { computeFingerprints } from "./receipt.js";
import type { VerificationResult } from "./types.js";

// ── Sanitize helper (same as receipt.ts) ─────────────────────────────

function sanitizeForSigning(obj: unknown): unknown {
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) throw new Error(`Non-finite number: ${obj}`);
    if (Number.isInteger(obj)) return obj;
    if (obj === Math.trunc(obj)) return Math.trunc(obj);
    throw new Error(`Non-integer float: ${obj}`);
  }
  if (Array.isArray(obj)) return obj.map((v) => sanitizeForSigning(v));
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) result[k] = sanitizeForSigning(v);
    return result;
  }
  return obj;
}

// ── Regex patterns ───────────────────────────────────────────────────

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64_RE = /^[a-f0-9]{64}$/;
const HEX16_RE = /^[a-f0-9]{16}$/;

const NON_EVALUATED = new Set(["NOT_CHECKED", "ERRORED"]);

// ── Individual checks ────────────────────────────────────────────────

function checkSchema(receipt: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const required = [
    "spec_version", "checks_version", "receipt_id",
    "receipt_fingerprint", "full_fingerprint", "correlation_id",
    "timestamp", "inputs", "outputs", "context_hash", "output_hash",
    "checks", "checks_passed", "checks_failed", "status",
  ];
  for (const field of required) {
    if (!(field in receipt)) errors.push(`Missing required field: ${field}`);
  }

  // v1.4+ minimum-required-fields assertion (SAN-222).
  // When checks_version >= 9, tool_name is required.
  // Error message text must match Python byte-for-byte for cross-SDK
  // debugging consistency.
  const cvStr = String(receipt.checks_version ?? "");
  const cvInt = parseInt(cvStr, 10);

  if (!isNaN(cvInt) && cvInt >= 9) {
    if (!receipt.tool_name) {
      errors.push(
        "v1.4+ receipt (checks_version >= 9) is missing required field: tool_name",
      );
    }
  }

  // v1.3+ minimum-required-fields assertion (SAN-213).
  // Mirror of Python verify.py:900-919. When checks_version >= 8,
  // enforcement_surface and invariants_scope are required fields.
  // Error message text must match Python byte-for-byte for cross-SDK
  // debugging consistency.
  const cvIntForV13Check = cvInt;
  if (!isNaN(cvIntForV13Check) && cvIntForV13Check >= 8) {
    if (!receipt.enforcement_surface) {
      errors.push(
        "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
      );
    }
    if (!receipt.invariants_scope) {
      errors.push(
        "v1.3+ receipt (checks_version >= 8) is missing required field: invariants_scope",
      );
    }
  }

  // receipt_id: UUID v4
  const rid = String(receipt.receipt_id ?? "");
  if (rid && !UUID_V4_RE.test(rid)) {
    errors.push(`receipt_id invalid format: '${rid}' (expected UUID v4)`);
  }

  // Hash format checks
  const fp = String(receipt.receipt_fingerprint ?? "");
  if (fp && !HEX16_RE.test(fp)) {
    errors.push(`receipt_fingerprint invalid format: '${fp}' (expected 16 hex)`);
  }

  const ffp = String(receipt.full_fingerprint ?? "");
  if (ffp && !HEX64_RE.test(ffp)) {
    errors.push(`full_fingerprint invalid format: '${ffp}' (expected 64 hex)`);
  }

  for (const field of ["context_hash", "output_hash"]) {
    const val = String(receipt[field] ?? "");
    if (val && !HEX64_RE.test(val)) {
      errors.push(`${field} invalid format: '${val}' (expected 64 hex)`);
    }
  }

  return errors;
}

function checkSignature(
  receipt: Record<string, unknown>,
  publicKey: KeyObject,
): string[] {
  const errors: string[] = [];
  const sigBlock = receipt.receipt_signature as Record<string, unknown> | undefined;

  if (!sigBlock) {
    errors.push("Receipt has no signature");
    return errors;
  }

  const signatureB64 = String(sigBlock.signature ?? "");
  if (!signatureB64) {
    errors.push("Receipt signature value is empty");
    return errors;
  }

  // Check key_id
  const expectedKeyId = getKeyId(publicKey);
  if (sigBlock.key_id !== expectedKeyId) {
    errors.push(
      `Signature key_id mismatch: got '${sigBlock.key_id}', expected '${expectedKeyId}'`,
    );
    return errors;
  }

  // Reconstruct signable form
  const signable = structuredClone(receipt);
  (signable.receipt_signature as Record<string, unknown>).signature = "";

  try {
    const sanitized = sanitizeForSigning(signable);
    const canonical = canonicalize(sanitized);
    const data = Buffer.from(canonical, "utf-8");
    const valid = verify(data, signatureB64, publicKey);
    if (!valid) {
      errors.push("Receipt signature verification FAILED — receipt may have been tampered");
    }
  } catch (e) {
    errors.push(`Signature verification error: ${e}`);
  }

  return errors;
}

function checkFingerprint(receipt: Record<string, unknown>): string[] {
  const errors: string[] = [];

  const { receipt_fingerprint: computed16, full_fingerprint: computed64 } =
    computeFingerprints(receipt);

  const expected16 = String(receipt.receipt_fingerprint ?? "");
  const expected64 = String(receipt.full_fingerprint ?? "");

  if (computed16 !== expected16) {
    errors.push(
      `Fingerprint mismatch: computed '${computed16}', expected '${expected16}'`,
    );
  }

  if (expected64 && computed64 !== expected64) {
    errors.push(
      `Full fingerprint mismatch: computed '${computed64}', expected '${expected64}'`,
    );
  }

  return errors;
}

function checkContentHashes(receipt: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const inputs = receipt.inputs as Record<string, unknown> | undefined;
  const outputs = receipt.outputs as Record<string, unknown> | undefined;

  if (inputs) {
    const computed = hashObj(inputs);
    const expected = String(receipt.context_hash ?? "");
    if (expected && computed !== expected) {
      errors.push(
        `context_hash mismatch: computed '${computed}', expected '${expected}'`,
      );
    }
  }

  if (outputs) {
    const computed = hashObj(outputs);
    const expected = String(receipt.output_hash ?? "");
    if (expected && computed !== expected) {
      errors.push(
        `output_hash mismatch: computed '${computed}', expected '${expected}'`,
      );
    }
  }

  return errors;
}

function checkStatusConsistency(receipt: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const checks = (receipt.checks as Record<string, unknown>[]) ?? [];

  const standardChecks = checks.filter(
    (c) => !NON_EVALUATED.has(String(c.status ?? "")),
  );

  const FAIL_SEVERITIES = new Set(["critical", "high"]);
  const WARN_SEVERITIES = new Set(["warning", "medium", "low"]);

  const criticalFails = standardChecks.filter(
    (c) => !c.passed && FAIL_SEVERITIES.has(String(c.severity)),
  ).length;
  const warnFails = standardChecks.filter(
    (c) => !c.passed && WARN_SEVERITIES.has(String(c.severity)),
  ).length;
  const nonEvaluated = checks.filter(
    (c) => NON_EVALUATED.has(String(c.status ?? "")),
  );

  let computed: string;
  if (criticalFails > 0) computed = "FAIL";
  else if (warnFails > 0) computed = "WARN";
  else if (nonEvaluated.length > 0) computed = "PARTIAL";
  else computed = "PASS";

  // SAN-213 v1.3 enforcement override (parity with generateReceipt and
  // Python verify.py:479-491). Receipt status cannot contradict
  // enforcement.action: a receipt with action="halted" but
  // status="PASS" would misrepresent reality. Override only fires when
  // computed status is PASS — receipts whose checks already produced
  // WARN/FAIL/PARTIAL are left alone (matches Python's design choice;
  // the receipt is rejected by the status mismatch error if there's
  // an actual contradiction).
  const enforcement = receipt.enforcement as Record<string, unknown> | undefined;
  if (enforcement) {
    const enforcementAction = enforcement.action as string | undefined;
    if (computed === "PASS") {
      if (enforcementAction === "halted") {
        computed = "FAIL";
      } else if (enforcementAction === "warned") {
        computed = "WARN";
      } else if (enforcementAction === "escalated") {
        computed = "WARN";
      }
    }
  }

  const expected = String(receipt.status ?? "");
  if (computed !== expected) {
    const enforcementAction = enforcement?.action as string | undefined;
    let msg: string;
    if (enforcementAction) {
      msg = (
        `Status mismatch: receipt has enforcement.action='${enforcementAction}' ` +
        `with status='${expected}' but v1.3 spec §10 requires status='${computed}'. ` +
        `Receipt is cryptographically valid but semantically defective: ` +
        `the audit trail misrepresents what governance actually did.`
      );
    } else {
      msg = `Status mismatch: computed ${computed}, expected ${expected}`;
    }
    errors.push(msg);
  }

  // Check counts
  const actualPassed = standardChecks.filter((c) => c.passed).length;
  const actualFailed = standardChecks.length - actualPassed;

  if (receipt.checks_passed !== actualPassed) {
    errors.push(
      `checks_passed mismatch: got ${receipt.checks_passed}, expected ${actualPassed}`,
    );
  }
  if (receipt.checks_failed !== actualFailed) {
    errors.push(
      `checks_failed mismatch: got ${receipt.checks_failed}, expected ${actualFailed}`,
    );
  }

  return errors;
}

function checkTimestamp(receipt: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const ts = receipt.timestamp as string | undefined;
  if (!ts) return errors;

  const parsed = new Date(ts);
  if (isNaN(parsed.getTime())) {
    errors.push(`Timestamp is not valid ISO 8601: '${ts}'`);
    return errors;
  }

  const now = Date.now();
  // Not in the future (with 5 minute tolerance for clock skew)
  if (parsed.getTime() > now + 5 * 60 * 1000) {
    errors.push(`Timestamp is in the future: '${ts}'`);
  }

  // Not impossibly old (before 2024-01-01)
  const minDate = new Date("2024-01-01T00:00:00Z");
  if (parsed.getTime() < minDate.getTime()) {
    errors.push(`Timestamp is impossibly old: '${ts}'`);
  }

  return errors;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Verify a receipt's integrity.
 *
 * Runs all checks independently and reports all failures:
 * 1. Schema validation (required fields, format)
 * 2. Signature verification (Ed25519)
 * 3. Fingerprint recalculation
 * 4. Content hash verification
 * 5. Status/count consistency
 * 6. Timestamp sanity
 */
export function verifyReceipt(
  receipt: Record<string, unknown>,
  publicKey?: KeyObject,
): VerificationResult {
  const allErrors: string[] = [];
  const warnings: string[] = [];
  const checksPerformed: string[] = [];

  // 1. Schema validation
  checksPerformed.push("schema");
  const schemaErrors = checkSchema(receipt);
  allErrors.push(...schemaErrors);

  // Legacy warning for pre-v1.3 receipts missing new fields. Mirrors Python verify.py:927-940.
  const cvStr = String(receipt.checks_version ?? "");
  const cvLegacy = parseInt(cvStr, 10);
  if (!isNaN(cvLegacy) && (cvLegacy === 6 || cvLegacy === 7)) {
    if (!receipt.enforcement_surface) {
      warnings.push(
        `Pre-v1.3 receipt (checks_version=${cvLegacy}): ` +
        `'enforcement_surface' field not present. This field was added in ` +
        `v1.3 (checks_version 8) and is not required at this protocol version. ` +
        `Re-generate with SDK >=1.3 for v1.3 integrity claims.`
      );
    }
    if (!receipt.invariants_scope) {
      warnings.push(
        `Pre-v1.3 receipt (checks_version=${cvLegacy}): ` +
        `'invariants_scope' field not present. This field was added in ` +
        `v1.3 (checks_version 8) and is not required at this protocol version.`
      );
    }
  }

  // 2. Signature verification
  if (publicKey) {
    checksPerformed.push("signature");
    const sigErrors = checkSignature(receipt, publicKey);
    allErrors.push(...sigErrors);
  } else if (receipt.receipt_signature) {
    warnings.push("Signature present but no public key provided for verification");
  }

  // 3. Fingerprint recalculation
  checksPerformed.push("fingerprint");
  const fpErrors = checkFingerprint(receipt);
  allErrors.push(...fpErrors);

  // 4. Content hash verification
  checksPerformed.push("content_hashes");
  const hashErrors = checkContentHashes(receipt);
  allErrors.push(...hashErrors);

  // 5. Status/count consistency
  checksPerformed.push("status_consistency");
  const statusErrors = checkStatusConsistency(receipt);
  allErrors.push(...statusErrors);

  // 6. Timestamp sanity
  checksPerformed.push("timestamp");
  const tsErrors = checkTimestamp(receipt);
  allErrors.push(...tsErrors);

  return {
    valid: allErrors.length === 0,
    errors: allErrors,
    warnings,
    checks_performed: checksPerformed,
  };
}
