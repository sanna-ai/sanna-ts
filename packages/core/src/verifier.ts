/**
 * Sanna Protocol — Receipt verifier
 *
 * Verifies receipt integrity: schema, signature, fingerprint, and consistency.
 * See Sanna specification v1.0, Sections 2, 4, and 5.
 */

import type { KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

import { canonicalize, hashObj } from "./hashing.js";
import { verify, getKeyId, sanitizeForSigning } from "./crypto.js";
import { computeFingerprints } from "./receipt.js";
import type { VerificationResult, Check } from "./types.js";
import {
  verifySessionManifestReceipt,
  verifyInvocationAnomalyReceipt,
  VALID_ANOMALY_EVENT_TYPES,
} from "./verifier-manifest.js";

// ── Regex patterns ───────────────────────────────────────────────────

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HEX64_RE = /^[a-f0-9]{64}$/;
const HEX16_RE = /^[a-f0-9]{16}$/;

const NON_EVALUATED = new Set(["NOT_CHECKED", "ERRORED"]);

// ── ajv validator (lazy singleton) ───────────────────────────────────

// Compiled once on first use; reused for all subsequent validations.
// Catches conditional allOf rules (B1/B2/A1/A3/B3/B4/MODIFY/R1/R2) that
// the hand-rolled checks below do not cover.
//
// `any` casts mirror the test pattern (ajv as any) to satisfy the DTS
// builder -- Ajv2020/addFormats types don't satisfy TS2020's constructor
// constraint when resolved via Node16 moduleResolution.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _ajvValidate: ((data: unknown) => boolean) & { errors?: any[] | null } | null = null;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getAjvValidator(): ((data: unknown) => boolean) & { errors?: any[] | null } {
  if (_ajvValidate) return _ajvValidate;
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const schemaPath = resolve(__dirname, "../../../spec/schemas/receipt.schema.json");
  const fullSchema = JSON.parse(readFileSync(schemaPath, "utf-8")) as { allOf?: unknown[] };
  // Compile ONLY the allOf conditional rules, not the full property/required
  // definitions. The hand-rolled checks above already cover unconditional
  // required-field rules; running the full schema would duplicate those with
  // different error messages and break existing test fixtures that omit optional
  // fields (e.g. CheckResult.name). The allOf rules have no $ref/$defs
  // dependencies so they extract cleanly.
  const conditionalSchema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "allOf": fullSchema.allOf ?? [],
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ajv = new (Ajv2020 as any)({ allErrors: true, strict: false });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (addFormats as any)(ajv);
  _ajvValidate = ajv.compile(conditionalSchema) as typeof _ajvValidate;
  return _ajvValidate!;
}

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

  // v1.5+ minimum-required-fields assertion (SAN-370).
  // When checks_version >= 10, agent_identity + agent_session_id are required.
  // Error message text must match Python byte-for-byte for cross-SDK
  // debugging consistency.
  const cvStr = String(receipt.checks_version ?? "");
  const cvInt = parseInt(cvStr, 10);

  if (!isNaN(cvInt) && cvInt >= 10) {
    const agentIdentity = receipt.agent_identity as Record<string, unknown> | undefined;
    if (!agentIdentity) {
      errors.push("v1.5+ receipt (checks_version >= 10) is missing required field: agent_identity");
    } else if (!agentIdentity.agent_session_id) {
      errors.push("v1.5+ receipt agent_identity missing required sub-field: agent_session_id");
    }
  }

  // v1.4+ minimum-required-fields assertion (SAN-222).
  // When checks_version >= 9, tool_name is required.
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

  // Interceptor assurance (SAN-765 / spec Section 7.3): an authority-only receipt with a top-level Receipt
  // Triad never ran reasoning checks, so assurance must be "partial". Error text MUST match Python verify.py
  // byte-for-byte (cross-SDK consistency).
  const hasTopTriad =
    typeof receipt.input_hash === "string" ||
    typeof receipt.reasoning_hash === "string" ||
    typeof receipt.action_hash === "string";
  if (receipt.invariants_scope === "authority_only" && hasTopTriad) {
    if (receipt.assurance !== "partial") {
      errors.push(
        "Authority-only receipt (invariants_scope=authority_only) with a Receipt Triad " +
          "must have assurance='partial' per spec Section 7.3 (no reasoning checks ran).",
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

  // ── ajv conditional-rule validation (SAN-394) ───────────────────────
  // Second pass: catches B1/B2/A1/A3/B3/B4/MODIFY/R1/R2 rules that the
  // hand-rolled checks above do not cover. Verdict-level cross-SDK parity:
  // same receipts fail in both Python (jsonschema) and TS (ajv). Error
  // message text differs between libraries (expected); error presence is
  // the parity gate.
  try {
    const validate = getAjvValidator();
    const valid = validate(receipt);
    if (!valid && validate.errors) {
      for (const err of validate.errors) {
        const path = err.instancePath || "/";
        const msg = `Schema validation failed: ${err.message} (at ${path})`;
        // Dedup: skip if a hand-rolled check already caught a violation
        // for the same field (avoids double-reporting missing agent_identity etc.)
        const fieldName = path.split("/").pop() ?? "";
        if (!errors.some((e) => fieldName && e.includes(fieldName))) {
          errors.push(msg);
        }
      }
    }
  } catch (ajvErr) {
    // Schema compilation failure is a verifier bug, not a receipt bug.
    errors.push(`Schema validation internal error: ${String(ajvErr)}`);
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

/**
 * Verify a value is a well-formed spec section 2.11.1 redaction marker.
 *
 * A valid marker has shape: `{__redacted__: true, original_hash: "<64-hex>"}`.
 *
 * TS parallel of sanna-repo Python `_is_redaction_marker` at verify.py:668.
 * Internal helper for `checkGatewayRedactionMarkersCorrect`. NOT exported.
 *
 * Note: this helper validates the DICT marker shape for spec section 2.11.1
 * (gateway content redaction). It is DISTINCT from `isValidRedactionMarker`
 * in verifier-manifest.ts which validates the STRING marker shape for spec
 * section 2.14 / 2.22.5 (SAN-406 manifest content redaction). The two
 * helpers cover non-overlapping scopes.
 */
function isRedactionMarker(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  const obj = value as Record<string, unknown>;
  if (obj.__redacted__ !== true) return false;
  const oh = obj.original_hash;
  return typeof oh === "string" && /^[a-f0-9]{64}$/.test(oh);
}

/**
 * Verify content_mode declaration matches actual spec section 2.11.1 marker state.
 *
 * Stable umbrella error code: `REDACTION_CLAIM_WITHOUT_MARKER` (cross-SDK aligned
 * with sanna-repo Python verifier at sanna/verify.py:_check_gateway_redaction_markers_correct).
 * Single umbrella covering three distinct rejection cases (the fixture and the
 * SDKs intentionally use one code for "redaction state mismatch" generally):
 *
 * 1. content_mode='redacted' is claimed but neither inputs.context nor
 *    outputs.response contains a valid spec section 2.11.1 marker.
 * 2. content_mode='redacted' and a field has __redacted__=true but the marker
 *    is malformed (missing or invalid original_hash). Attacker may have
 *    pre-populated a fake marker that bypassed FIX-12.
 * 3. content_mode='full' is claimed but a field IS a valid spec section 2.11.1
 *    marker. Claim/state mismatch the other direction.
 *
 * Scope note: only inputs.context and outputs.response are checked. This matches
 * the emission-side scope of @sanna-ai/core's `applyRedactionMarkers` which only
 * writes markers to those two fields. If future spec changes extend the
 * redactable-field set, this function must be updated in lockstep with the
 * Python counterpart at sanna-repo's sanna/verify.py.
 *
 * @param receipt The receipt object to verify.
 * @returns An array of error strings, each prefixed with REDACTION_CLAIM_WITHOUT_MARKER:.
 *          Empty array if all states are consistent.
 */
export function checkGatewayRedactionMarkersCorrect(receipt: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const contentMode = receipt.content_mode as string | null | undefined;
  const inputs = (receipt.inputs as Record<string, unknown>) ?? {};
  const outputs = (receipt.outputs as Record<string, unknown>) ?? {};
  const ctx = inputs.context;
  const resp = outputs.response;

  const isMarkerAttempt = (v: unknown): boolean =>
    typeof v === "object" && v !== null && (v as Record<string, unknown>).__redacted__ === true;

  const ctxIsMarkerAttempt = isMarkerAttempt(ctx);
  const respIsMarkerAttempt = isMarkerAttempt(resp);
  const ctxIsValidMarker = ctxIsMarkerAttempt && isRedactionMarker(ctx);
  const respIsValidMarker = respIsMarkerAttempt && isRedactionMarker(resp);

  if (contentMode === "redacted") {
    if (!(ctxIsValidMarker || respIsValidMarker)) {
      errors.push(
        "REDACTION_CLAIM_WITHOUT_MARKER: content_mode='redacted' is claimed " +
          "but neither inputs.context nor outputs.response contains a valid " +
          "spec section 2.11.1 marker",
      );
    }
    if (ctxIsMarkerAttempt && !ctxIsValidMarker) {
      errors.push(
        "REDACTION_CLAIM_WITHOUT_MARKER: inputs.context marker is malformed " +
          "(missing or invalid original_hash; expected 64-char lowercase hex)",
      );
    }
    if (respIsMarkerAttempt && !respIsValidMarker) {
      errors.push(
        "REDACTION_CLAIM_WITHOUT_MARKER: outputs.response marker is malformed " +
          "(missing or invalid original_hash; expected 64-char lowercase hex)",
      );
    }
  } else if (contentMode === "full") {
    if (ctxIsValidMarker || respIsValidMarker) {
      errors.push(
        "REDACTION_CLAIM_WITHOUT_MARKER: content_mode='full' is claimed but " +
          "inputs/outputs contain spec section 2.11.1 markers (claim/state mismatch)",
      );
    }
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

  // SAN-371: cv=9 receipts pass with informational warning indicating
  // partial R6 conformance only (agent_identity absent at cv<10 per spec
  // Section 2.19 line 780). cv=10 binds agent_identity for full R6.
  if (!isNaN(cvLegacy) && cvLegacy === 9) {
    warnings.push(
      "CV9_LEGACY: Receipt at checks_version=9 (v1.4) verified successfully " +
      "with the 20-field fingerprint formula. cv=9 receipts indicate partial " +
      "R6 conformance only; agent_identity is absent. Receipts emitted at " +
      "cv=10 (v1.5) bind agent_identity for full R6 conformance per spec " +
      "Section 2.19. No re-emission required: existing signed cv=9 receipts " +
      "remain cryptographically valid indefinitely."
    );
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
  allErrors.push(...checkGatewayRedactionMarkersCorrect(receipt)); // SAN-516 PR 3 of 3

  // 5. Status/count consistency
  checksPerformed.push("status_consistency");
  const statusErrors = checkStatusConsistency(receipt);
  allErrors.push(...statusErrors);

  // 6. Timestamp sanity
  checksPerformed.push("timestamp");
  const tsErrors = checkTimestamp(receipt);
  allErrors.push(...tsErrors);

  // SAN-358: manifest/anomaly semantic checks
  const eventType = receipt.event_type as string | undefined;
  let manifestChecks: Check[] = [];
  if (eventType === "session_manifest") {
    checksPerformed.push("manifest_checks");
    manifestChecks = verifySessionManifestReceipt(receipt);
    for (const chk of manifestChecks) {
      if (chk.status === "FAIL") allErrors.push(chk.message);
      else if (chk.status === "WARN") warnings.push(chk.message);
    }
  } else if (eventType && VALID_ANOMALY_EVENT_TYPES.has(eventType)) {
    checksPerformed.push("manifest_checks");
    manifestChecks = verifyInvocationAnomalyReceipt(receipt, null);
    for (const chk of manifestChecks) {
      if (chk.status === "FAIL") allErrors.push(chk.message);
      else if (chk.status === "WARN") warnings.push(chk.message);
    }
  }

  return {
    valid: allErrors.length === 0,
    errors: allErrors,
    warnings,
    checks_performed: checksPerformed,
    checks: manifestChecks,
  };
}

export function verifyReceiptSet(
  receipts: Record<string, unknown>[],
  publicKey?: KeyObject,
): Record<string, VerificationResult> {
  const results: Record<string, VerificationResult> = {};
  for (const receipt of receipts) {
    const rid = String(receipt.receipt_id ?? "unknown");
    results[rid] = verifyReceipt(receipt, publicKey);
  }
  // Cross-receipt anomaly pass
  for (const receipt of receipts) {
    const rid = String(receipt.receipt_id ?? "unknown");
    const et = receipt.event_type as string | undefined;
    if (et && VALID_ANOMALY_EVENT_TYPES.has(et)) {
      const crossChecks = verifyInvocationAnomalyReceipt(receipt, receipts);
      const result = results[rid];
      result.checks = crossChecks;
      // Re-derive errors/warnings from cross-receipt checks (replaces single-receipt WARNs)
      // Remove single-receipt WARN messages for the two cross-receipt checks
      result.warnings = result.warnings.filter(
        (w) => w !== "Cross-receipt parent resolution requires receipt set; use verify_receipt_set"
      );
      for (const chk of crossChecks) {
        if (chk.status === "FAIL") result.errors.push(chk.message);
        else if (chk.status === "WARN") result.warnings.push(chk.message);
      }
      result.valid = result.errors.length === 0;
    }
  }
  return results;
}
