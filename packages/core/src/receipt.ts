/**
 * Sanna Protocol — Receipt module
 *
 * Fingerprint computation, receipt signing, and receipt construction.
 * See Sanna specification v1.0, Sections 2 and 4.
 */

import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { EMPTY_HASH, canonicalize, hashContent, hashObj } from "./hashing.js";
import { sign, getKeyId } from "./crypto.js";
import type { Receipt, CheckResult, ReceiptSignature, ContentMode } from "./types.js";

// ── Constants ────────────────────────────────────────────────────────

export const SPEC_VERSION = "1.4";
export const CHECKS_VERSION = "9"; // SAN-222 v1.4: tool_name + agent_model fields (positions 17-20)
export const TOOL_VERSION = "1.4.0"; // v1.4: bare semver (was "sanna-ts/1.3.0")
export const TOOL_NAME = "sanna-ts"; // v1.4: canonical SDK identity per spec §2.17

// ── Fingerprint computation ──────────────────────────────────────────

/**
 * Compute the 14-field fingerprint components for a receipt.
 * Returns the pipe-delimited fingerprint input string.
 *
 * Fields 1-12: (original)
 * Field 13: parent_receipts_hash — SHA-256 of canonicalized parent_receipts. EMPTY_HASH if null/absent.
 * Field 14: workflow_id_hash — SHA-256 of UTF-8 workflow_id. EMPTY_HASH if null/absent.
 *
 * See spec §4.1 for the full algorithm.
 */
export function computeFingerprintInput(receipt: Record<string, unknown>): string {
  const correlationId = (receipt.correlation_id as string) ?? "";

  // Bug #4: correlation_id must not contain pipe character (matches Python ValueError)
  if (correlationId.includes("|")) {
    throw new Error(
      `correlation_id must not contain '|' character: ${correlationId}`,
    );
  }

  const contextHash = (receipt.context_hash as string) ?? "";
  const outputHash = (receipt.output_hash as string) ?? "";
  const checksVersion = (receipt.checks_version as string) ?? "";

  // checks_hash — optional fields default to null (not undefined) to match Python's None serialization
  const checks = (receipt.checks as Record<string, unknown>[]) ?? [];
  const hasEnforcementFields = checks.some((c) => c.triggered_by !== undefined);
  let checksData: Record<string, unknown>[];
  if (hasEnforcementFields) {
    checksData = checks.map((c) => ({
      check_id: c.check_id ?? "",
      passed: c.passed,
      severity: c.severity ?? "",
      evidence: c.evidence ?? null,
      triggered_by: c.triggered_by ?? null,
      enforcement_level: c.enforcement_level ?? null,
      check_impl: c.check_impl ?? null,
      replayable: c.replayable ?? null,
    }));
  } else {
    checksData = checks.map((c) => ({
      check_id: c.check_id ?? "",
      passed: c.passed,
      severity: c.severity ?? "",
      evidence: c.evidence ?? null,
    }));
  }
  const checksHash = checksData.length > 0 ? hashObj(checksData) : EMPTY_HASH;

  // constitution_hash (strip constitution_approval)
  const constitutionRef = receipt.constitution_ref as Record<string, unknown> | undefined;
  let constitutionHash: string;
  if (constitutionRef) {
    const stripped: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(constitutionRef)) {
      if (k !== "constitution_approval") stripped[k] = v;
    }
    constitutionHash = hashObj(stripped);
  } else {
    constitutionHash = EMPTY_HASH;
  }

  // Python treats [] and {} as falsy; match that behavior for fields 5-12.
  const isTruthy = (v: unknown): boolean => {
    if (!v) return false;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === "object") return Object.keys(v as Record<string, unknown>).length > 0;
    return true;
  };

  const enforcement = receipt.enforcement as Record<string, unknown> | undefined;
  const enforcementHash = isTruthy(enforcement) ? hashObj(enforcement) : EMPTY_HASH;

  const coverage = receipt.evaluation_coverage as Record<string, unknown> | undefined;
  const coverageHash = isTruthy(coverage) ? hashObj(coverage) : EMPTY_HASH;

  const authority = receipt.authority_decisions as unknown[] | undefined;
  const authorityHash = isTruthy(authority) ? hashObj(authority) : EMPTY_HASH;

  const escalation = receipt.escalation_events as unknown[] | undefined;
  const escalationHash = isTruthy(escalation) ? hashObj(escalation) : EMPTY_HASH;

  const trust = receipt.source_trust_evaluations as unknown[] | undefined;
  const trustHash = isTruthy(trust) ? hashObj(trust) : EMPTY_HASH;

  const extensions = receipt.extensions as Record<string, unknown> | undefined;
  const extensionsHash = isTruthy(extensions) ? hashObj(extensions) : EMPTY_HASH;

  // Field 13: parent_receipts_hash — explicit null check ([] ≠ null)
  const parentReceipts = receipt.parent_receipts as string[] | null | undefined;
  const parentReceiptsHash = parentReceipts != null ? hashObj(parentReceipts) : EMPTY_HASH;

  // Field 14: workflow_id_hash
  const workflowId = receipt.workflow_id as string | null | undefined;
  const workflowIdHash = workflowId != null ? hashContent(workflowId, 64) : EMPTY_HASH;

  // 12-field fingerprint for checks_version < 6 (backward compat with pre-v1.0 receipts)
  const cvInt = parseInt(checksVersion, 10);
  if (!isNaN(cvInt) && cvInt < 6) {
    return [
      correlationId,
      contextHash,
      outputHash,
      checksVersion,
      checksHash,
      constitutionHash,
      enforcementHash,
      coverageHash,
      authorityHash,
      escalationHash,
      trustHash,
      extensionsHash,
    ].join("|");
  }

  // 14-field fingerprint for 6 <= checks_version < 8
  if (!isNaN(cvInt) && cvInt < 8) {
    return [
      correlationId,
      contextHash,
      outputHash,
      checksVersion,
      checksHash,
      constitutionHash,
      enforcementHash,
      coverageHash,
      authorityHash,
      escalationHash,
      trustHash,
      extensionsHash,
      parentReceiptsHash,
      workflowIdHash,
    ].join("|");
  }

  // 16-field fingerprint for checks_version >= 8 (v1.3, SAN-213)
  // Fields 15-16: enforcement_surface and invariants_scope participate in the
  // fingerprint as hash_text(value). When the receipt is missing these fields
  // (cv >= 8 but field absent), fall back to "" so computeFingerprintInput
  // never throws. The verifier's checkSchema catches the missing-field defect
  // separately; this fallback ensures verifyReceipt can collect ALL independent
  // errors instead of short-circuiting on a throw. The resulting fingerprint
  // mismatch (hash("") != hash(expected)) loudly surfaces the problem at the
  // fingerprint check too.
  const enforcementSurfaceRaw =
      (receipt.enforcement_surface as string) ?? "";
  const invariantsScopeRaw =
      (receipt.invariants_scope as string) ?? "";
  const enforcementSurfaceHash = hashContent(enforcementSurfaceRaw, 64);
  const invariantsScopeHash    = hashContent(invariantsScopeRaw, 64);

  return [
    correlationId,
    contextHash,
    outputHash,
    checksVersion,
    checksHash,
    constitutionHash,
    enforcementHash,
    coverageHash,
    authorityHash,
    escalationHash,
    trustHash,
    extensionsHash,
    parentReceiptsHash,
    workflowIdHash,
    enforcementSurfaceHash,
    invariantsScopeHash,
  ].join("|");
}

/**
 * Compute the receipt fingerprint (16-hex) and full fingerprint (64-hex).
 */
export function computeFingerprints(receipt: Record<string, unknown>): {
  receipt_fingerprint: string;
  full_fingerprint: string;
} {
  const input = computeFingerprintInput(receipt);
  return {
    receipt_fingerprint: hashContent(input, 16),
    full_fingerprint: hashContent(input, 64),
  };
}

// ── Receipt signing ──────────────────────────────────────────────────

/**
 * Sanitize a value tree for signing: convert exact-integer floats to int,
 * reject non-integer floats.
 */
function sanitizeForSigning(obj: unknown): unknown {
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      throw new Error(`Non-finite number in signed content: ${obj}`);
    }
    if (Number.isInteger(obj)) return obj;
    if (obj === Math.trunc(obj)) return Math.trunc(obj);
    throw new Error(`Non-integer float in signed content: ${obj}`);
  }
  if (Array.isArray(obj)) {
    return obj.map((v) => sanitizeForSigning(v));
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = sanitizeForSigning(v);
    }
    return result;
  }
  return obj;
}

/**
 * Sign a receipt dict and add receipt_signature block.
 *
 * The signing material is the canonical JSON of the entire receipt
 * with receipt_signature.signature set to "" (placeholder).
 */
export function signReceipt(
  receipt: Record<string, unknown>,
  privateKey: KeyObject,
  signedBy: string,
): Record<string, unknown> {
  const keyId = getKeyId(privateKey);

  const sigBlock: ReceiptSignature = {
    signature: "",  // placeholder — excluded from signing
    key_id: keyId,
    signed_by: signedBy,
    signed_at: new Date().toISOString(),
    scheme: "receipt_sig_v1",
  };

  // Create signable copy with placeholder signature
  const signable = structuredClone(receipt);
  signable.receipt_signature = sigBlock;
  const sanitized = sanitizeForSigning(signable);
  const canonical = canonicalize(sanitized);
  const data = Buffer.from(canonical, "utf-8");

  // Sign and replace placeholder
  const signatureB64 = sign(data, privateKey);
  sigBlock.signature = signatureB64;

  receipt.receipt_signature = sigBlock;
  return receipt;
}

// ── Receipt generation ───────────────────────────────────────────────

export interface ReceiptParams {
  correlation_id: string;
  inputs: Record<string, unknown>;
  outputs: Record<string, unknown>;
  checks: CheckResult[];
  status?: string;
  tool_version?: string;
  constitution_ref?: Record<string, unknown>;
  enforcement?: Record<string, unknown>;
  evaluation_coverage?: Record<string, unknown>;
  authority_decisions?: Record<string, unknown>[];
  escalation_events?: Record<string, unknown>[];
  source_trust_evaluations?: Record<string, unknown>[];
  extensions?: Record<string, unknown>;
  parent_receipts?: string[] | null;
  workflow_id?: string | null;
  enforcementSurface?: string;
  invariantsScope?: string;
  content_mode?: ContentMode;
  content_mode_source?: string | null;
  event_type?: string | null;
  context_limitation?: string | null;
  input_hash?: string | null;
  reasoning_hash?: string | null;
  action_hash?: string | null;
  assurance?: "full" | "partial" | null;
}

/**
 * Generate a complete receipt from parameters.
 * Computes hashes, fingerprints, UUID, and status.
 */
export function generateReceipt(params: ReceiptParams): Receipt {
  if (params.correlation_id.includes("|")) {
    throw new Error(
      `correlation_id must not contain '|' character: ${params.correlation_id}`,
    );
  }

  const contextHash = hashObj(params.inputs);
  const outputHash = hashObj(params.outputs);

  const checksPassed = params.checks.filter((c) => c.passed).length;
  const checksFailed = params.checks.filter((c) => !c.passed).length;

  // Compute status if not provided
  let status = params.status;
  if (!status) {
    const FAIL_SEVERITIES = new Set(["critical", "high"]);
    const WARN_SEVERITIES = new Set(["warning", "medium", "low"]);
    const hasCriticalFail = params.checks.some(
      (c) => !c.passed && FAIL_SEVERITIES.has(c.severity),
    );
    const hasWarnFail = params.checks.some(
      (c) => !c.passed && WARN_SEVERITIES.has(c.severity),
    );
    if (hasCriticalFail) status = "FAIL";
    else if (hasWarnFail) status = "WARN";
    else status = "PASS";
  }

  // SAN-213 v1.3: 4-action enforcement override (mirrors Python receipt.py:678-692).
  // Receipt status cannot contradict enforcement.action: a receipt with action="halted"
  // but status="PASS" would misrepresent reality. Override only fires when computed
  // status is PASS — receipts whose checks already produced WARN/FAIL are left alone
  // (verifier in 3C provides the cross-field consistency check).
  if (params.enforcement) {
    const enforcementAction = (params.enforcement as Record<string, unknown>).action as string | undefined;
    if (status === "PASS") {
      if (enforcementAction === "halted") {
        status = "FAIL";
      } else if (enforcementAction === "warned") {
        status = "WARN";
      } else if (enforcementAction === "escalated") {
        status = "WARN";
      }
      // "allowed" → PASS, no change needed
    }
  }

  const receiptBase: Record<string, unknown> = {
    spec_version: SPEC_VERSION,
    tool_version: params.tool_version ?? TOOL_VERSION,
    checks_version: CHECKS_VERSION,
    receipt_id: randomUUID(),
    correlation_id: params.correlation_id,
    timestamp: new Date().toISOString(),
    inputs: params.inputs,
    outputs: params.outputs,
    context_hash: contextHash,
    output_hash: outputHash,
    checks: params.checks,
    checks_passed: checksPassed,
    checks_failed: checksFailed,
    status,
  };

  // Chaining fields (participate in fingerprint)
  if (params.parent_receipts != null) receiptBase.parent_receipts = params.parent_receipts;
  if (params.workflow_id != null) receiptBase.workflow_id = params.workflow_id;

  // Optional fields
  if (params.constitution_ref) receiptBase.constitution_ref = params.constitution_ref;
  if (params.enforcement) receiptBase.enforcement = params.enforcement;
  if (params.evaluation_coverage) receiptBase.evaluation_coverage = params.evaluation_coverage;
  if (params.authority_decisions) receiptBase.authority_decisions = params.authority_decisions;
  if (params.escalation_events) receiptBase.escalation_events = params.escalation_events;
  if (params.source_trust_evaluations) receiptBase.source_trust_evaluations = params.source_trust_evaluations;
  if (params.extensions) receiptBase.extensions = params.extensions;

  // v1.3 required top-level fields (participate in fingerprint at
  // positions 15-16). Defaults match Python receipt.py:589-590.
  receiptBase.enforcement_surface = params.enforcementSurface ?? "middleware";
  receiptBase.invariants_scope    = params.invariantsScope    ?? "full";

  // Metadata fields (do NOT participate in fingerprint)
  if (params.content_mode != null) receiptBase.content_mode = params.content_mode;
  if (params.content_mode_source != null) receiptBase.content_mode_source = params.content_mode_source;
  if (params.event_type !== undefined) receiptBase.event_type = params.event_type;
  if (params.context_limitation !== undefined) receiptBase.context_limitation = params.context_limitation;
  if (params.input_hash !== undefined) receiptBase.input_hash = params.input_hash;
  if (params.reasoning_hash !== undefined) receiptBase.reasoning_hash = params.reasoning_hash;
  if (params.action_hash !== undefined) receiptBase.action_hash = params.action_hash;
  if (params.assurance !== undefined) receiptBase.assurance = params.assurance;

  // Compute fingerprints
  const { receipt_fingerprint, full_fingerprint } = computeFingerprints(receiptBase);
  receiptBase.receipt_fingerprint = receipt_fingerprint;
  receiptBase.full_fingerprint = full_fingerprint;

  return receiptBase as unknown as Receipt;
}
