/**
 * SAN-368: AARM Core (R1-R6) conformance verifier.
 *
 * Mechanically verifies the public claim from spec Section 14:
 * "Sanna Protocol v1.5 implements AARM Core (R1-R6) conformance,
 * mechanically verifiable via `sanna-verify aarm`."
 *
 * Per-requirement check functions, decision-enum mapping table, aggregate
 * report. See spec Section 14 for the normative mapping.
 */

import type { KeyObject } from "node:crypto";

import { computeFingerprints } from "./receipt.js";
import { verify, getKeyId, sanitizeForSigning } from "./crypto.js";
import { canonicalize } from "./hashing.js";

// Decision-enum mapping table (code primitive per SAN-356 G2).
// Sanna receipts use the LEFT keys; AARM names are RIGHT values.
export const SANNA_TO_AARM: Record<string, string> = {
  // authority_decisions.boundary_type values
  can_execute: "ALLOW",
  cannot_execute: "DENY",
  must_escalate: "STEP_UP",
  modify_with_constraints: "MODIFY",
  defer_pending_context: "DEFER",
  // authority_decisions.decision values (action-form)
  allow: "ALLOW",
  halt: "DENY",
  escalate: "STEP_UP",
  modify: "MODIFY",
  defer: "DEFER",
};

export interface CheckResult {
  requirement: string;
  name: string;
  status: string;
  message: string;
  evidence: Record<string, unknown>[];
}

export interface AarmReport {
  aggregate_status: string;
  checks: CheckResult[];
  receipt_count: number;
  generated_at: string;
}

// ── Internal helpers ─────────────────────────────────────────────────

function verifyFingerprintForAarm(
  receipt: Record<string, unknown>,
): { ok: boolean; computed: string; expected: string } {
  try {
    const { receipt_fingerprint: computed16, full_fingerprint: computed64 } =
      computeFingerprints(receipt);
    const expected16 = String(receipt.receipt_fingerprint ?? "");
    const expected64 = String(receipt.full_fingerprint ?? "");
    if (computed16 !== expected16) {
      return { ok: false, computed: computed16, expected: expected16 };
    }
    if (expected64 && computed64 !== expected64) {
      return { ok: false, computed: computed64, expected: expected64 };
    }
    return { ok: true, computed: computed16, expected: expected16 };
  } catch {
    return { ok: false, computed: "", expected: "" };
  }
}

function verifySignatureForAarm(
  receipt: Record<string, unknown>,
  publicKey: KeyObject,
): boolean {
  try {
    const sigBlock = receipt.receipt_signature as Record<string, unknown> | undefined;
    if (!sigBlock?.signature) return false;
    const signatureB64 = String(sigBlock.signature);
    const expectedKeyId = getKeyId(publicKey);
    if (sigBlock.key_id !== expectedKeyId) return false;
    const signable = structuredClone(receipt);
    (signable.receipt_signature as Record<string, unknown>).signature = "";
    const sanitized = sanitizeForSigning(signable);
    const canonical = canonicalize(sanitized);
    const data = Buffer.from(canonical, "utf-8");
    return verify(data, signatureB64, publicKey);
  } catch {
    return false;
  }
}

// ── R1-R6 check functions ────────────────────────────────────────────

export function checkR1PreExecutionInterception(
  receipts: Record<string, unknown>[],
): CheckResult {
  const validSurfaces = new Set([
    "middleware",
    "gateway",
    "cli_interceptor",
    "http_interceptor",
    "mixed",
  ]);

  const failing: Record<string, unknown>[] = [];
  let invocationCount = 0;

  for (const r of receipts) {
    const et = String(r.event_type ?? "");
    if (et.startsWith("invocation_")) {
      invocationCount += 1;
      const surface = r.enforcement_surface;
      if (!validSurfaces.has(String(surface ?? ""))) {
        failing.push({
          receipt_fingerprint: r.receipt_fingerprint,
          event_type: et,
          enforcement_surface: surface ?? null,
        });
      }
    }
  }

  if (!invocationCount) {
    const missingSurface = receipts.filter(
      (r) => !validSurfaces.has(String(r.enforcement_surface ?? "")),
    );
    if (missingSurface.length) {
      return {
        requirement: "R1",
        name: "Pre-Execution Interception",
        status: "FAIL",
        message: `${missingSurface.length} receipt(s) lack a valid enforcement_surface`,
        evidence: missingSurface.map((r) => ({
          receipt_fingerprint: r.receipt_fingerprint ?? null,
          enforcement_surface: r.enforcement_surface ?? null,
        })),
      };
    }
    return {
      requirement: "R1",
      name: "Pre-Execution Interception",
      status: "PASS",
      message: `All ${receipts.length} receipt(s) have a valid enforcement_surface`,
      evidence: [],
    };
  }

  if (failing.length) {
    return {
      requirement: "R1",
      name: "Pre-Execution Interception",
      status: "FAIL",
      message: `${failing.length} invocation receipt(s) lack a valid enforcement_surface`,
      evidence: failing,
    };
  }

  return {
    requirement: "R1",
    name: "Pre-Execution Interception",
    status: "PASS",
    message: `All ${invocationCount} invocation receipt(s) have a valid enforcement_surface`,
    evidence: [],
  };
}

export function checkR2ContextAccumulation(
  receipts: Record<string, unknown>[],
): CheckResult {
  const fingerprints = new Set<string>();
  for (const r of receipts) {
    if (r.full_fingerprint) fingerprints.add(String(r.full_fingerprint));
    if (r.receipt_fingerprint) fingerprints.add(String(r.receipt_fingerprint));
  }

  const broken: Record<string, unknown>[] = [];
  for (const r of receipts) {
    const parents = (r.parent_receipts as string[] | null) ?? [];
    for (const p of parents) {
      if (p && !fingerprints.has(p)) {
        broken.push({
          receipt_fingerprint: r.receipt_fingerprint ?? null,
          missing_parent: p,
        });
      }
    }
  }

  if (broken.length) {
    return {
      requirement: "R2",
      name: "Context Accumulation (parent_receipts chain)",
      status: "FAIL",
      message: `${broken.length} parent_receipts reference(s) do not resolve within the receipt set`,
      evidence: broken,
    };
  }

  return {
    requirement: "R2",
    name: "Context Accumulation (parent_receipts chain)",
    status: "PASS",
    message: "All parent_receipts references resolve within the receipt set",
    evidence: [],
  };
}

export function checkR3PolicyEvaluation(
  receipts: Record<string, unknown>[],
): CheckResult {
  const governance = receipts.filter((r) => r.constitution_ref != null);

  if (!governance.length) {
    return {
      requirement: "R3",
      name: "Policy Evaluation with Intent Alignment",
      status: "N/A",
      message: "No governance receipts in set (constitution_ref absent on all receipts)",
      evidence: [],
    };
  }

  const failing = governance.filter((r) => {
    const cr = r.constitution_ref as Record<string, unknown> | null;
    return !cr?.policy_hash;
  });

  if (failing.length) {
    return {
      requirement: "R3",
      name: "Policy Evaluation with Intent Alignment",
      status: "FAIL",
      message: `${failing.length} governance receipt(s) lack constitution_ref.policy_hash`,
      evidence: failing.map((r) => ({
        receipt_fingerprint: r.receipt_fingerprint ?? null,
      })),
    };
  }

  return {
    requirement: "R3",
    name: "Policy Evaluation with Intent Alignment",
    status: "PASS",
    message: `All ${governance.length} governance receipt(s) have constitution_ref.policy_hash`,
    evidence: [],
  };
}

export function checkR4Decisions(
  receipts: Record<string, unknown>[],
): CheckResult {
  const validDecisions = new Set(Object.keys(SANNA_TO_AARM));
  const invalid: Record<string, unknown>[] = [];
  const stepUpUnresolved: Record<string, unknown>[] = [];

  for (const r of receipts) {
    const authorityDecisions = (r.authority_decisions as Record<string, unknown>[] | null) ?? [];
    for (const ad of authorityDecisions) {
      const d = ad.decision as string | undefined;
      if (d && !validDecisions.has(d)) {
        invalid.push({
          receipt_fingerprint: r.receipt_fingerprint ?? null,
          field: "authority_decisions.decision",
          value: d,
        });
      }
      const bt = ad.boundary_type as string | undefined;
      if (bt && !validDecisions.has(bt)) {
        invalid.push({
          receipt_fingerprint: r.receipt_fingerprint ?? null,
          field: "authority_decisions.boundary_type",
          value: bt,
        });
      }
    }

    const enforcement = r.enforcement as Record<string, unknown> | undefined;
    const ea = enforcement?.action as string | undefined;
    if (ea === "escalate" || ea === "escalated") {
      const thisFp =
        (r.full_fingerprint as string | undefined) ??
        (r.receipt_fingerprint as string | undefined);
      if (thisFp) {
        const resolution = receipts.find((other) => {
          const parents = (other.parent_receipts as string[] | null) ?? [];
          return parents.includes(thisFp);
        });
        if (!resolution) {
          stepUpUnresolved.push({
            receipt_fingerprint: r.receipt_fingerprint ?? null,
            issue: "STEP_UP receipt has no downstream receipt chaining to it",
          });
        }
      }
    }
  }

  if (invalid.length || stepUpUnresolved.length) {
    return {
      requirement: "R4",
      name: "Five Authorization Decisions (with STEP_UP chain check)",
      status: "FAIL",
      message:
        `${invalid.length} invalid decision value(s); ` +
        `${stepUpUnresolved.length} unresolved STEP_UP receipt(s)`,
      evidence: [...invalid, ...stepUpUnresolved],
    };
  }

  return {
    requirement: "R4",
    name: "Five Authorization Decisions (with STEP_UP chain check)",
    status: "PASS",
    message:
      "All decisions are in the valid AARM-mapped enum; " +
      "all STEP_UP receipts chain to a resolution",
    evidence: [],
  };
}

export function checkR5TamperEvident(
  receipts: Record<string, unknown>[],
  publicKey?: KeyObject,
): CheckResult {
  const failing: Record<string, unknown>[] = [];

  for (const r of receipts) {
    const { ok, computed, expected } = verifyFingerprintForAarm(r);
    if (!ok) {
      failing.push({
        receipt_fingerprint: r.receipt_fingerprint ?? null,
        issue: `fingerprint mismatch (computed ${computed.slice(0, 16)}, expected ${expected.slice(0, 16)})`,
      });
      continue;
    }
    if (publicKey != null) {
      const sigBlock = r.receipt_signature as Record<string, unknown> | undefined;
      if (sigBlock?.signature) {
        if (!verifySignatureForAarm(r, publicKey)) {
          failing.push({
            receipt_fingerprint: r.receipt_fingerprint ?? null,
            issue: "signature verification failed",
          });
        }
      }
    }
  }

  if (failing.length) {
    return {
      requirement: "R5",
      name: "Tamper-Evident Receipts",
      status: "FAIL",
      message: `${failing.length} receipt(s) failed cryptographic integrity check`,
      evidence: failing,
    };
  }

  return {
    requirement: "R5",
    name: "Tamper-Evident Receipts",
    status: "PASS",
    message:
      `All ${receipts.length} receipt(s) have valid fingerprints` +
      (publicKey != null ? " and signatures" : ""),
    evidence: [],
  };
}

export function checkR6IdentityBinding(
  receipts: Record<string, unknown>[],
): CheckResult {
  let passCount = 0;
  let partialCount = 0;
  const fail: Record<string, unknown>[] = [];

  for (const r of receipts) {
    const cvStr = String(r.checks_version ?? "");
    const cv = parseInt(cvStr, 10);
    const cvNum = isNaN(cv) ? 0 : cv;

    if (cvNum >= 10) {
      const ai = r.agent_identity as Record<string, unknown> | undefined;
      if (!ai?.agent_session_id) {
        fail.push({
          receipt_fingerprint: r.receipt_fingerprint ?? null,
          checks_version: cvStr,
          issue: "cv=10 receipt missing agent_identity.agent_session_id",
        });
      } else {
        passCount += 1;
      }
    } else {
      partialCount += 1;
    }
  }

  if (fail.length) {
    return {
      requirement: "R6",
      name: "Identity Binding",
      status: "FAIL",
      message: `${fail.length} cv=10 receipt(s) missing agent_identity`,
      evidence: fail,
    };
  }

  if (partialCount > 0 && passCount === 0) {
    return {
      requirement: "R6",
      name: "Identity Binding",
      status: "PARTIAL",
      message:
        `All ${partialCount} receipt(s) at cv<=9 (partial R6); ` +
        "upgrade to cv=10 with agent_identity for full R6 conformance",
      evidence: [],
    };
  }

  if (partialCount > 0) {
    return {
      requirement: "R6",
      name: "Identity Binding",
      status: "PARTIAL",
      message:
        `${passCount} receipt(s) at cv=10 with agent_identity (full R6); ` +
        `${partialCount} receipt(s) at cv<=9 (partial R6)`,
      evidence: [],
    };
  }

  return {
    requirement: "R6",
    name: "Identity Binding",
    status: "PASS",
    message: `All ${passCount} receipt(s) at cv=10 with agent_identity (full R6)`,
    evidence: [],
  };
}

// ── Aggregate + format ───────────────────────────────────────────────

export function aggregateAarmReport(
  receipts: Record<string, unknown>[],
  publicKey?: KeyObject,
): AarmReport {
  const checks: CheckResult[] = [
    checkR1PreExecutionInterception(receipts),
    checkR2ContextAccumulation(receipts),
    checkR3PolicyEvaluation(receipts),
    checkR4Decisions(receipts),
    checkR5TamperEvident(receipts, publicKey),
    checkR6IdentityBinding(receipts),
  ];

  const statuses = new Set(checks.map((c) => c.status));
  let aggregateStatus: string;
  if (statuses.has("FAIL")) {
    aggregateStatus = "FAIL";
  } else if (statuses.has("PARTIAL")) {
    aggregateStatus = "PARTIAL";
  } else {
    aggregateStatus = "PASS";
  }

  return {
    aggregate_status: aggregateStatus,
    checks,
    receipt_count: receipts.length,
    generated_at: new Date().toISOString(),
  };
}

export function formatAarmReport(report: AarmReport, fmt: string = "json"): string {
  if (fmt === "json") {
    return JSON.stringify(
      {
        aggregate_status: report.aggregate_status,
        receipt_count: report.receipt_count,
        generated_at: report.generated_at,
        checks: report.checks,
      },
      null,
      2,
    );
  }

  if (fmt === "human") {
    const lines: string[] = [
      "AARM Core (R1-R6) Conformance Report",
      "=".repeat(40),
      `Receipt count: ${report.receipt_count}`,
      `Generated at:  ${report.generated_at}`,
      `Aggregate:     ${report.aggregate_status}`,
      "",
    ];
    for (const c of report.checks) {
      lines.push(`  [${c.status.padEnd(7)}] ${c.requirement} -- ${c.name}`);
      lines.push(`            ${c.message}`);
      if (c.evidence.length > 0 && (c.status === "FAIL" || c.status === "PARTIAL")) {
        const shown = c.evidence.slice(0, 3);
        for (const e of shown) {
          lines.push(`            evidence: ${JSON.stringify(e)}`);
        }
        if (c.evidence.length > 3) {
          lines.push(`            ... (${c.evidence.length - 3} more)`);
        }
      }
      lines.push("");
    }
    return lines.join("\n");
  }

  throw new Error(`Unknown format: ${JSON.stringify(fmt)} (supported: json, human)`);
}
