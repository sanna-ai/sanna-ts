/**
 * Sanna Gateway — Receipt v2.0 Triad
 *
 * Enhanced receipt generation with three deterministic hashes, embedded at
 * extensions["com.sanna.gateway"].receipt_triad (SAN-848):
 * - input_hash:     hash of the incoming request (tool + args)
 * - reasoning_hash: hash of governance reasoning (decision + checks)
 * - action_hash:    at the gateway boundary this equals input_hash — the
 *                    gateway can only observe the tool call it proxied, not
 *                    what the downstream server actually executed.
 *                    context_limitation documents this constraint for
 *                    downstream verifiers. Mirrors Python's
 *                    sanna.gateway.receipt_v2.compute_receipt_triad.
 */

import { hashObj } from "@sanna-ai/core";
import type { AuthorityDecision, CheckResult } from "@sanna-ai/core";

// ── Types ────────────────────────────────────────────────────────────

export interface ReceiptTriad {
  input_hash: string;
  reasoning_hash: string;
  action_hash: string;
  context_limitation: string;
}

// ── Hash computation ─────────────────────────────────────────────────

/**
 * Hash of the incoming request: tool name + arguments.
 */
export function computeInputHash(
  toolName: string,
  args: Record<string, unknown>,
): string {
  return hashObj({ tool_name: toolName, arguments: args });
}

/**
 * Hash of governance reasoning: authority decision, check results,
 * and optional justification.
 */
export function computeReasoningHash(
  authorityDecision: AuthorityDecision,
  checkResults: CheckResult[],
  justification?: string,
): string {
  return hashObj({
    decision: authorityDecision.decision,
    reason: authorityDecision.reason,
    boundary_type: authorityDecision.boundary_type,
    checks: checkResults.map((c) => ({
      check_id: c.check_id,
      passed: c.passed,
      severity: c.severity,
    })),
    justification: justification ?? null,
  });
}

/**
 * Build the complete receipt triad from pre-computed hashes.
 *
 * At the gateway boundary, action_hash always equals input_hash: the
 * gateway is a proxy and cannot attest to what the downstream server
 * actually executed, only to the tool call it observed and forwarded.
 * context_limitation is fixed to "gateway_boundary" to document this for
 * downstream verifiers (SAN-848; mirrors Python's
 * sanna.gateway.receipt_v2.compute_receipt_triad).
 */
export function buildReceiptTriad(
  inputHash: string,
  reasoningHash: string,
): ReceiptTriad {
  return {
    input_hash: inputHash,
    reasoning_hash: reasoningHash,
    action_hash: inputHash,
    context_limitation: "gateway_boundary",
  };
}
