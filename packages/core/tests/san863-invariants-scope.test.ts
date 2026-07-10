/**
 * SAN-863 (PR B): derive invariants_scope from observed execution instead of
 * defaulting to "full". Mirrors the SEMANTICS of Python's
 * _derive_invariants_scope (sanna-repo/src/sanna/middleware.py, SAN-863 PR A)
 * with TS's wider not-evaluated status vocabulary: NOT_CHECKED, ERRORED,
 * UNKNOWN_TYPE, UNSAFE_PATTERN (Python only has NOT_CHECKED/ERRORED).
 *
 * Coverage (did the declared rule run) and outcome (did it pass) are
 * orthogonal. This suite asserts coverage reporting only; it does not touch
 * or assert enforcement outcomes (checks_passed/checks_failed, halt
 * decisions), which are explicitly out of scope for SAN-863 PR B.
 */
import { describe, it, expect } from "vitest";
import { generateReceipt, signReceipt } from "../src/receipt.js";
import { verifyReceipt } from "../src/verifier.js";
import { generateKeypair } from "../src/crypto.js";
import type { CheckResult } from "../src/types.js";

const { privateKey: privKey, publicKey: pubKey } = generateKeypair();

function coverage(receipt: Record<string, unknown>): Record<string, unknown> | undefined {
  const ext = receipt.extensions as Record<string, unknown> | undefined;
  return ext?.["com.sanna.coverage"] as Record<string, unknown> | undefined;
}

describe("SAN-863: invariants_scope derivation", () => {
  it("unrecognized invariant (UNKNOWN_TYPE) -> limited, with correct coverage extension", () => {
    const checks: CheckResult[] = [
      {
        check_id: "INV_UNKNOWN",
        passed: false,
        severity: "critical",
        evidence: "Unrecognized invariant type: cannot evaluate rule",
        status: "UNKNOWN_TYPE",
        triggered_by: "INV_UNKNOWN",
      },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-1",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("limited");
    expect(receipt.invariants_scope).not.toBe("full");
    expect(coverage(receipt)).toEqual({
      invariants_declared: 1,
      invariants_executed: 0,
      skipped: [{ id: "INV_UNKNOWN", reason: "UNKNOWN_TYPE" }],
    });
  });

  it("all declared invariants execute -> full, no coverage extension", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A" },
      { check_id: "INV_B", passed: false, severity: "high", evidence: "found it", triggered_by: "INV_B" },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-2",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });

  it("a declared invariant that never reaches checks -> limited, reason DROPPED", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A" },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-3",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
      declaredInvariantIds: ["INV_A", "INV_GHOST"],
    }) as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("limited");
    expect(coverage(receipt)).toEqual({
      invariants_declared: 2,
      invariants_executed: 1,
      skipped: [{ id: "INV_GHOST", reason: "DROPPED" }],
    });
  });

  it("status explicitly null -> counted as EVALUATED (the openclaw pass path)", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A", status: null },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-4",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
      declaredInvariantIds: ["INV_A"],
    }) as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });

  it("status undefined -> counted as EVALUATED", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A", status: undefined },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-5",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
      declaredInvariantIds: ["INV_A"],
    }) as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });

  it("caller explicitly passing full while an invariant did not evaluate -> downgraded to limited (never honored)", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: false, severity: "critical", evidence: "bad pattern", triggered_by: "INV_A", status: "ERRORED" },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-6",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
      invariantsScope: "full",
    }) as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("limited");
    expect(coverage(receipt)?.skipped).toEqual([{ id: "INV_A", reason: "ERRORED" }]);
  });

  it("caller passing authority_only -> honored unchanged (never upgraded, never downgraded)", () => {
    // Would derive "limited" if re-derived (INV_A errored) -- must stay authority_only.
    const limitedIfDerived: CheckResult[] = [
      { check_id: "INV_A", passed: false, severity: "critical", evidence: "bad pattern", triggered_by: "INV_A", status: "ERRORED" },
    ];
    const r1 = generateReceipt({
      correlation_id: "san863-7a",
      inputs: {},
      outputs: {},
      checks: limitedIfDerived,
      enforcementSurface: "middleware",
      invariantsScope: "authority_only",
    }) as unknown as Record<string, unknown>;
    expect(r1.invariants_scope).toBe("authority_only");
    expect(r1.extensions).toBeUndefined();

    // Would derive "full" if re-derived (everything evaluated) -- must NOT be upgraded to full.
    const fullIfDerived: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A" },
    ];
    const r2 = generateReceipt({
      correlation_id: "san863-7b",
      inputs: {},
      outputs: {},
      checks: fullIfDerived,
      enforcementSurface: "middleware",
      invariantsScope: "authority_only",
    }) as unknown as Record<string, unknown>;
    expect(r2.invariants_scope).toBe("authority_only");
    expect(r2.extensions).toBeUndefined();
  });

  it("zero declared invariants -> full (matching Python), no coverage extension", () => {
    const r1 = generateReceipt({
      correlation_id: "san863-8a",
      inputs: {},
      outputs: {},
      checks: [],
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;
    expect(r1.invariants_scope).toBe("full");
    expect(r1.extensions).toBeUndefined();

    // Explicit empty declared list (e.g. a constitution with an empty invariants array).
    const r2 = generateReceipt({
      correlation_id: "san863-8b",
      inputs: {},
      outputs: {},
      checks: [],
      enforcementSurface: "middleware",
      declaredInvariantIds: [],
    }) as unknown as Record<string, unknown>;
    expect(r2.invariants_scope).toBe("full");
    expect(r2.extensions).toBeUndefined();
  });

  it("C1-C5 coherence checks (no triggered_by) do NOT affect coverage", () => {
    const checks: CheckResult[] = [
      { check_id: "C1", name: "Context Grounding", passed: true, severity: "info", evidence: null },
      { check_id: "C2", name: "Constitutional Alignment", passed: false, severity: "high", evidence: "violation" },
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A" },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-9",
      inputs: {},
      outputs: {},
      checks,
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;

    // Only INV_A (triggered_by-bearing) counts; it evaluated cleanly -> full.
    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });

  it("SELF-CONSISTENCY: full shape -- fingerprint recomputes and signature verifies", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A" },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-10-full",
      inputs: { query: "q" },
      outputs: { response: "r" },
      checks,
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;
    expect(receipt.invariants_scope).toBe("full");

    signReceipt(receipt, privKey, "test@sanna.dev");
    const result = verifyReceipt(receipt, pubKey);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it("SELF-CONSISTENCY: limited shape -- fingerprint recomputes and signature verifies", () => {
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: false, severity: "critical", evidence: "cannot evaluate", triggered_by: "INV_A", status: "UNKNOWN_TYPE" },
      { check_id: "INV_B", passed: true, severity: "info", evidence: null, triggered_by: "INV_B" },
    ];
    const receipt = generateReceipt({
      correlation_id: "san863-10-limited",
      inputs: { query: "q" },
      outputs: { response: "r" },
      checks,
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;
    expect(receipt.invariants_scope).toBe("limited");
    expect(coverage(receipt)).toEqual({
      invariants_declared: 2,
      invariants_executed: 1,
      skipped: [{ id: "INV_A", reason: "UNKNOWN_TYPE" }],
    });

    signReceipt(receipt, privKey, "test@sanna.dev");
    const result = verifyReceipt(receipt, pubKey);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it("NEGATIVE CONTROL: no path emits full when missing is non-empty", () => {
    const notEvaluatedStatuses = ["NOT_CHECKED", "ERRORED", "UNKNOWN_TYPE", "UNSAFE_PATTERN"];
    for (const status of notEvaluatedStatuses) {
      const checks: CheckResult[] = [
        { check_id: "INV_A", passed: false, severity: "critical", evidence: "x", triggered_by: "INV_A", status },
      ];
      // Case 1: requestedScope omitted (derives).
      const r1 = generateReceipt({
        correlation_id: `san863-neg-${status}-1`,
        inputs: {}, outputs: {}, checks,
        enforcementSurface: "middleware",
      }) as unknown as Record<string, unknown>;
      expect(r1.invariants_scope).not.toBe("full");

      // Case 2: requestedScope explicitly "full" (still not honored as full).
      const r2 = generateReceipt({
        correlation_id: `san863-neg-${status}-2`,
        inputs: {}, outputs: {}, checks,
        enforcementSurface: "middleware",
        invariantsScope: "full",
      }) as unknown as Record<string, unknown>;
      expect(r2.invariants_scope).not.toBe("full");

      // Case 3: declared set includes an extra id that never appears at all (DROPPED).
      const r3 = generateReceipt({
        correlation_id: `san863-neg-${status}-3`,
        inputs: {}, outputs: {}, checks,
        enforcementSurface: "middleware",
        declaredInvariantIds: ["INV_A", "INV_MISSING"],
      }) as unknown as Record<string, unknown>;
      expect(r3.invariants_scope).not.toBe("full");
    }
  });

  it("invariants_scope full vs limited produces different fingerprints", () => {
    const fullChecks: CheckResult[] = [
      { check_id: "INV_A", passed: true, severity: "info", evidence: null, triggered_by: "INV_A" },
    ];
    const limitedChecks: CheckResult[] = [
      { check_id: "INV_A", passed: false, severity: "critical", evidence: "x", triggered_by: "INV_A", status: "UNKNOWN_TYPE" },
    ];
    const rFull = generateReceipt({
      correlation_id: "san863-fp-parity",
      inputs: {}, outputs: {}, checks: fullChecks,
      enforcementSurface: "middleware",
    });
    const rLimited = generateReceipt({
      correlation_id: "san863-fp-parity",
      inputs: {}, outputs: {}, checks: limitedChecks,
      enforcementSurface: "middleware",
    });
    expect(rFull.invariants_scope).toBe("full");
    expect(rLimited.invariants_scope).toBe("limited");
    expect(rFull.full_fingerprint).not.toBe(rLimited.full_fingerprint);
  });

  it("the coverage extension CONTENT participates in the fingerprint, isolated from checks", () => {
    // Identical checks array (identical checks_hash) in both receipts; only
    // declaredInvariantIds differs, changing the coverage extension's content
    // (and therefore extensions_hash) while invariants_scope stays "limited"
    // in both. Proves the extension content itself is fingerprint-covered,
    // not just its presence/absence.
    const checks: CheckResult[] = [
      { check_id: "INV_A", passed: false, severity: "critical", evidence: "x", triggered_by: "INV_A", status: "UNKNOWN_TYPE" },
    ];
    const rProxy = generateReceipt({
      correlation_id: "san863-fp-isolation",
      inputs: {}, outputs: {}, checks,
      enforcementSurface: "middleware",
    }) as unknown as Record<string, unknown>;
    const rExtraDeclared = generateReceipt({
      correlation_id: "san863-fp-isolation",
      inputs: {}, outputs: {}, checks,
      enforcementSurface: "middleware",
      declaredInvariantIds: ["INV_A", "INV_GHOST"],
    }) as unknown as Record<string, unknown>;

    expect(rProxy.invariants_scope).toBe("limited");
    expect(rExtraDeclared.invariants_scope).toBe("limited");
    expect(coverage(rProxy)).not.toEqual(coverage(rExtraDeclared));
    expect(rProxy.full_fingerprint).not.toBe(rExtraDeclared.full_fingerprint);
  });
});
