/**
 * SAN-836: sannaObserve / withSannaGovernance default-posture conformance.
 *
 * DECISION (operator-approved, GRC-reviewed): flip the sannaObserve /
 * withSannaGovernance default enforcementMode from "advisory" to "enforced",
 * matching the Python SDK's default posture. "advisory" and "permissive"
 * remain explicit opt-ins; only the DEFAULT changes.
 *
 * PARITY MAPPING (E): Python's @sanna_observe decorator has no enforcement
 * mode toggle -- it always enforces. middleware.py halts unconditionally
 * when a check's enforcement_level resolves to "halt". Checks recorded at
 * "warn" / "log" enforcement levels are always recorded on the receipt but
 * never halt execution, in either SDK. This change brings the TS DEFAULT
 * posture (no enforcementMode passed) into line with that always-halts-on-
 * halt-level behavior. It is DEFAULT-POSTURE parity only: the full set of
 * *which* conditions resolve to a halt-severity check still differs
 * cross-SDK (tracked separately under SAN-849/850/851) and is not addressed
 * here.
 *
 * Isolation from SAN-850: TS fails closed on invariants it cannot classify
 * (UNKNOWN_TYPE -> passed:false, severity derived from `enforcement: "halt"`
 * -> "critical"), which is a *separate*, already-tracked over-block bug that
 * also becomes default-active once "enforced" is the default. To keep this
 * suite's assertions about the default-flip itself uncontaminated by that
 * known bug, every constitution below uses only RECOGNIZED invariant types
 * (required_keywords) or the authority-boundary evaluator (which has no
 * "unrecognized" failure mode at all -- an action is allow/escalate/halt by
 * construction, never UNKNOWN_TYPE). None of these fixtures use the
 * catch-all "No fabrication" / check:null invariant shape that trips
 * SAN-850.
 */
import { describe, it, expect } from "vitest";
import { sannaObserve, SannaHaltError } from "../src/middleware.js";
import type { Constitution } from "../src/types.js";

function makeConstitution(overrides: Partial<Constitution> = {}): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "san836-test-agent",
      domain: "testing",
      description: "SAN-836 conformance agent",
      extensions: {},
    },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test boundary", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  };
}

function echoAgent(input: { query: string; context?: string }): string {
  return `Response to: ${input.query}. Context mentions: ${input.context ?? "none"}`;
}

// ── A / B fixture: authority cannot_execute boundary ───────────────────
// Recognized-by-construction halt condition -- no UNKNOWN_TYPE path exists
// for authority evaluation, so this is fully isolated from SAN-850.

function makeAuthorityHaltConstitution(): Constitution {
  return makeConstitution({
    authority_boundaries: {
      cannot_execute: ["dangerous_tool"],
      must_escalate: [],
      can_execute: [],
      default_escalation: "log",
    },
  });
}

function dangerousFn(): string {
  return "action-completed";
}

// ── C / D fixture: recognized `required_keywords` invariant ────────────
// "must contain '<kw>'" is detected as required_keywords (not UNKNOWN_TYPE),
// so pass/fail is a real evaluated verdict, not a SAN-850 fail-closed
// artifact.

function makeRequiredKeywordConstitution(
  keyword: string,
  enforcement: "halt" | "warn",
): Constitution {
  return makeConstitution({
    invariants: [
      {
        id: "INV_REQUIRED_KW",
        rule: `must contain '${keyword}'`,
        enforcement,
        check: null,
      },
    ],
  });
}

describe("SAN-836: sannaObserve default flips advisory -> enforced", () => {
  it("A. NEW DEFAULT ENFORCES: no enforcementMode + authority cannot_execute boundary halts the tool", () => {
    const constitution = makeAuthorityHaltConstitution();

    const governed = sannaObserve(dangerousFn, {
      constitution,
      toolName: "dangerous_tool",
      // no enforcementMode -- must resolve to the new "enforced" default
    });

    let threw = false;
    let haltError: SannaHaltError | undefined;
    try {
      governed();
      // If we get here, the wrap did NOT halt -- fail explicitly rather
      // than rely solely on toThrow so the failure message is unambiguous
      // pre-fix (this line executes on pre-fix/advisory-default code).
      expect.unreachable("expected sannaObserve to halt under the new enforced default");
    } catch (e) {
      threw = true;
      haltError = e as SannaHaltError;
    }

    expect(threw).toBe(true);
    expect(haltError).toBeInstanceOf(SannaHaltError);
    // The caller never receives a normal SannaResult -- governed() throws
    // instead of returning {output, receipt, halted}.
    expect(haltError!.receipt.enforcement?.action).toBe("halted");
    const authorityDecisions = haltError!.receipt.authority_decisions as
      | Record<string, unknown>[]
      | undefined;
    expect(authorityDecisions?.[0]?.decision).toBe("halt");
  });

  it("B. ADVISORY STILL OPTS OUT: explicit enforcementMode 'advisory' on the same authority boundary does not halt", () => {
    const constitution = makeAuthorityHaltConstitution();

    const governed = sannaObserve(dangerousFn, {
      constitution,
      toolName: "dangerous_tool",
      enforcementMode: "advisory",
    });

    const result = governed();
    expect(result.halted).toBe(false);
    expect(result.output).toBe("action-completed");
    // The would-be-halt condition is still recorded on the receipt -- for
    // an authority-boundary condition this lands in authority_decisions
    // (not checks[]; checks[] is populated by the coherence/invariant
    // pipeline, which authority evaluation is upstream of and independent
    // from). The record is honest: decision "halt" is preserved even
    // though advisory mode did not enforce it.
    const authorityDecisions = result.receipt.authority_decisions as
      | Record<string, unknown>[]
      | undefined;
    expect(authorityDecisions?.[0]?.decision).toBe("halt");
  });

  it("C. NO OVER-BLOCK OF NORMAL CASES: no enforcementMode + all-recognized, all-passing invariants does not halt", () => {
    // "Response" appears in echoAgent's own output template, so this
    // recognized required_keywords check genuinely passes (not a SAN-850
    // fail-closed artifact).
    const constitution = makeRequiredKeywordConstitution("Response", "halt");

    const governed = sannaObserve(echoAgent, {
      constitution,
      // no enforcementMode
    });

    const result = governed({ query: "test", context: "context" });
    expect(result.halted).toBe(false);
    expect(result.output).toContain("Response to:");
    const check = result.receipt.checks.find((c) => c.check_id === "INV_REQUIRED_KW");
    expect(check?.passed).toBe(true);
  });

  it("D. NO OVER-ENFORCEMENT OF WARN SEVERITY: no enforcementMode + recognized invariant failing at 'warn' does not halt", () => {
    // Keyword deliberately absent from echoAgent's output -> genuine fail,
    // not a SAN-850 UNKNOWN_TYPE artifact (required_keywords is a fully
    // recognized, evaluated invariant type).
    const constitution = makeRequiredKeywordConstitution(
      "sanna-required-keyword-not-present",
      "warn",
    );

    const governed = sannaObserve(echoAgent, {
      constitution,
      // no enforcementMode
    });

    const result = governed({ query: "test", context: "context" });
    expect(result.halted).toBe(false);
    expect(result.output).toContain("Response to:");

    const check = result.receipt.checks.find((c) => c.check_id === "INV_REQUIRED_KW");
    expect(check).toBeDefined();
    expect(check?.passed).toBe(false);
    // enforcement:"warn" maps to severity "medium" -- outside
    // HALT_SEVERITIES = {critical, high} -- so it is recorded, not halted.
    expect(check?.severity).toBe("medium");
  });
});
