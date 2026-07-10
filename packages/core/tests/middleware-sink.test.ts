// SAN-836 TEST MIGRATION NOTE: sannaObserve's default enforcementMode
// flipped from "advisory" to "enforced" (matching Python's always-enforcing
// @sanna_observe). makeConstitution()'s default invariant below
// (INV_NO_FABRICATION, rule "No fabrication", enforcement: "halt", check:
// null) resolves to UNKNOWN_TYPE -- a separate, already-tracked fail-closed
// bug (SAN-850) that treats unrecognized invariants as critical-severity
// failures. Under the new enforced default this incidentally halts every
// sink-integration test below, none of which test enforcement/halting as
// their purpose (they test sink.store() plumbing, receipt field
// propagation, and NullSink no-op behavior). Those tests are pinned to
// `enforcementMode: "advisory"` explicitly -- byte-identical to their
// pre-flip implicit-advisory behavior -- so they keep verifying what they
// were built to verify. "sink.store called even on halted receipts"
// already used an explicit enforced/authority-halt constitution and is
// unaffected by this migration.
import { describe, it, expect, vi } from "vitest";
import {
  sannaObserve,
  SannaHaltError,
} from "../src/middleware.js";
import { NullSink } from "../src/sinks/null-sink.js";
import type { Constitution, ReceiptSink } from "../src/types.js";

function makeConstitution(overrides: Partial<Constitution> = {}): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent",
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
    invariants: [
      { id: "INV_NO_FABRICATION", rule: "No fabrication", enforcement: "halt", check: null },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  };
}

function makeMockSink(): ReceiptSink {
  return {
    store: vi.fn().mockResolvedValue({ success: true, receiptId: "test" }),
  };
}

function echoAgent(input: { query: string; context?: string }): string {
  return `Response to: ${input.query}. Context mentions: ${input.context ?? "none"}`;
}

function piiAgent(_input: { query: string }): string {
  return "Contact john@example.com for details.";
}

describe("middleware sink integration", () => {
  it("sink.store() called after receipt generation", async () => {
    // SAN-836: observation-only (sink.store call plumbing) -- see file header.
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      enforcementMode: "advisory",
    });

    governed({ query: "test", context: "context" });

    // sink.store is called asynchronously via .catch chain
    await vi.waitFor(() => {
      expect(sink.store).toHaveBeenCalledTimes(1);
    });
  });

  it("receipt still returned in result even with sink", () => {
    // SAN-836: observation-only (result.receipt presence) -- see file header.
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    expect(result.receipt).toBeDefined();
    expect(result.receipt.receipt_id).toBeTruthy();
  });

  it("backward compat: no sink means no persistence (no error)", () => {
    // SAN-836: observation-only (sink-omission does not error) -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    expect(result.receipt).toBeDefined();
    expect(result.halted).toBe(false);
  });

  it("sink.store() receives the generated receipt", async () => {
    // SAN-836: observation-only (sink receives matching receipt_id) -- see file header.
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test", context: "ctx" });

    await vi.waitFor(() => {
      expect(sink.store).toHaveBeenCalledTimes(1);
    });

    const storedReceipt = (sink.store as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(storedReceipt.receipt_id).toBe(result.receipt.receipt_id);
  });

  it("sink.store() failure with log_and_continue doesn't throw", () => {
    const sink: ReceiptSink = {
      store: vi.fn().mockRejectedValue(new Error("storage failure")),
    };

    // SAN-836: observation-only (sink.store rejection does not propagate) -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      enforcementMode: "advisory",
    });

    // Should not throw even though sink.store rejects
    const result = governed({ query: "test" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
  });

  it("sink.store() receiving correct receipt_id", async () => {
    // SAN-836: observation-only (stored receipt_id format/match) -- see file header.
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });

    await vi.waitFor(() => {
      expect(sink.store).toHaveBeenCalled();
    });

    const storedReceipt = (sink.store as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(storedReceipt.receipt_id).toMatch(/^[0-9a-f-]+$/);
    expect(storedReceipt.receipt_id).toBe(result.receipt.receipt_id);
  });

  it("parentReceipts option propagated to receipt", () => {
    // SAN-836: observation-only (parentReceipts field propagation) -- see file header.
    const sink = makeMockSink();
    const parentIds = ["parent-receipt-001", "parent-receipt-002"];
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      parentReceipts: parentIds,
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    expect(result.receipt.parent_receipts).toEqual(parentIds);
  });

  it("workflowId option propagated to receipt", () => {
    // SAN-836: observation-only (workflowId field propagation) -- see file header.
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      workflowId: "workflow-abc-123",
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    expect(result.receipt.workflow_id).toBe("workflow-abc-123");
  });

  it("parentReceipts null by default (not in fingerprint)", () => {
    // SAN-836: observation-only (default-null field, not a fingerprint value
    // test) -- pinned advisory, byte-identical to pre-flip -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    // parent_receipts should be undefined or null when not provided
    expect(result.receipt.parent_receipts == null).toBe(true);
  });

  it("workflowId null by default (not in fingerprint)", () => {
    // SAN-836: observation-only (default-null field, not a fingerprint value
    // test) -- pinned advisory, byte-identical to pre-flip -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    // workflow_id should be undefined or null when not provided
    expect(result.receipt.workflow_id == null).toBe(true);
  });

  it("content_mode and content_mode_source not in receipt by default", () => {
    // SAN-836: observation-only (default-absent fields) -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    // content_mode should be undefined or null when not explicitly set
    expect(result.receipt.content_mode == null).toBe(true);
    expect(result.receipt.content_mode_source == null).toBe(true);
  });

  it("receipt has spec_version 1.4", () => {
    // SAN-836: observation-only (spec_version field, not enforcement) -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    expect(result.receipt.spec_version).toBe("1.4");
  });

  it("receipt has checks_version 9", () => {
    // SAN-836: observation-only (checks_version field, not enforcement) -- see file header.
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test" });
    expect(result.receipt.checks_version).toBe("9");
  });

  it("sink.store called even on halted receipts", async () => {
    const sink = makeMockSink();
    const constitution = makeConstitution({
      authority_boundaries: {
        cannot_execute: ["dangerous_tool"],
        must_escalate: [],
        can_execute: [],
        default_escalation: "log",
      },
    });

    function dangerousFn(): string {
      return "done";
    }

    const governed = sannaObserve(dangerousFn, {
      constitution,
      enforcementMode: "enforced",
      toolName: "dangerous_tool",
      sink,
    });

    try {
      governed();
    } catch (e) {
      expect(e).toBeInstanceOf(SannaHaltError);
      const haltError = e as SannaHaltError;
      expect(haltError.receipt).toBeDefined();
    }

    // The halt in this case happens in authority evaluation (before sink.store in runGovernance),
    // but the SannaHaltError still carries a receipt. The sink may or may not be called
    // depending on where the halt occurs. Verify the error was thrown with a receipt.
    expect.assertions(2);
  });

  it("NullSink as a sink produces no errors", async () => {
    // SAN-836: observation-only (NullSink no-op behavior) -- see file header.
    const nullSink = new NullSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink: nullSink,
      enforcementMode: "advisory",
    });

    const result = governed({ query: "test", context: "ctx" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
    expect(result.halted).toBe(false);
  });
});
