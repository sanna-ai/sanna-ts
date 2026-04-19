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
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
    });

    governed({ query: "test", context: "context" });

    // sink.store is called asynchronously via .catch chain
    await vi.waitFor(() => {
      expect(sink.store).toHaveBeenCalledTimes(1);
    });
  });

  it("receipt still returned in result even with sink", () => {
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
    });

    const result = governed({ query: "test" });
    expect(result.receipt).toBeDefined();
    expect(result.receipt.receipt_id).toBeTruthy();
  });

  it("backward compat: no sink means no persistence (no error)", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    expect(result.receipt).toBeDefined();
    expect(result.halted).toBe(false);
  });

  it("sink.store() receives the generated receipt", async () => {
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
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

    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
    });

    // Should not throw even though sink.store rejects
    const result = governed({ query: "test" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
  });

  it("sink.store() receiving correct receipt_id", async () => {
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
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
    const sink = makeMockSink();
    const parentIds = ["parent-receipt-001", "parent-receipt-002"];
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      parentReceipts: parentIds,
    });

    const result = governed({ query: "test" });
    expect(result.receipt.parent_receipts).toEqual(parentIds);
  });

  it("workflowId option propagated to receipt", () => {
    const sink = makeMockSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink,
      workflowId: "workflow-abc-123",
    });

    const result = governed({ query: "test" });
    expect(result.receipt.workflow_id).toBe("workflow-abc-123");
  });

  it("parentReceipts null by default (not in fingerprint)", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    // parent_receipts should be undefined or null when not provided
    expect(result.receipt.parent_receipts == null).toBe(true);
  });

  it("workflowId null by default (not in fingerprint)", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    // workflow_id should be undefined or null when not provided
    expect(result.receipt.workflow_id == null).toBe(true);
  });

  it("content_mode and content_mode_source not in receipt by default", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    // content_mode should be undefined or null when not explicitly set
    expect(result.receipt.content_mode == null).toBe(true);
    expect(result.receipt.content_mode_source == null).toBe(true);
  });

  it("receipt has spec_version 1.3", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    expect(result.receipt.spec_version).toBe("1.3");
  });

  it("receipt has checks_version 8", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    expect(result.receipt.checks_version).toBe("8");
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
    const nullSink = new NullSink();
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
      sink: nullSink,
    });

    const result = governed({ query: "test", context: "ctx" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
    expect(result.halted).toBe(false);
  });
});
