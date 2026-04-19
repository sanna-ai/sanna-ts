import { describe, it, expect } from "vitest";
import { NullSink } from "../src/sinks/null-sink.js";
import type { Receipt } from "../src/types.js";

function makeReceipt(id: string): Receipt {
  return {
    spec_version: "1.3",
    tool_version: "sanna-ts/1.3.0",
    checks_version: "8",
    receipt_id: id,
    receipt_fingerprint: "abcdef0123456789",
    full_fingerprint: "a".repeat(64),
    correlation_id: "sanna-test123",
    timestamp: new Date().toISOString(),
    inputs: { query: "test" },
    outputs: { response: "test output" },
    context_hash: "ctx-hash",
    output_hash: "out-hash",
    checks: [],
    checks_passed: 0,
    checks_failed: 0,
    status: "PASS",
    enforcement_surface: "middleware",
    invariants_scope: "full",
  };
}

describe("NullSink", () => {
  it("store returns success", async () => {
    const sink = new NullSink();
    const result = await sink.store(makeReceipt("r-001"));
    expect(result.success).toBe(true);
  });

  it("storeBatch returns success for all", async () => {
    const sink = new NullSink();
    const receipts = [makeReceipt("r-001"), makeReceipt("r-002"), makeReceipt("r-003")];
    const results = await sink.storeBatch(receipts);
    expect(results).toHaveLength(3);
    for (const result of results) {
      expect(result.success).toBe(true);
    }
  });

  it("flush resolves", async () => {
    const sink = new NullSink();
    await expect(sink.flush()).resolves.toBeUndefined();
  });

  it("close resolves", async () => {
    const sink = new NullSink();
    await expect(sink.close()).resolves.toBeUndefined();
  });

  it("store includes receipt_id in result", async () => {
    const sink = new NullSink();
    const result = await sink.store(makeReceipt("r-unique-42"));
    expect(result.receiptId).toBe("r-unique-42");
  });

  it("storeBatch returns correct count", async () => {
    const sink = new NullSink();
    const receipts = [makeReceipt("a"), makeReceipt("b")];
    const results = await sink.storeBatch(receipts);
    expect(results).toHaveLength(2);
    expect(results[0].receiptId).toBe("a");
    expect(results[1].receiptId).toBe("b");
  });

  it("multiple stores all succeed", async () => {
    const sink = new NullSink();
    const r1 = await sink.store(makeReceipt("r-1"));
    const r2 = await sink.store(makeReceipt("r-2"));
    const r3 = await sink.store(makeReceipt("r-3"));
    expect(r1.success).toBe(true);
    expect(r2.success).toBe(true);
    expect(r3.success).toBe(true);
  });

  it("can store same receipt twice", async () => {
    const sink = new NullSink();
    const receipt = makeReceipt("r-dup");
    const r1 = await sink.store(receipt);
    const r2 = await sink.store(receipt);
    expect(r1.success).toBe(true);
    expect(r2.success).toBe(true);
    expect(r1.receiptId).toBe(r2.receiptId);
  });
});
