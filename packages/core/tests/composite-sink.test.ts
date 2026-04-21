import { describe, it, expect, vi } from "vitest";
import type { Receipt, ReceiptSink, SinkResult } from "../src/types.js";
import { CompositeSink } from "../src/sinks/composite-sink.js";

function makeReceipt(id = "test-001"): Receipt {
  return {
    spec_version: "1.4",
    tool_version: "1.4.0",
    checks_version: "9",
    receipt_id: id,
    receipt_fingerprint: "a".repeat(16),
    full_fingerprint: "b".repeat(64),
    correlation_id: "corr-001",
    timestamp: new Date().toISOString(),
    inputs: { query: "test" },
    outputs: { response: "test" },
    context_hash: "c".repeat(64),
    output_hash: "d".repeat(64),
    checks: [],
    checks_passed: 0,
    checks_failed: 0,
    status: "PASS",
    enforcement_surface: "middleware",
    invariants_scope: "full",
    tool_name: "sanna-ts",
  } as Receipt;
}

function mockSink(overrides: Partial<ReceiptSink> = {}): ReceiptSink {
  return {
    store: vi.fn().mockResolvedValue({ success: true, receiptId: "test-001" }),
    ...overrides,
  };
}

describe("CompositeSink", () => {
  it("store fans out to all sinks", async () => {
    const s1 = mockSink();
    const s2 = mockSink();
    const composite = new CompositeSink([s1, s2]);
    const receipt = makeReceipt();

    await composite.store(receipt);

    expect(s1.store).toHaveBeenCalledWith(receipt);
    expect(s2.store).toHaveBeenCalledWith(receipt);
  });

  it("store returns success when all succeed", async () => {
    const s1 = mockSink();
    const s2 = mockSink();
    const composite = new CompositeSink([s1, s2]);

    const result = await composite.store(makeReceipt());

    expect(result.success).toBe(true);
    expect(result.receiptId).toBe("test-001");
  });

  it("store returns failure with aggregated errors when one fails", async () => {
    const s1 = mockSink();
    const s2 = mockSink({
      store: vi.fn().mockResolvedValue({ success: false, error: "disk full" }),
    });
    const composite = new CompositeSink([s1, s2]);

    const result = await composite.store(makeReceipt());

    expect(result.success).toBe(false);
    expect(result.error).toContain("disk full");
  });

  it("store returns failure when one sink throws", async () => {
    const s1 = mockSink();
    const s2 = mockSink({
      store: vi.fn().mockRejectedValue(new Error("connection refused")),
    });
    const composite = new CompositeSink([s1, s2]);

    const result = await composite.store(makeReceipt());

    expect(result.success).toBe(false);
    expect(result.error).toContain("connection refused");
  });

  it("failure isolation — one sink failing does not prevent others", async () => {
    const s1 = mockSink({
      store: vi.fn().mockRejectedValue(new Error("boom")),
    });
    const s2 = mockSink();
    const composite = new CompositeSink([s1, s2]);

    await composite.store(makeReceipt());

    expect(s1.store).toHaveBeenCalled();
    expect(s2.store).toHaveBeenCalled();
  });

  it("storeBatch delegates to each sink's storeBatch", async () => {
    const batchResult: SinkResult[] = [
      { success: true, receiptId: "r1" },
      { success: true, receiptId: "r2" },
    ];
    const s1 = mockSink({ storeBatch: vi.fn().mockResolvedValue(batchResult) });
    const s2 = mockSink({ storeBatch: vi.fn().mockResolvedValue(batchResult) });
    const composite = new CompositeSink([s1, s2]);
    const receipts = [makeReceipt("r1"), makeReceipt("r2")];

    const results = await composite.storeBatch(receipts);

    expect(s1.storeBatch).toHaveBeenCalledWith(receipts);
    expect(s2.storeBatch).toHaveBeenCalledWith(receipts);
    expect(results).toHaveLength(2);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it("storeBatch falls back to individual store if no storeBatch", async () => {
    const s1 = mockSink(); // no storeBatch
    const composite = new CompositeSink([s1]);
    const receipts = [makeReceipt("r1"), makeReceipt("r2")];

    const results = await composite.storeBatch(receipts);

    expect(s1.store).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(2);
  });

  it("storeBatch aggregates errors per receipt", async () => {
    const s1 = mockSink({
      storeBatch: vi.fn().mockResolvedValue([
        { success: true, receiptId: "r1" },
        { success: false, error: "s1 fail on r2", receiptId: "r2" },
      ]),
    });
    const s2 = mockSink({
      storeBatch: vi.fn().mockResolvedValue([
        { success: true, receiptId: "r1" },
        { success: true, receiptId: "r2" },
      ]),
    });
    const composite = new CompositeSink([s1, s2]);

    const results = await composite.storeBatch([makeReceipt("r1"), makeReceipt("r2")]);

    expect(results[0].success).toBe(true);
    expect(results[1].success).toBe(false);
    expect(results[1].error).toContain("s1 fail on r2");
  });

  it("flush calls all sinks' flush", async () => {
    const flush1 = vi.fn().mockResolvedValue(undefined);
    const flush2 = vi.fn().mockResolvedValue(undefined);
    const s1 = mockSink({ flush: flush1 });
    const s2 = mockSink({ flush: flush2 });
    const composite = new CompositeSink([s1, s2]);

    await composite.flush();

    expect(flush1).toHaveBeenCalled();
    expect(flush2).toHaveBeenCalled();
  });

  it("flush handles sinks without flush method", async () => {
    const s1 = mockSink(); // no flush
    const composite = new CompositeSink([s1]);

    await expect(composite.flush()).resolves.toBeUndefined();
  });

  it("close calls all sinks' close", async () => {
    const close1 = vi.fn().mockResolvedValue(undefined);
    const close2 = vi.fn().mockResolvedValue(undefined);
    const s1 = mockSink({ close: close1 });
    const s2 = mockSink({ close: close2 });
    const composite = new CompositeSink([s1, s2]);

    await composite.close();

    expect(close1).toHaveBeenCalled();
    expect(close2).toHaveBeenCalled();
  });

  it("close handles sinks without close method", async () => {
    const s1 = mockSink(); // no close
    const composite = new CompositeSink([s1]);

    await expect(composite.close()).resolves.toBeUndefined();
  });

  it("empty sinks array — no errors on store/flush/close", async () => {
    const composite = new CompositeSink([]);

    const storeResult = await composite.store(makeReceipt());
    expect(storeResult.success).toBe(true);

    await expect(composite.flush()).resolves.toBeUndefined();
    await expect(composite.close()).resolves.toBeUndefined();
  });

  it("three sinks — two succeed, one fails — error includes only failed sink", async () => {
    const s1 = mockSink();
    const s2 = mockSink({
      store: vi.fn().mockResolvedValue({ success: false, error: "s2 error" }),
    });
    const s3 = mockSink();
    const composite = new CompositeSink([s1, s2, s3]);

    const result = await composite.store(makeReceipt());

    expect(result.success).toBe(false);
    expect(result.error).toBe("s2 error");
  });

  it("Promise.allSettled parallelism — sinks called concurrently", async () => {
    const callOrder: number[] = [];

    const s1 = mockSink({
      store: vi.fn().mockImplementation(async () => {
        callOrder.push(1);
        await new Promise((r) => setTimeout(r, 50));
        callOrder.push(11);
        return { success: true };
      }),
    });
    const s2 = mockSink({
      store: vi.fn().mockImplementation(async () => {
        callOrder.push(2);
        await new Promise((r) => setTimeout(r, 10));
        callOrder.push(22);
        return { success: true };
      }),
    });
    const composite = new CompositeSink([s1, s2]);

    await composite.store(makeReceipt());

    // Both sinks should start before either finishes
    expect(callOrder[0]).toBe(1);
    expect(callOrder[1]).toBe(2);
    // s2 finishes before s1 due to shorter delay
    expect(callOrder[2]).toBe(22);
    expect(callOrder[3]).toBe(11);
  });
});
