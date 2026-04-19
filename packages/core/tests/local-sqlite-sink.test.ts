import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { LocalSQLiteSink } from "../src/sinks/local-sqlite-sink.js";
import type { Receipt } from "../src/types.js";

function makeReceipt(id = "test-001"): Receipt {
  return {
    spec_version: "1.3",
    tool_version: "sanna-ts/1.3.0",
    checks_version: "8",
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
  } as Receipt;
}

let tmpDir: string;
let sink: LocalSQLiteSink;

describe("LocalSQLiteSink", () => {
  afterEach(async () => {
    await sink?.close();
    if (tmpDir) {
      try { rmSync(tmpDir, { recursive: true }); } catch {}
    }
  });

  function createSink(): LocalSQLiteSink {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-sqlite-test-"));
    sink = new LocalSQLiteSink(join(tmpDir, "receipts.db"));
    return sink;
  }

  it("should store a receipt and return success", async () => {
    const s = createSink();
    const result = await s.store(makeReceipt());
    expect(result.success).toBe(true);
    expect(result.receiptId).toBe("test-001");
  });

  it("should store multiple receipts", async () => {
    const s = createSink();
    await s.store(makeReceipt("r1"));
    await s.store(makeReceipt("r2"));
    await s.store(makeReceipt("r3"));

    const store = s.getStore();
    const all = store.query({});
    expect(all).toHaveLength(3);
  });

  it("should return the underlying ReceiptStore", async () => {
    const s = createSink();
    expect(s.getStore()).toBeDefined();
    expect(typeof s.getStore().save).toBe("function");
  });

  it("storeBatch should store all receipts", async () => {
    const s = createSink();
    const receipts = [makeReceipt("b1"), makeReceipt("b2"), makeReceipt("b3")];
    const results = await s.storeBatch(receipts);
    expect(results).toHaveLength(3);
    expect(results.every((r) => r.success)).toBe(true);
  });

  it("flush should resolve without error", async () => {
    const s = createSink();
    await expect(s.flush()).resolves.toBeUndefined();
  });

  it("close should not throw", async () => {
    const s = createSink();
    await expect(s.close()).resolves.toBeUndefined();
  });

  it("should persist receipt data correctly", async () => {
    const s = createSink();
    const receipt = makeReceipt("persist-test");
    await s.store(receipt);

    const store = s.getStore();
    const results = store.query({ correlation_id: "corr-001" });
    expect(results).toHaveLength(1);
    expect(results[0].receipt_id).toBe("persist-test");
  });

  it("should handle receipts with v1.1 fields", async () => {
    const s = createSink();
    const receipt = {
      ...makeReceipt("v11-test"),
      parent_receipts: ["parent-fp-1", "parent-fp-2"],
      workflow_id: "wf-001",
      content_mode: "full" as const,
      content_mode_source: "local_config",
    } as Receipt;
    const result = await s.store(receipt);
    expect(result.success).toBe(true);
  });
});
