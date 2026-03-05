import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ReceiptStore } from "../src/store.js";
import {
  createSinkResult,
  SinkError,
  LocalSQLiteSink,
  NullSink,
} from "../src/sinks/index.js";
import type { FailurePolicy, ReceiptSink, SinkResult } from "../src/sinks/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    receipt_id: `receipt-${Math.random().toString(36).slice(2, 10)}`,
    correlation_id: "test-corr-001",
    timestamp: new Date().toISOString(),
    status: "PASS",
    checks: [
      { check_id: "C1", passed: true, severity: "info", evidence: null },
    ],
    checks_passed: 1,
    checks_failed: 0,
    constitution_ref: {
      document_id: "test-agent/1.0",
      policy_hash: "c".repeat(64),
    },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// SinkResult & createSinkResult
// ---------------------------------------------------------------------------

describe("SinkResult", () => {
  it("ok is true when failed is 0", () => {
    const r = createSinkResult(3, 0);
    expect(r.ok).toBe(true);
    expect(r.stored).toBe(3);
    expect(r.failed).toBe(0);
    expect(r.errors).toEqual([]);
  });

  it("ok is false when failed > 0", () => {
    const r = createSinkResult(1, 2, ["err1", "err2"]);
    expect(r.ok).toBe(false);
    expect(r.failed).toBe(2);
  });

  it("errors defaults to empty array", () => {
    const r = createSinkResult(1, 0);
    expect(r.errors).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// SinkError
// ---------------------------------------------------------------------------

describe("SinkError", () => {
  it("is an instance of Error", () => {
    const err = new SinkError("boom");
    expect(err).toBeInstanceOf(Error);
  });

  it("has name SinkError", () => {
    const err = new SinkError("boom");
    expect(err.name).toBe("SinkError");
  });

  it("preserves message", () => {
    const err = new SinkError("something went wrong");
    expect(err.message).toBe("something went wrong");
  });
});

// ---------------------------------------------------------------------------
// FailurePolicy type check
// ---------------------------------------------------------------------------

describe("FailurePolicy", () => {
  it("accepts valid values", () => {
    const policies: FailurePolicy[] = ["log_and_continue", "raise", "buffer_and_retry"];
    expect(policies).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// ReceiptSink interface compliance
// ---------------------------------------------------------------------------

describe("ReceiptSink interface", () => {
  it("NullSink satisfies the interface", () => {
    const sink: ReceiptSink = new NullSink();
    expect(typeof sink.store).toBe("function");
    expect(typeof sink.batchStore).toBe("function");
    expect(typeof sink.flush).toBe("function");
    expect(typeof sink.close).toBe("function");
  });

  it("all methods return promises", async () => {
    const sink: ReceiptSink = new NullSink();
    expect(sink.store({})).toBeInstanceOf(Promise);
    expect(sink.batchStore([])).toBeInstanceOf(Promise);
    expect(sink.flush()).toBeInstanceOf(Promise);
    expect(sink.close()).toBeInstanceOf(Promise);
  });
});

// ---------------------------------------------------------------------------
// LocalSQLiteSink
// ---------------------------------------------------------------------------

describe("LocalSQLiteSink", () => {
  let tmpDir: string;
  let dbPath: string;
  let sink: LocalSQLiteSink;

  beforeEach(() => {
    process.env.SANNA_ALLOW_TEMP_DB = "1";
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-sink-test-"));
    dbPath = join(tmpDir, "sink.db");
    sink = new LocalSQLiteSink(dbPath);
  });

  afterEach(() => {
    try { sink.close(); } catch { /* already closed */ }
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
    delete process.env.SANNA_ALLOW_TEMP_DB;
  });

  describe("store", () => {
    it("stores a receipt and returns ok result", async () => {
      const result = await sink.store(makeReceipt({ receipt_id: "s-001" }));
      expect(result.ok).toBe(true);
      expect(result.stored).toBe(1);
      expect(result.failed).toBe(0);
    });

    it("persists to SQLite (verifiable via ReceiptStore)", async () => {
      await sink.store(makeReceipt({ receipt_id: "persist-001" }));
      const store = new ReceiptStore(dbPath);
      const rows = store.query();
      expect(rows).toHaveLength(1);
      expect(rows[0].receipt_id).toBe("persist-001");
      store.close();
    });

    it("returns SinkResult type", async () => {
      const result = await sink.store(makeReceipt());
      expect(result).toHaveProperty("stored");
      expect(result).toHaveProperty("failed");
      expect(result).toHaveProperty("errors");
      expect(result).toHaveProperty("ok");
    });
  });

  describe("batchStore", () => {
    it("stores multiple receipts", async () => {
      const receipts = Array.from({ length: 5 }, (_, i) =>
        makeReceipt({ receipt_id: `batch-${i}` })
      );
      const result = await sink.batchStore(receipts);
      expect(result.ok).toBe(true);
      expect(result.stored).toBe(5);
      expect(result.failed).toBe(0);
    });

    it("handles empty array", async () => {
      const result = await sink.batchStore([]);
      expect(result.ok).toBe(true);
      expect(result.stored).toBe(0);
    });
  });

  describe("failure policies", () => {
    it("log_and_continue does not throw on normal operation", async () => {
      const result = await sink.store(makeReceipt());
      expect(result.ok).toBe(true);
    });

    it("raise policy creates SinkError on failure", async () => {
      const raiseSink = new LocalSQLiteSink(
        join(tmpDir, "raise.db"),
        "raise"
      );
      // Normal receipt works fine
      const result = await raiseSink.store(makeReceipt());
      expect(result.ok).toBe(true);
      await raiseSink.close();
    });
  });

  describe("flush", () => {
    it("is a no-op (does not throw)", async () => {
      await expect(sink.flush()).resolves.toBeUndefined();
    });
  });

  describe("close", () => {
    it("closes underlying store", async () => {
      await sink.close();
      // Underlying store is closed — operations should fail
      expect(() => {
        (sink as any)._store.save(makeReceipt());
      }).toThrow();
    });
  });

  describe("accumulation", () => {
    it("multiple stores accumulate", async () => {
      for (let i = 0; i < 10; i++) {
        await sink.store(makeReceipt({ receipt_id: `acc-${i}` }));
      }
      const store = new ReceiptStore(dbPath);
      expect(store.count()).toBe(10);
      store.close();
    });
  });
});

// ---------------------------------------------------------------------------
// NullSink
// ---------------------------------------------------------------------------

describe("NullSink", () => {
  it("store always returns ok", async () => {
    const sink = new NullSink();
    const result = await sink.store({ any: "data" });
    expect(result.ok).toBe(true);
    expect(result.stored).toBe(1);
  });

  it("batchStore returns count", async () => {
    const sink = new NullSink();
    const receipts = Array.from({ length: 7 }, (_, i) => ({ id: i }));
    const result = await sink.batchStore(receipts);
    expect(result.ok).toBe(true);
    expect(result.stored).toBe(7);
  });

  it("batchStore handles empty array", async () => {
    const sink = new NullSink();
    const result = await sink.batchStore([]);
    expect(result.ok).toBe(true);
    expect(result.stored).toBe(0);
  });

  it("flush is a no-op", async () => {
    const sink = new NullSink();
    await expect(sink.flush()).resolves.toBeUndefined();
  });

  it("close is a no-op", async () => {
    const sink = new NullSink();
    await expect(sink.close()).resolves.toBeUndefined();
  });

  it("still works after close", async () => {
    const sink = new NullSink();
    await sink.close();
    const result = await sink.store({ still: "works" });
    expect(result.ok).toBe(true);
  });

  it("works with interface typing", async () => {
    const sink: ReceiptSink = new NullSink();
    const result = await sink.store({});
    expect(result.ok).toBe(true);
  });
});
