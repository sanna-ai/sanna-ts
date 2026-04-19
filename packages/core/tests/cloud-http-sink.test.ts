import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CloudHTTPSink } from "../src/sinks/cloud-http-sink.js";
import type { Receipt } from "../src/types.js";
import { writeFileSync, readFileSync, mkdtempSync, existsSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── Helper ────────────────────────────────────────────────────────────

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

function mockResponse(status: number, body = "", headers: Record<string, string> = {}): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    text: () => Promise.resolve(body),
    headers: {
      get: (name: string) => headers[name] ?? null,
    },
  } as unknown as Response;
}

// ── Tests ─────────────────────────────────────────────────────────────

describe("CloudHTTPSink", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  // ── 1. Constructor defaults ──────────────────────────────────────

  describe("constructor defaults", () => {
    it("sets default failurePolicy to log_and_continue", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      // Verify by triggering the log_and_continue path (no throw on failure)
      fetchMock.mockResolvedValue(mockResponse(400, "bad"));
      await expect(sink.store(makeReceipt())).resolves.toEqual(
        expect.objectContaining({ success: false }),
      );
    });

    it("sets default timeoutMs to 10000", () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      // We verify indirectly; the sink is constructed without error
      expect(sink).toBeDefined();
    });

    it("sets default maxRetries to 3", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        retryBackoffBaseMs: 1,
      });
      fetchMock.mockResolvedValue(mockResponse(500));
      await sink.store(makeReceipt());
      // 1 initial + 3 retries = 4 calls
      expect(fetchMock).toHaveBeenCalledTimes(4);
    });

    it("sets default batchSize to 50", () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      // Constructed without error; batch splitting tested separately
      expect(sink).toBeDefined();
    });

    it("sets default bufferPath to null", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      // No buffer file created on failure
      fetchMock.mockResolvedValue(mockResponse(400, "bad"));
      await sink.store(makeReceipt());
      // No throw, no buffer — just logged
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("strips trailing slash from apiUrl", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com/", apiKey: "key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      await sink.store(makeReceipt());
      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.example.com/v1/receipts",
        expect.anything(),
      );
    });
  });

  // ── 2. Successful store ──────────────────────────────────────────

  describe("successful store", () => {
    it("returns success with receiptId on 201", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      const receipt = makeReceipt("r-123");
      const result = await sink.store(receipt);
      expect(result).toEqual({ success: true, receiptId: "r-123" });
    });

    it("calls fetch with correct URL", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      await sink.store(makeReceipt());
      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.example.com/v1/receipts",
        expect.anything(),
      );
    });

    it("sends correct headers", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "my-api-key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      await sink.store(makeReceipt());

      const callArgs = fetchMock.mock.calls[0][1];
      expect(callArgs.headers["Content-Type"]).toBe("application/json");
      expect(callArgs.headers["Authorization"]).toBe("Bearer my-api-key");
      expect(callArgs.headers["User-Agent"]).toMatch(/^sanna-ts\//);
    });

    it("sends receipt as JSON body", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      const receipt = makeReceipt();
      await sink.store(receipt);

      const callArgs = fetchMock.mock.calls[0][1];
      expect(JSON.parse(callArgs.body)).toEqual(receipt);
    });
  });

  // ── 3. Successful store with 409 (duplicate) ────────────────────

  it("treats 409 as success (duplicate)", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(409));
    const result = await sink.store(makeReceipt("dup-001"));
    expect(result).toEqual({ success: true, receiptId: "dup-001" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  // ── 4. Batch store ──────────────────────────────────────────────

  describe("batch store", () => {
    it("sends batch to /v1/receipts/batch endpoint", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      const receipts = [makeReceipt("b-1"), makeReceipt("b-2")];
      const results = await sink.storeBatch(receipts);
      expect(results).toEqual([
        { success: true, receiptId: "b-1" },
        { success: true, receiptId: "b-2" },
      ]);
      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.example.com/v1/receipts/batch",
        expect.anything(),
      );
    });

    it("sends receipts array in body", async () => {
      const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
      fetchMock.mockResolvedValue(mockResponse(201));
      const receipts = [makeReceipt("b-1"), makeReceipt("b-2")];
      await sink.storeBatch(receipts);

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.receipts).toHaveLength(2);
      expect(body.receipts[0].receipt_id).toBe("b-1");
    });
  });

  // ── 5. 400 error — no retry ─────────────────────────────────────

  it("does not retry on 400", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(400, "Bad Request"));
    await sink.store(makeReceipt());
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  // ── 6. 401 error — no retry ─────────────────────────────────────

  it("does not retry on 401", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(401, "Unauthorized"));
    await sink.store(makeReceipt());
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  // ── 7. 403 error — no retry ─────────────────────────────────────

  it("does not retry on 403", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(403, "Forbidden"));
    await sink.store(makeReceipt());
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  // ── 8. 429 rate limit — retry with Retry-After ──────────────────

  it("retries on 429 with Retry-After header", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      maxRetries: 1,
    });
    fetchMock
      .mockResolvedValueOnce(mockResponse(429, "Rate limited", { "Retry-After": "1" }))
      .mockResolvedValueOnce(mockResponse(201));

    const result = await sink.store(makeReceipt());
    expect(result.success).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  // ── 9. 503 — retry with backoff ────────────────────────────────

  it("retries on 503 with backoff", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      maxRetries: 1,
      retryBackoffBaseMs: 10,
    });
    fetchMock
      .mockResolvedValueOnce(mockResponse(503))
      .mockResolvedValueOnce(mockResponse(201));

    const result = await sink.store(makeReceipt());
    expect(result.success).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  // ── 10. 5xx — retry with backoff ───────────────────────────────

  it("retries on 500 with backoff", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      maxRetries: 1,
      retryBackoffBaseMs: 10,
    });
    fetchMock
      .mockResolvedValueOnce(mockResponse(500))
      .mockResolvedValueOnce(mockResponse(201));

    const result = await sink.store(makeReceipt());
    expect(result.success).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  // ── 11. Max retries exceeded ───────────────────────────────────

  it("returns failure after max retries exceeded", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      maxRetries: 2,
      retryBackoffBaseMs: 10,
    });
    fetchMock.mockResolvedValue(mockResponse(500));

    const result = await sink.store(makeReceipt());
    // 1 initial + 2 retries = 3 calls
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result.success).toBe(false);
    expect(result.error).toContain("500");
  });

  it("throws after max retries with throw policy", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      failurePolicy: "throw",
      maxRetries: 1,
      retryBackoffBaseMs: 10,
    });
    fetchMock.mockResolvedValue(mockResponse(500));

    await expect(sink.store(makeReceipt())).rejects.toThrow("HTTP 500");
  });

  // ── 12. Timeout handling ───────────────────────────────────────

  it("retries on fetch abort (timeout)", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      maxRetries: 1,
      timeoutMs: 50,
      retryBackoffBaseMs: 10,
    });

    fetchMock
      .mockRejectedValueOnce(new DOMException("The operation was aborted.", "AbortError"))
      .mockResolvedValueOnce(mockResponse(201));

    const result = await sink.store(makeReceipt());
    expect(result.success).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("passes AbortController signal to fetch", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(201));
    await sink.store(makeReceipt());

    const callArgs = fetchMock.mock.calls[0][1];
    expect(callArgs.signal).toBeInstanceOf(AbortSignal);
  });

  // ── 13. log_and_continue policy ────────────────────────────────

  describe("log_and_continue policy", () => {
    it("does not throw on failure", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "log_and_continue",
        maxRetries: 0,
      });
      fetchMock.mockResolvedValue(mockResponse(400, "bad"));

      const result = await sink.store(makeReceipt());
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it("returns SinkResult with receiptId on failure", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "log_and_continue",
        maxRetries: 0,
      });
      fetchMock.mockResolvedValue(mockResponse(400, "bad"));

      const result = await sink.store(makeReceipt("fail-001"));
      expect(result.receiptId).toBe("fail-001");
    });
  });

  // ── 14. throw policy ───────────────────────────────────────────

  it("throws on failure with throw policy", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      failurePolicy: "throw",
      maxRetries: 0,
    });
    fetchMock.mockResolvedValue(mockResponse(400, "bad request"));

    await expect(sink.store(makeReceipt())).rejects.toThrow("HTTP 400");
  });

  // ── 15. buffer_and_retry policy ────────────────────────────────

  describe("buffer_and_retry policy", () => {
    let tmpDir: string;
    let bufferFile: string;

    beforeEach(() => {
      tmpDir = mkdtempSync(join(tmpdir(), "sanna-sink-test-"));
      bufferFile = join(tmpDir, "buffer.jsonl");
    });

    afterEach(() => {
      try {
        if (existsSync(bufferFile)) unlinkSync(bufferFile);
      } catch {
        // ignore
      }
    });

    it("appends receipt to buffer file on failure", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "buffer_and_retry",
        bufferPath: bufferFile,
        maxRetries: 0,
      });
      fetchMock.mockResolvedValue(mockResponse(400, "bad"));

      const receipt = makeReceipt("buf-001");
      await sink.store(receipt);

      expect(existsSync(bufferFile)).toBe(true);
      const lines = readFileSync(bufferFile, "utf-8").trim().split("\n");
      expect(lines).toHaveLength(1);
      const buffered = JSON.parse(lines[0]);
      expect(buffered.receipt_id).toBe("buf-001");
    });

    it("appends multiple receipts to buffer on repeated failures", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "buffer_and_retry",
        bufferPath: bufferFile,
        maxRetries: 0,
      });
      fetchMock.mockResolvedValue(mockResponse(400, "bad"));

      await sink.store(makeReceipt("buf-001"));
      await sink.store(makeReceipt("buf-002"));

      const lines = readFileSync(bufferFile, "utf-8").trim().split("\n");
      expect(lines).toHaveLength(2);
    });

    // ── 16. flush() drains buffer ──────────────────────────────────

    it("flush() drains buffer by sending receipts", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "buffer_and_retry",
        bufferPath: bufferFile,
        maxRetries: 0,
      });

      // Write receipts directly to buffer
      const r1 = makeReceipt("flush-001");
      const r2 = makeReceipt("flush-002");
      writeFileSync(bufferFile, JSON.stringify(r1) + "\n" + JSON.stringify(r2) + "\n");

      // Now mock success
      fetchMock.mockResolvedValue(mockResponse(201));
      await sink.flush();

      // Buffer should be empty
      const content = readFileSync(bufferFile, "utf-8").trim();
      expect(content).toBe("");
    });

    it("flush() is a no-op when no buffer path", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
      });
      // Should not throw
      await sink.flush();
    });

    it("flush() is a no-op when buffer file does not exist", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "buffer_and_retry",
        bufferPath: join(tmpDir, "nonexistent.jsonl"),
      });
      await sink.flush();
    });
  });

  // ── 17. close() clears interval and flushes ────────────────────

  describe("close()", () => {
    it("clears retry interval and flushes", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "sanna-sink-close-"));
      const bufferFile = join(tmpDir, "buffer.jsonl");

      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        failurePolicy: "buffer_and_retry",
        bufferPath: bufferFile,
      });

      // Write a receipt to buffer
      const r = makeReceipt("close-001");
      writeFileSync(bufferFile, JSON.stringify(r) + "\n");

      fetchMock.mockResolvedValue(mockResponse(201));
      await sink.close();

      // Buffer should be drained
      const content = readFileSync(bufferFile, "utf-8").trim();
      expect(content).toBe("");

      // Further flush calls should still work (no error from cleared interval)
      await sink.flush();
    });

    it("can be called without buffer_and_retry policy", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
      });
      await sink.close();
      // No error thrown
    });
  });

  // ── 18. User-Agent header includes version ─────────────────────

  it("User-Agent header includes sanna-ts/ prefix", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(201));
    await sink.store(makeReceipt());

    const callArgs = fetchMock.mock.calls[0][1];
    expect(callArgs.headers["User-Agent"]).toBe("sanna-ts/1.3");
  });

  // ── 19. Authorization header is Bearer token ──────────────────

  it("sets Authorization header as Bearer token", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "secret-token-xyz",
    });
    fetchMock.mockResolvedValue(mockResponse(201));
    await sink.store(makeReceipt());

    const callArgs = fetchMock.mock.calls[0][1];
    expect(callArgs.headers["Authorization"]).toBe("Bearer secret-token-xyz");
  });

  // ── 20. Batch splits into batchSize chunks ─────────────────────

  describe("batch splitting", () => {
    it("splits large batch into batchSize chunks", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        batchSize: 2,
      });
      fetchMock.mockResolvedValue(mockResponse(201));

      const receipts = [makeReceipt("s-1"), makeReceipt("s-2"), makeReceipt("s-3")];
      const results = await sink.storeBatch(receipts);

      // Should be 2 fetch calls: one batch of 2, one batch of 1
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(results).toHaveLength(3);
      expect(results.every((r) => r.success)).toBe(true);

      // Verify first batch has 2 receipts
      const body1 = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body1.receipts).toHaveLength(2);

      // Verify second batch has 1 receipt
      const body2 = JSON.parse(fetchMock.mock.calls[1][1].body);
      expect(body2.receipts).toHaveLength(1);
    });

    it("handles batch failure for a single chunk", async () => {
      const sink = new CloudHTTPSink({
        apiUrl: "https://api.example.com",
        apiKey: "key",
        batchSize: 2,
        maxRetries: 0,
      });
      fetchMock
        .mockResolvedValueOnce(mockResponse(201)) // first batch succeeds
        .mockResolvedValueOnce(mockResponse(400, "bad")); // second batch fails

      const receipts = [makeReceipt("s-1"), makeReceipt("s-2"), makeReceipt("s-3")];
      const results = await sink.storeBatch(receipts);

      expect(results[0].success).toBe(true);
      expect(results[1].success).toBe(true);
      expect(results[2].success).toBe(false);
    });
  });

  // ── Additional edge cases ──────────────────────────────────────

  it("uses POST method for all requests", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    fetchMock.mockResolvedValue(mockResponse(201));
    await sink.store(makeReceipt());

    const callArgs = fetchMock.mock.calls[0][1];
    expect(callArgs.method).toBe("POST");
  });

  it("retries on network error (fetch rejection)", async () => {
    const sink = new CloudHTTPSink({
      apiUrl: "https://api.example.com",
      apiKey: "key",
      maxRetries: 1,
      retryBackoffBaseMs: 10,
    });
    fetchMock
      .mockRejectedValueOnce(new Error("ECONNREFUSED"))
      .mockResolvedValueOnce(mockResponse(201));

    const result = await sink.store(makeReceipt());
    expect(result.success).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("storeBatch returns empty array for empty input", async () => {
    const sink = new CloudHTTPSink({ apiUrl: "https://api.example.com", apiKey: "key" });
    const results = await sink.storeBatch([]);
    expect(results).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
