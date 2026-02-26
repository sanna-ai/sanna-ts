import { describe, it, expect, vi } from "vitest";
import { receiptToSpan, SannaSpanExporter } from "../src/otel-exporter.js";
import { generateReceipt, hashObj } from "../src/index.js";

// ── Mock OTel types ──────────────────────────────────────────────────

function createMockSpan() {
  const attributes: Record<string, string | number | boolean> = {};
  let status: { code: number; message?: string } = { code: 0 };
  let ended = false;

  return {
    setAttribute: vi.fn((key: string, value: string | number | boolean) => {
      attributes[key] = value;
      return mockSpan;
    }),
    setStatus: vi.fn((s: { code: number; message?: string }) => {
      status = s;
      return mockSpan;
    }),
    end: vi.fn(() => {
      ended = true;
    }),
    // Test helpers
    _attributes: attributes,
    _getStatus: () => status,
    _isEnded: () => ended,
  };

  // Self-reference for chaining
  var mockSpan: ReturnType<typeof createMockSpan>;
  mockSpan = undefined as any; // will be assigned by closure
}

function createMockTracer() {
  const spans: ReturnType<typeof createMockSpan>[] = [];

  return {
    startSpan: vi.fn((_name: string, _options?: unknown) => {
      const span = createMockSpan();
      spans[spans.length] = span;
      return span;
    }),
    _spans: spans,
  };
}

// ── Test receipt helpers ─────────────────────────────────────────────

function makeReceipt(overrides?: Record<string, unknown>): Record<string, unknown> {
  const receipt = generateReceipt({
    correlation_id: "sanna-test-otel-001",
    inputs: { query: "What is the refund policy?", context: "Refunds within 30 days." },
    outputs: { response: "Refunds are available within 30 days." },
    checks: [
      { check_id: "C1", name: "Context Grounding", passed: true, severity: "info", evidence: null },
      { check_id: "C2", name: "Mark Inferences", passed: false, severity: "warning", evidence: "Unmarked claim" },
    ],
    constitution_ref: {
      document_id: "test-agent/1.0",
      policy_hash: "a".repeat(64),
    },
  });
  return { ...receipt, ...overrides } as Record<string, unknown>;
}

// ── Tests ────────────────────────────────────────────────────────────

describe("receiptToSpan", () => {
  it("should create a span with correct attributes", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt();
    const span = receiptToSpan(receipt, tracer as any);

    expect(tracer.startSpan).toHaveBeenCalledWith("sanna.governance.test-agent");
    expect(span.setAttribute).toHaveBeenCalled();

    const attrs = (span as any)._attributes;
    expect(attrs["sanna.receipt_id"]).toBe(receipt.receipt_id);
    expect(attrs["sanna.correlation_id"]).toBe("sanna-test-otel-001");
    expect(attrs["sanna.status"]).toBe(receipt.status);
    expect(attrs["sanna.spec_version"]).toBeTruthy();
    expect(attrs["sanna.checks_passed"]).toBeTypeOf("number");
    expect(attrs["sanna.checks_failed"]).toBeTypeOf("number");
    expect(attrs["sanna.receipt_fingerprint"]).toBeTruthy();
    expect(span.end).toHaveBeenCalled();
  });

  it("should set OK status for PASS receipt", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt({ status: "PASS" });
    const span = receiptToSpan(receipt, tracer as any);

    expect(span.setStatus).toHaveBeenCalledWith({ code: 1 }); // SpanStatusCode.OK
  });

  it("should set ERROR status for FAIL receipt", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt({ status: "FAIL" });
    const span = receiptToSpan(receipt, tracer as any);

    expect(span.setStatus).toHaveBeenCalledWith({
      code: 2, // SpanStatusCode.ERROR
      message: "Governance check failed",
    });
  });

  it("should compute content hash", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt();
    receiptToSpan(receipt, tracer as any);

    const attrs = tracer._spans[0]._attributes;
    const hash = attrs["sanna.content_hash"] as string;

    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).toBe(hashObj(receipt));
  });

  it("should include artifact URI when provided", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt();
    receiptToSpan(receipt, tracer as any, {
      artifactUri: "s3://governance/receipts/001.json",
    });

    const attrs = tracer._spans[0]._attributes;
    expect(attrs["sanna.artifact_uri"]).toBe("s3://governance/receipts/001.json");
  });

  it("should extract agent name from constitution_ref", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt();
    receiptToSpan(receipt, tracer as any);

    const attrs = tracer._spans[0]._attributes;
    expect(attrs["sanna.agent_name"]).toBe("test-agent");
    expect(tracer.startSpan).toHaveBeenCalledWith("sanna.governance.test-agent");
  });

  it("should map individual check statuses", () => {
    const tracer = createMockTracer();
    const receipt = makeReceipt({
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
        { check_id: "C2", passed: false, severity: "warning", evidence: "issue" },
        // C3 absent
      ],
    });
    receiptToSpan(receipt, tracer as any);

    const attrs = tracer._spans[0]._attributes;
    expect(attrs["sanna.c1"]).toBe("pass");
    expect(attrs["sanna.c2"]).toBe("fail");
    expect(attrs["sanna.c3"]).toBe("absent");
    expect(attrs["sanna.c4"]).toBe("absent");
    expect(attrs["sanna.c5"]).toBe("absent");
  });

  it("should handle receipt without optional fields", () => {
    const tracer = createMockTracer();
    const minimal: Record<string, unknown> = {
      receipt_id: "r-minimal",
      correlation_id: "corr-1",
      status: "PASS",
      spec_version: "1.0",
      checks_passed: 0,
      checks_failed: 0,
      receipt_fingerprint: "abc",
    };

    const span = receiptToSpan(minimal, tracer as any);

    expect(tracer.startSpan).toHaveBeenCalledWith("sanna.governance");
    expect(span.end).toHaveBeenCalled();

    const attrs = tracer._spans[0]._attributes;
    expect(attrs["sanna.receipt_id"]).toBe("r-minimal");
    expect(attrs["sanna.c1"]).toBe("absent");
    expect(attrs["sanna.content_hash"]).toMatch(/^[0-9a-f]{64}$/);
    // No agent_name attribute set (no constitution_ref)
    expect(attrs["sanna.agent_name"]).toBeUndefined();
  });
});

describe("SannaSpanExporter", () => {
  it("should export batch of receipts", () => {
    const tracer = createMockTracer();
    const exporter = new SannaSpanExporter(tracer as any);

    const receipts = [
      makeReceipt({ receipt_id: "r1" }),
      makeReceipt({ receipt_id: "r2" }),
      makeReceipt({ receipt_id: "r3" }),
    ];

    const spans = exporter.exportBatch(receipts);

    expect(spans).toHaveLength(3);
    expect(tracer.startSpan).toHaveBeenCalledTimes(3);

    // Each span should have been ended
    for (const span of spans) {
      expect(span.end).toHaveBeenCalled();
    }
  });
});
