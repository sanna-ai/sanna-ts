/**
 * Sanna OpenTelemetry exporter — convert receipts into OTel spans.
 *
 * Spans carry a pointer + integrity hash to the receipt, NOT the full
 * receipt JSON. This keeps span payloads small while preserving the
 * ability to verify artifact integrity from traces.
 *
 * This module uses dynamic imports for @opentelemetry/api — it is an
 * optional peer dependency. Import will throw if OTel is not installed.
 *
 * Usage:
 *   import { receiptToSpan, SannaSpanExporter } from "@sanna-ai/core";
 *   const tracer = trace.getTracer("sanna");
 *   receiptToSpan(receipt, tracer, { artifactUri: "s3://bucket/receipt.json" });
 */

import { hashObj } from "./hashing.js";

// ── OTel types (duck-typed to avoid hard dependency) ────────────────

interface Span {
  setAttribute(key: string, value: string | number | boolean): this;
  setStatus(status: { code: number; message?: string }): this;
  end(): void;
}

interface SpanOptions {
  attributes?: Record<string, string | number | boolean>;
}

interface Tracer {
  startSpan(name: string, options?: SpanOptions): Span;
}

// SpanStatusCode values per OTel spec
const SpanStatusCode = {
  UNSET: 0,
  OK: 1,
  ERROR: 2,
} as const;

// ── Check status mapping ─────────────────────────────────────────────

const CHECK_ID_MAP: Record<string, string> = {
  C1: "c1",
  C2: "c2",
  C3: "c3",
  C4: "c4",
  C5: "c5",
  "sanna.context_contradiction": "c1",
  "sanna.unmarked_inference": "c2",
  "sanna.false_certainty": "c3",
  "sanna.conflict_collapse": "c4",
  "sanna.premature_compression": "c5",
};

function extractCheckStatuses(
  checks: Record<string, unknown>[],
): Record<string, string> {
  const found: Record<string, string> = {};

  for (const check of checks) {
    const checkId = String(check.check_id ?? "");
    const checkImpl = String(check.check_impl ?? "");

    const key = CHECK_ID_MAP[checkId] ?? CHECK_ID_MAP[checkImpl];
    if (!key) continue;
    if (found[key]) continue; // first match wins

    found[key] = check.passed ? "pass" : "fail";
  }

  return found;
}

// ── Public API ───────────────────────────────────────────────────────

export interface ReceiptSpanOptions {
  artifactUri?: string;
  parentSpan?: Span;
  additionalAttributes?: Record<string, string | number | boolean>;
}

/**
 * Convert a governance receipt into an OpenTelemetry span.
 *
 * The span carries a pointer + integrity hash, not the full receipt.
 */
export function receiptToSpan(
  receipt: Record<string, unknown>,
  tracer: Tracer,
  options: ReceiptSpanOptions = {},
): Span {
  // Extract agent name from constitution_ref if present
  const constitutionRef = receipt.constitution_ref as
    | Record<string, unknown>
    | undefined;
  let agentName: string | undefined;
  if (constitutionRef?.document_id) {
    const docId = String(constitutionRef.document_id);
    // document_id format: "agent-name/version"
    const slashIdx = docId.indexOf("/");
    agentName = slashIdx > 0 ? docId.slice(0, slashIdx) : docId;
  }

  const spanName = agentName
    ? `sanna.governance.${agentName}`
    : "sanna.governance";

  const span = tracer.startSpan(spanName);

  // Core receipt attributes
  span.setAttribute("sanna.receipt_id", String(receipt.receipt_id ?? ""));
  span.setAttribute(
    "sanna.correlation_id",
    String(receipt.correlation_id ?? ""),
  );
  span.setAttribute("sanna.status", String(receipt.status ?? ""));
  span.setAttribute("sanna.spec_version", String(receipt.spec_version ?? ""));
  span.setAttribute("sanna.checks_passed", Number(receipt.checks_passed ?? 0));
  span.setAttribute("sanna.checks_failed", Number(receipt.checks_failed ?? 0));
  span.setAttribute(
    "sanna.receipt_fingerprint",
    String(receipt.receipt_fingerprint ?? ""),
  );

  // Content hash — SHA-256 of canonical JSON of the entire receipt
  const contentHash = hashObj(receipt);
  span.setAttribute("sanna.content_hash", contentHash);

  // Artifact URI
  if (options.artifactUri) {
    span.setAttribute("sanna.artifact_uri", options.artifactUri);
  }

  // Agent name
  if (agentName) {
    span.setAttribute("sanna.agent_name", agentName);
  }

  // Individual check statuses (C1-C5)
  const checks = (receipt.checks ?? []) as Record<string, unknown>[];
  const checkStatuses = extractCheckStatuses(checks);
  for (const n of ["c1", "c2", "c3", "c4", "c5"]) {
    span.setAttribute(`sanna.${n}`, checkStatuses[n] ?? "absent");
  }

  // Additional attributes
  if (options.additionalAttributes) {
    for (const [key, value] of Object.entries(options.additionalAttributes)) {
      span.setAttribute(key, value);
    }
  }

  // Span status
  const status = String(receipt.status ?? "");
  if (status === "FAIL") {
    span.setStatus({ code: SpanStatusCode.ERROR, message: "Governance check failed" });
  } else {
    span.setStatus({ code: SpanStatusCode.OK });
  }

  span.end();
  return span;
}

// ── SannaSpanExporter ────────────────────────────────────────────────

export class SannaSpanExporter {
  private _tracer: Tracer;

  constructor(tracer: Tracer) {
    this._tracer = tracer;
  }

  /** Export a single receipt as a span. */
  exportReceipt(
    receipt: Record<string, unknown>,
    options?: ReceiptSpanOptions,
  ): Span {
    return receiptToSpan(receipt, this._tracer, options);
  }

  /** Export multiple receipts, each as its own span. */
  exportBatch(
    receipts: Record<string, unknown>[],
    options?: ReceiptSpanOptions,
  ): Span[] {
    return receipts.map((r) => receiptToSpan(r, this._tracer, options));
  }
}
