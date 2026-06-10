# Cookbook

Focused recipes for flows not already covered in the README quickstarts. For `sannaObserve` basics and the gateway setup, see the [README Quick Start sections](../README.md#quick-start--library-mode).

## 1. Subprocess and Fetch Interceptors

Enforce governance on `child_process` and `fetch` calls without modifying call sites. Each intercepted call is evaluated against the constitution and produces a signed receipt.

```typescript
import {
  patchChildProcess, unpatchChildProcess,
  patchFetch, unpatchFetch,
  LocalSQLiteSink,
} from "@sanna-ai/core";

const CONSTITUTION = "constitution.yaml";
const AGENT_ID = "my-agent/1.0";
const sink = new LocalSQLiteSink(".sanna/receipts.db");

// Activate both interceptors before agent logic runs
await patchChildProcess({ constitutionPath: CONSTITUTION, sink, agentId: AGENT_ID, mode: "enforce" });
await patchFetch({ constitutionPath: CONSTITUTION, sink, agentId: AGENT_ID, mode: "enforce" });

try {
  // child_process calls are now governed
  const { execSync } = await import("node:child_process");
  const out = execSync("ls -la", { encoding: "utf-8" });
  console.log(out);

  // fetch calls are now governed (globalThis.fetch)
  const resp = await fetch("https://api.example.com/data");
  const data = await resp.json();
  console.log(data);
} catch (err) {
  // ---- child_process blocked (halt or escalate in enforce mode) ----
  // Throws NodeJS.ErrnoException { code: "ENOENT" }
  if ((err as NodeJS.ErrnoException).code === "ENOENT") {
    console.error("child_process call blocked by governance:", (err as Error).message);
    return;
  }

  // ---- fetch blocked via globalThis.fetch ----
  // Throws TypeError("fetch failed") with .cause = Error("connect ECONNREFUSED ...")
  if (err instanceof TypeError) {
    console.error("fetch call blocked by governance:", (err as TypeError).message);
    return;
  }

  // ---- fetch blocked via http.request / https.request ----
  // Throws NodeJS.ErrnoException { code: "ECONNREFUSED" }
  if ((err as NodeJS.ErrnoException).code === "ECONNREFUSED") {
    console.error("http.request blocked by governance:", (err as Error).message);
    return;
  }

  // Unexpected error
  throw err;
} finally {
  // Always unpatch in a finally block for clean teardown
  unpatchChildProcess();
  unpatchFetch();
}
```

**Enforcement modes:**

| Mode | Blocked calls | Receipt emitted |
|------|--------------|-----------------|
| `"enforce"` | Yes -- halted and escalated calls both throw (see error types above) | Yes |
| `"audit"` | No -- all calls execute regardless of policy | Yes |
| `"passthrough"` | No -- all calls execute | Yes |

In `"enforce"` mode, `escalate` decisions fail closed (same behavior as `halt`).

**Security model:** In-process monkeypatching -- defense-in-depth for cooperative code only. For untrusted or adversarial code, use the gateway (out-of-process MCP proxy).

**Error type heterogeneity:** The thrown types differ by surface and calling API. Write catch blocks by checking `err.code` or `instanceof TypeError`, not by class name. See [docs/ts-sdk-reference.md#thrown-error-types-when-blocked-enforce-mode](./ts-sdk-reference.md#thrown-error-types-when-blocked-enforce-mode) for the full matrix.

---

## 2. Register a Custom Invariant Evaluator

Add domain-specific checks alongside the built-in C1-C5 heuristics. The evaluator runs automatically when its invariant ID appears in the constitution.

### Step 1 -- Write and register the evaluator

```typescript
import { registerInvariantEvaluator, clearEvaluators } from "@sanna-ai/core";
import type { InvariantEvaluatorFn } from "@sanna-ai/core";

const checkNoSsn: InvariantEvaluatorFn = (context, output, constitution, checkConfig) => {
  const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/;
  const hasSsn = ssnPattern.test(output);
  return {
    check_id: "INV_NO_SSN",
    name: "No SSN in Output",
    passed: !hasSsn,
    severity: hasSsn ? "critical" : "info",
    evidence: hasSsn ? "SSN pattern detected in output" : null,
  };
};

registerInvariantEvaluator("INV_NO_SSN", checkNoSsn);
// Throws if "INV_NO_SSN" is already registered.
```

Raise an exception on internal evaluator failure (do not return a failed `CheckResult` -- that triggers a false halt). Errors are caught by the runtime and recorded as `status: "ERRORED"`.

**Test isolation:** Call `clearEvaluators()` in your test `afterEach` / `afterAll`. The registry is module-level; leaked registrations cause `Error: Evaluator already registered` in subsequent tests.

### Step 2 -- Add the invariant to the constitution

```yaml
invariants:
  - id: INV_NO_SSN
    rule: Never include Social Security Numbers in output
    enforcement: halt
```

### Step 3 -- Use with `sannaObserve`

```typescript
import { sannaObserve, SannaHaltError } from "@sanna-ai/core";
// registerInvariantEvaluator must be called before sannaObserve is invoked.

const myAgent = sannaObserve(
  (query: string, context: string): string => {
    return "Customer record processed.";
  },
  {
    constitutionPath: "constitution.yaml",
    constitutionPublicKeyPath: "~/.sanna/keys/<key-id>.pub",
    enforcementMode: "enforced",
  },
);

try {
  const result = myAgent("Show customer data", "Name: Alice");
  console.log(result.receipt.status);  // "PASS" if no SSN found
} catch (e) {
  if (e instanceof SannaHaltError) {
    console.error(`HALTED: ${e.message}`);
    // e.failedChecks includes the INV_NO_SSN result
  }
}
```

---

## 3. Drift Report

Analyze per-agent failure rate trends from stored receipts and identify agents approaching the failure threshold.

### Via the library

```typescript
import { ReceiptStore, DriftAnalyzer, formatDriftReport } from "@sanna-ai/core";

const store = new ReceiptStore(".sanna/receipts.db");
const analyzer = new DriftAnalyzer(store);

const report = analyzer.analyze(30, {
  threshold: 0.15,        // 15% failure rate = critical
  projectionDays: 90,     // how far ahead to project a breach
});

console.log(`Fleet status: ${report.fleet_status}`);

for (const agent of report.agents) {
  if (agent.status !== "HEALTHY") {
    console.log(`\nAgent: ${agent.agent_id}  status=${agent.status}`);
    for (const check of agent.checks) {
      if (check.status !== "HEALTHY") {
        console.log(
          `  ${check.check_id}: fail_rate=${(check.fail_rate * 100).toFixed(1)}%  ` +
          `slope=${check.trend_slope > 0 ? "+" : ""}${check.trend_slope.toFixed(4)}/day  ` +
          `breach_in=${check.projected_breach_days ?? "N/A"}d`
        );
      }
    }
  }
}

// Human-readable text summary
console.log(formatDriftReport(report));

store.close();
```

### Via the CLI

```bash
# Human-readable report
sanna drift-report --db .sanna/receipts.db --window 30

# JSON output for downstream processing
sanna drift-report --db .sanna/receipts.db --window 30 --json

# Filter to a single agent
sanna drift-report --db .sanna/receipts.db --agent support-agent
```

### Multi-window analysis

```typescript
const reports = analyzer.analyzeMulti([7, 30, 90], { threshold: 0.15 });
for (const report of reports) {
  console.log(`${report.window_days}d: ${report.fleet_status}`);
}
```

### Export to file

```typescript
import { exportDriftReport } from "@sanna-ai/core";

// JSON
const json = exportDriftReport(report, "json");
// CSV (one row per agent + check combination)
const csv = exportDriftReport(report, "csv");
```

---

## 4. Evidence Bundle: Create and Verify

Evidence bundles are self-contained zip archives for auditors, regulators, and third parties -- receipt, constitution, and public key(s) in one file. Verification requires no network access.

### Create the bundle

```typescript
import { createBundle } from "@sanna-ai/core";

const bundlePath = createBundle({
  receiptPath: "receipt.json",
  constitutionPath: "constitution.yaml",
  publicKeyPath: "~/.sanna/keys/<key-id>.pub",
  outputPath: "evidence.zip",
  description: "Q2 2026 governance audit -- support-agent",
  // Optional: include constitution signer's key if different from receipt signer
  constitutionPublicKeyPath: "~/.sanna/keys/<author-key-id>.pub",
});
console.log(`Bundle created: ${bundlePath}`);
```

The receipt must be signed (`receipt_signature` present) and the constitution must be Ed25519-signed (`provenance.signature` present). Both conditions are enforced by `createBundle`.

### Verify the bundle

```typescript
import { verifyBundle } from "@sanna-ai/core";

const result = verifyBundle("evidence.zip");
console.log(`Valid: ${result.valid}`);
for (const check of result.checks) {
  const status = check.passed ? "PASS" : "FAIL";
  console.log(`  [${status}] ${check.name}: ${check.detail}`);
}

if (result.errors.length > 0) {
  for (const err of result.errors) {
    console.error(`ERROR: ${err}`);
  }
}
```

Seven-step verification: bundle structure, receipt schema, receipt fingerprint, constitution signature, provenance chain, receipt Ed25519 signature, trust anchor (if `trustedKeyIds` supplied).

### Via the CLI

```bash
# Create a bundle
sanna bundle-create \
  --receipt receipt.json \
  --constitution constitution.yaml \
  --public-key ~/.sanna/keys/<key-id>.pub \
  --output evidence.zip

# Verify it
sanna bundle-verify evidence.zip

# Verbose per-step output
sanna bundle-verify evidence.zip --verbose
```

Bundles are suitable for handing to auditors who have the `sanna` CLI but no access to your key store. The bundle is self-contained -- the public key is embedded and used automatically by `bundle-verify`.

---

## 5. Deliver Receipts to Sanna Cloud

Send receipts to the Sanna Cloud ingestion API via `CloudHTTPSink`. Receipts are delivered over HTTPS, with automatic retry, batching, and optional buffer-and-retry for resilience against transient network failures.

```typescript
import {
  sannaObserve, CloudHTTPSink, SannaHaltError,
} from "@sanna-ai/core";

const sink = new CloudHTTPSink({
  apiUrl: "https://api.sanna.dev/v1",
  apiKey: "sk-sanna-REPLACE_WITH_REAL_KEY",
  failurePolicy: "buffer_and_retry",
  bufferPath: ".sanna/buffer.jsonl",   // required for buffer_and_retry
  maxRetries: 3,
  timeoutMs: 10_000,
});

const myAgent = sannaObserve(
  (query: string, context: string): string => {
    return "Based on the data, revenue grew 12% year-over-year.";
  },
  {
    constitutionPath: "constitution.yaml",
    constitutionPublicKeyPath: "~/.sanna/keys/<key-id>.pub",
    enforcementMode: "enforced",
    sink,
  },
);

try {
  const result = myAgent(
    "What was revenue growth?",
    "Annual report: revenue increased 12% YoY.",
  );
  console.log(result.output);
  console.log(`Receipt delivered: ${result.receipt.receipt_id}`);
} catch (e) {
  if (e instanceof SannaHaltError) {
    console.error(`HALTED: ${e.message}`);
    // The halt receipt was also delivered to Cloud via the sink.
  }
}

// Flush any buffered receipts before process exit
await sink.flush();
await sink.close();
```

**Delivery behavior:**
- `201` -- success
- `409` -- treated as success (duplicate receipt already stored)
- `429` -- respects `Retry-After` header; retried
- `5xx` -- retried with exponential backoff
- `400` / `401` / `403` -- not retried (immediate failure)

**`buffer_and_retry`:** Failed receipts are appended to the JSONL buffer file. A background flush loop (every 60 seconds) re-attempts delivery. Call `sink.flush()` before process exit to drain the buffer. The background interval is `unref()`d so it does not hold the Node.js event loop open.

For more sink options (`NullSink`, `LocalSQLiteSink`, `CompositeSink`), see [docs/ts-sdk-reference.md#sinks](./ts-sdk-reference.md#sinks).
