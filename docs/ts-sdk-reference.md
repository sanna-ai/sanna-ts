# TypeScript SDK Reference

The `@sanna-ai/core` package provides trust infrastructure for AI agents: constitution enforcement, cryptographic receipts, and offline verification.

**Framing:** `sannaObserve` is **post-execution detection and attestation** -- the wrapped function executes and returns before output checks run. Side effects of the function are not prevented by `sannaObserve`. Pre-execution prevention is handled by the gateway (out-of-process MCP proxy) and the interceptor surfaces (`patchChildProcess`, `patchFetch`). The `reasoning/` module exports `HeuristicJudge`, `ReasoningPipeline`, and `JudgeVerdict` as library components; they are **not** wired into `sannaObserve` as a pre-execution gate.

## Install

```bash
npm install @sanna-ai/core                # Core library (Node.js 22+)
npm install -g @sanna-ai/cli              # CLI tools
npm install @sanna-ai/gateway             # MCP enforcement proxy
npm install @sanna-ai/mcp-server          # MCP governance server
```

All four packages require **Node.js 22+** for native Ed25519 support.

## Packages

| Package | npm | Bin | Description |
|---------|-----|-----|-------------|
| `@sanna-ai/core` | `npm install @sanna-ai/core` | -- | Constitution engine, receipts, coherence checks, middleware, receipt store, sinks, drift analysis, evidence bundles, approval workflows, identity claims |
| `@sanna-ai/cli` | `npm install -g @sanna-ai/cli` | `sanna` | 17-command CLI (see [README CLI Reference](../README.md#cli-reference)) |
| `@sanna-ai/gateway` | `npm install @sanna-ai/gateway` | `sanna-gateway` | MCP enforcement proxy with circuit breakers, escalation, receipt chaining, content mode attestation |
| `@sanna-ai/mcp-server` | `npm install @sanna-ai/mcp-server` | `sanna-mcp-server` | 10 governance tools over MCP stdio transport |

For quickstart examples and receipt/constitution format details, see the [README](../README.md).

---

## Observe

### `sannaObserve`

```typescript
function sannaObserve<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn,
  options?: SannaObserveOptions,
): (...args: TArgs) => SannaResult<TReturn>
```

Wraps a function with Sanna governance. The wrapped function executes first; coherence checks and invariant checks run against the output. Returns a new function that returns `SannaResult<T>`. In `"enforced"` mode, throws `SannaHaltError` when a critical check fails.

**`SannaObserveOptions`**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `constitution` | `Constitution` | -- | Pre-loaded constitution object |
| `constitutionPath` | `string` | -- | Path to signed constitution YAML |
| `constitutionPublicKeyPath` | `string` | -- | Path to Ed25519 public key for constitution signature verification |
| `signingKeyPath` | `string` | -- | Path to Ed25519 private key for signing receipts |
| `enforcementMode` | `EnforcementMode` | `"advisory"` | `"enforced"` (halt on critical failure) / `"advisory"` (receipts only) / `"permissive"` (no checks) |
| `toolName` | `string` | -- | Tool name for authority evaluation |
| `contextParam` | `string` | -- | Override parameter name for context extraction |
| `queryParam` | `string` | -- | Override parameter name for query extraction |
| `sink` | `ReceiptSink` | -- | Receipt delivery backend |
| `parentReceipts` | `string[] \| null` | -- | Fingerprints of causally-linked parent receipts |
| `workflowId` | `string \| null` | -- | Per-session workflow grouping identifier |
| `agentModel` | `string \| null` | -- | LLM model identifier (e.g., `"claude-opus-4-8"`) |
| `agentModelProvider` | `string \| null` | -- | LLM provider (e.g., `"anthropic"`) |
| `agentModelVersion` | `string \| null` | -- | LLM version string |
| `redactionConfig` | `RedactionConfig` | -- | PII redaction controls |

```typescript
import { sannaObserve, SannaHaltError } from "@sanna-ai/core";
import type { SannaResult } from "@sanna-ai/core";

const myAgent = sannaObserve(
  (query: string, context: string): string => {
    return "Based on the data, revenue grew 12% year-over-year.";
  },
  {
    constitutionPath: "constitution.yaml",
    constitutionPublicKeyPath: "~/.sanna/keys/<key-id>.pub",
    enforcementMode: "enforced",
  },
);

try {
  const result: SannaResult<string> = myAgent(
    "What was revenue growth?",
    "Annual report: revenue increased 12% YoY to $4.2B.",
  );
  console.log(result.output);   // original function return value
  console.log(result.receipt);  // governance receipt
  console.log(result.halted);   // false on success
} catch (e) {
  if (e instanceof SannaHaltError) {
    console.error(`HALTED: ${e.message}`);
    console.error(e.receipt);        // receipt documenting the halt
    console.error(e.failedChecks);   // CheckResult[] that triggered the halt
  }
}
```

### `withSannaGovernance`

```typescript
function withSannaGovernance(
  options?: SannaObserveOptions,
): <TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn,
) => (...args: TArgs) => SannaResult<TReturn>
```

Factory variant. Configure options once, apply to multiple functions.

```typescript
const govern = withSannaGovernance({ constitutionPath: "constitution.yaml", enforcementMode: "enforced" });
const safeSearch = govern(searchKnowledgeBase);
const safeAnswer = govern(generateAnswer);
```

### `SannaHaltError`

```typescript
class SannaHaltError extends Error {
  readonly receipt: Receipt;          // receipt documenting why the halt occurred
  readonly failedChecks: CheckResult[];
}
```

Thrown by `sannaObserve` in `"enforced"` mode when a check with severity `"critical"` or `"high"` fails, or when authority evaluation returns `"halt"`.

### `buildTraceData`

```typescript
function buildTraceData(
  query: string,
  context: string,
  output: string,
  constitution?: Constitution,
  checkResults?: CheckResult[],
): TraceData
```

Assembles the inputs/outputs structure that `generateReceipt` expects. Used when building integrations that call `generateReceipt` directly rather than via `sannaObserve`.

---

## Receipts

### `generateReceipt`

```typescript
function generateReceipt(params: ReceiptParams): Receipt
```

Assembles a complete receipt: computes content hashes, fingerprints, UUID, and status. `sannaObserve` calls this internally; use it directly when building non-decorator integrations.

Key fields of `ReceiptParams`:

| Field | Required | Description |
|-------|----------|-------------|
| `correlation_id` | yes | Correlation identifier (must not contain `\|`) |
| `inputs` | yes | Dict of function inputs |
| `outputs` | yes | Dict of function outputs |
| `checks` | yes | Array of `CheckResult` objects |
| `constitution_ref` | no | `{ document_id, policy_hash }` |
| `enforcement` | no | `{ action, reason, ... }` when a halt was triggered |
| `enforcementSurface` | no | `"middleware"` / `"gateway"` / `"cli_interceptor"` / `"http_interceptor"` (default `"middleware"`) |
| `invariantsScope` | no | `"full"` / `"authority_only"` / `"none"` (default `"full"`) |
| `parent_receipts` | no | `string[] \| null` -- parent fingerprints for causal chaining |
| `workflow_id` | no | `string \| null` |
| `agent_identity` | no | `{ agent_session_id: string, ... }` -- triggers cv=10 / spec_version 1.5 emission |
| `agent_model` | no | `string \| null` |
| `agent_model_provider` | no | `string \| null` |
| `agent_model_version` | no | `string \| null` |

When `agent_identity` is provided, receipts emit at `checks_version: "10"` / `spec_version: "1.5"`.

### `signReceipt`

```typescript
function signReceipt(
  receipt: Record<string, unknown>,
  privateKey: KeyObject,
  signedBy: string,
): Record<string, unknown>
```

Signs a receipt dict and adds a `receipt_signature` block. Signing material is the canonical JSON of the entire receipt with `receipt_signature.signature` set to `""` (placeholder).

### `computeFingerprints`

```typescript
function computeFingerprints(
  receipt: Record<string, unknown>,
): { receipt_fingerprint: string; full_fingerprint: string }
```

Recomputes the 16-hex and 64-hex fingerprints from a receipt dict. Used by `verifyReceipt` for tamper detection.

### Version constants (from `@sanna-ai/core`)

```typescript
import { SPEC_VERSION, CHECKS_VERSION, TOOL_VERSION, TOOL_NAME } from "@sanna-ai/core";
// SPEC_VERSION    = "1.5"
// CHECKS_VERSION  = "10"
// TOOL_VERSION    = "1.5.0"
// TOOL_NAME       = "sanna-ts"
```

For the receipt format, field definitions, and the Receipt Triad specification, see the [README Receipt Format section](../README.md#receipt-format) and the [v1.5 specification](https://github.com/sanna-ai/sanna-protocol/blob/main/spec/sanna-specification-v1.5.md).

---

## Verification

### `verifyReceipt`

```typescript
function verifyReceipt(
  receipt: Record<string, unknown>,
  publicKey?: KeyObject,
): VerificationResult
```

Offline receipt verification. Runs six checks independently and reports all failures:

1. Schema validation (required fields, format, ajv conditional rules)
2. Ed25519 signature (if `publicKey` provided)
3. Fingerprint recalculation
4. Content hash verification
5. Status/count consistency
6. Timestamp sanity

```typescript
import { verifyReceipt, loadPublicKey } from "@sanna-ai/core";
import { readFileSync } from "node:fs";

const receipt = JSON.parse(readFileSync("receipt.json", "utf-8"));
const pubKey = loadPublicKey("~/.sanna/keys/<key-id>.pub");

const result = verifyReceipt(receipt, pubKey);
console.log(result.valid);             // true or false
console.log(result.errors);            // string[] -- all failures
console.log(result.warnings);          // string[] -- non-fatal notes
console.log(result.checks_performed);  // which checks ran
```

### `verifyReceiptSet`

```typescript
function verifyReceiptSet(
  receipts: Record<string, unknown>[],
  publicKey?: KeyObject,
): Record<string, VerificationResult>
```

Verify a batch of receipts. Also runs cross-receipt anomaly checks when `event_type` fields indicate related receipts.

### `checkGatewayRedactionMarkersCorrect`

```typescript
function checkGatewayRedactionMarkersCorrect(
  receipt: Record<string, unknown>,
): string[]
```

Verify that `content_mode` declaration matches actual spec section 2.11.1 marker state in `inputs.context` and `outputs.response`. Returns error strings prefixed with `REDACTION_CLAIM_WITHOUT_MARKER:`.

### `verifySessionManifestReceipt` / `verifyInvocationAnomalyReceipt`

```typescript
import { verifySessionManifestReceipt, verifyInvocationAnomalyReceipt } from "@sanna-ai/core";

function verifySessionManifestReceipt(receipt: Record<string, unknown>): Check[]
function verifyInvocationAnomalyReceipt(
  receipt: Record<string, unknown>,
  receipts: Record<string, unknown>[] | null,
): Check[]
```

Semantic checks for manifest and anomaly receipts. Called automatically by `verifyReceipt` when `event_type` is `"session_manifest"` or an anomaly event type.

---

## Store

### `ReceiptStore`

```typescript
class ReceiptStore {
  constructor(dbPath?: string)  // default: ".sanna/receipts.db"
  save(receipt: Record<string, unknown>): string    // returns receipt_id
  query(filters?: ReceiptQueryFilters): Record<string, unknown>[]
  count(filters?: ReceiptQueryFilters): number
  close(): void
  [Symbol.dispose](): void
}
```

SQLite-backed receipt persistence using `better-sqlite3`. The constructor rejects `/tmp` paths unless `SANNA_ALLOW_TEMP_DB=1` (CI/testing only). Creates parent directories with `0o700` mode. Works as a `using`-statement resource (Symbol.dispose).

`ReceiptQueryFilters`:

| Filter | Type | Description |
|--------|------|-------------|
| `agent_id` | `string` | Filter by agent ID (extracted from `constitution_ref.document_id`) |
| `constitution_id` | `string` | Filter by full constitution document ID |
| `correlation_id` | `string` | Filter by correlation ID |
| `status` | `string` | `"PASS"` / `"WARN"` / `"FAIL"` / `"PARTIAL"` |
| `enforcement` | `boolean` | If true, return only halted/escalated receipts |
| `since` | `string` | ISO 8601 lower bound on timestamp |
| `until` | `string` | ISO 8601 upper bound on timestamp |
| `limit` | `number` | Max results to return |
| `offset` | `number` | Result offset for pagination |

```typescript
import { ReceiptStore } from "@sanna-ai/core";

using store = new ReceiptStore(".sanna/receipts.db");
store.save(result.receipt as unknown as Record<string, unknown>);
const failures = store.query({ status: "FAIL", limit: 20 });
```

---

## Drift

### `DriftAnalyzer`

```typescript
class DriftAnalyzer {
  constructor(store: ReceiptStore)
  analyze(
    windowDays?: number,            // default: 30
    opts?: {
      agentId?: string;
      threshold?: number;           // default: 0.15
      projectionDays?: number;      // default: 90
    },
  ): DriftReport
  analyzeMulti(windows?: number[], opts?: ...): DriftReport[]
}
```

Computes per-agent, per-check failure rates with linear regression trend analysis and breach-day projection. Pure TypeScript (no numpy/scipy).

```typescript
import { ReceiptStore, DriftAnalyzer } from "@sanna-ai/core";

const store = new ReceiptStore(".sanna/receipts.db");
const analyzer = new DriftAnalyzer(store);
const report = analyzer.analyze(30, { threshold: 0.15 });

console.log(report.fleet_status);     // "HEALTHY" | "WARNING" | "CRITICAL" | "INSUFFICIENT_DATA"
for (const agent of report.agents) {
  console.log(agent.agent_id, agent.status);
  for (const check of agent.checks) {
    console.log(`  ${check.check_id}: fail_rate=${(check.fail_rate * 100).toFixed(1)}%`);
  }
}
store.close();
```

### Report formatting helpers

```typescript
function formatDriftReport(report: DriftReport): string       // human-readable text
function exportDriftReport(report: DriftReport, fmt?: "json" | "csv"): string
```

### Drift data types (from `@sanna-ai/core`)

| Type | Fields |
|------|--------|
| `DriftReport` | `window_days`, `threshold`, `generated_at`, `agents`, `fleet_status` |
| `AgentDriftSummary` | `agent_id`, `constitution_id`, `status`, `total_receipts`, `checks`, `projected_breach_days` |
| `CheckDriftDetail` | `check_id`, `total_evaluated`, `pass_count`, `fail_count`, `fail_rate`, `trend_slope`, `projected_breach_days`, `status` |

```typescript
import { calculateSlope, projectBreach } from "@sanna-ai/core";
// Pure helpers also exported: calculateSlope(xs, ys), projectBreach(currentRate, slope, threshold)
```

---

## Sinks

### `ReceiptSink` (interface)

```typescript
interface ReceiptSink {
  store(receipt: Receipt): Promise<SinkResult>;
  storeBatch?(receipts: Receipt[]): Promise<SinkResult[]>;
  flush?(): Promise<void>;
  close?(): Promise<void>;
}
```

### `FailurePolicy`

```typescript
type FailurePolicy = "log_and_continue" | "throw" | "buffer_and_retry";
// "log_and_continue"  -- default; logs to stderr, returns error result
// "throw"             -- throws on delivery failure
// "buffer_and_retry"  -- buffers to JSONL file, background retry loop
```

### Concrete sinks

```typescript
import { NullSink, LocalSQLiteSink, CloudHTTPSink, CompositeSink } from "@sanna-ai/core";
import type { CloudHTTPSinkOptions } from "@sanna-ai/core";

// No-op sink (drops receipts silently)
const nullSink = new NullSink();

// SQLite-backed local persistence (wraps ReceiptStore)
const localSink = new LocalSQLiteSink(".sanna/receipts.db");

// HTTPS endpoint with retry, exponential backoff, batch, and optional buffer-on-failure
const cloudSink = new CloudHTTPSink({
  apiUrl: "https://api.sanna.dev/v1",     // appends /receipts internally
  apiKey: "<your-key>",
  failurePolicy: "buffer_and_retry",       // optional, default: "log_and_continue"
  timeoutMs: 10_000,                       // optional, default: 10000
  maxRetries: 3,                           // optional, default: 3
  bufferPath: ".sanna/buffer.jsonl",       // required for buffer_and_retry
});

// Fan-out to multiple sinks
const sink = new CompositeSink([localSink, cloudSink]);

const result = await sink.store(receipt);
console.log(result.success, result.receiptId);
```

`CloudHTTPSink` behavior: retries on 429/5xx with exponential backoff; treats 409 (duplicate) as success; no retry on 400/401/403. Sends to `${apiUrl}/v1/receipts` (single) or `${apiUrl}/v1/receipts/batch` (batch).

---

## Interceptors

`patchChildProcess` and `patchFetch` are in-process monkeypatches for cooperative code. Each call is evaluated against the constitution and produces a signed receipt. For untrusted or adversarial code, use the gateway (out-of-process MCP proxy).

### `patchChildProcess` / `unpatchChildProcess`

```typescript
async function patchChildProcess(options: PatchOptions): Promise<void>
function unpatchChildProcess(): void

interface PatchOptions {
  constitutionPath: string;
  sink: ReceiptSink;
  agentId: string;
  mode?: "enforce" | "audit" | "passthrough";   // default: "enforce"
  signingKey?: Buffer;                           // Ed25519 private key PEM bytes
  contentMode?: "full" | "redacted" | "hashes_only";
  workflowId?: string;
  parentFingerprint?: string;
  redactionConfig?: RedactionConfig;
}
```

Patches `child_process`: `spawn`, `spawnSync`, `exec`, `execSync`, `execFile`, `execFileSync`, `fork`. On activation, emits a `session_manifest` receipt for the CLI surface. In `enforce` mode, failure to emit the manifest aborts patching.

### `patchFetch` / `unpatchFetch`

```typescript
async function patchFetch(options: HttpPatchOptions): Promise<void>
function unpatchFetch(): void

interface HttpPatchOptions extends PatchOptions {
  excludeUrls?: string[];   // glob patterns for URLs to skip governance
}
```

Patches `globalThis.fetch`, `http.request`, and `https.request`. Sanna Cloud endpoints (`*.sanna.cloud/*`) are always excluded to prevent recursive interception. On activation, emits a `session_manifest` receipt for the HTTP surface.

### Behavior matrix

Both interceptors share the same three-mode model. The `mode` option controls whether policy violations block execution.

| Mode | `allow` | `halt` | `escalate` |
|------|---------|--------|------------|
| `"enforce"` | execute + receipt | **block** + receipt | **block** + receipt |
| `"audit"` | execute + receipt | execute + receipt | execute + receipt |
| `"passthrough"` | execute + receipt | execute + receipt | execute + receipt |

In `"enforce"` mode, `escalate` fails closed (same as `halt`) -- SAN-745.

Every intercepted call emits a receipt regardless of mode, recording the decision, hashes, and enforcement action.

### Thrown error types when blocked (enforce mode)

**Heterogeneous by surface** -- customers must write distinct catch blocks:

| Surface | Thrown type | How to detect |
|---------|-------------|---------------|
| `child_process.*` | `ErrnoException { code: "ENOENT" }` | `(err as NodeJS.ErrnoException).code === "ENOENT"` |
| `globalThis.fetch` | `TypeError("fetch failed")` with `.cause` | `err instanceof TypeError` |
| `http.request` / `https.request` | `ErrnoException { code: "ECONNREFUSED" }` | `(err as NodeJS.ErrnoException).code === "ECONNREFUSED"` |

The child_process interceptor throws an error shaped like a spawn ENOENT (the Node.js native error for an unknown binary); the fetch interceptors throw errors shaped like connection refusals. These types are structural, not named classes -- write catch blocks by checking `err.code` or `instanceof TypeError` rather than by class name.

For a complete interceptor example, see [docs/cookbook.md](./cookbook.md#1-subprocess-and-fetch-interceptors).

### Authority evaluators (also exported)

```typescript
import { evaluateCliAuthority, checkCliInvariants, evaluateApiAuthority, checkApiInvariants } from "@sanna-ai/core";
// Low-level authority evaluators used internally by the interceptors.
// Exposed for custom interception and testing.
```

---

## Coherence Checks (C1-C5)

Five built-in deterministic heuristics. No API calls or external dependencies.

```typescript
import {
  checkC1ContextGrounding,
  checkC2ConstitutionalAlignment,
  checkC3InstructionAdherence,
  checkC4OutputConsistency,
  checkC5ConstraintSatisfaction,
  runCoherenceChecks,
} from "@sanna-ai/core";
import type { CoherenceCheckOptions } from "@sanna-ai/core";

const opts: CoherenceCheckOptions = {
  context: "Annual report: revenue increased 12% YoY.",
  query: "What was revenue growth?",
  output: "Revenue grew 12% year-over-year.",
  constitution,   // optional; required for C2 and C5
};

const results = runCoherenceChecks(opts);
// Returns CheckResult[] for C1 through C5 in order.
```

| Check | What it catches | Severity on fail |
|-------|-----------------|-----------------|
| C1 `checkC1ContextGrounding` | Output does not reference provided context keywords | `"high"` |
| C2 `checkC2ConstitutionalAlignment` | Output matches prohibition patterns from constitution boundaries | `"high"` |
| C3 `checkC3InstructionAdherence` | Output shares no keywords with the query | `"medium"` |
| C4 `checkC4OutputConsistency` | Always passes (structural check only) | -- |
| C5 `checkC5ConstraintSatisfaction` | Explicit length/format constraints from constitution invariants | `"medium"` |

C4 always passes; semantic contradiction detection requires LLM evaluation (see `LLMJudge`).

---

## Invariants

### `loadInvariantChecks` / `runInvariantCheck` / `runAllInvariantChecks`

```typescript
function loadInvariantChecks(constitution: Constitution): InvariantDefinition[]
function runInvariantCheck(invariant: InvariantDefinition, output: string, context?: string): CheckResult
function runAllInvariantChecks(constitution: Constitution, output: string, context?: string): CheckResult[]
```

Extracts invariant definitions from a constitution and evaluates them against output. Built-in types detected from rule text: `pii_detection`, `max_length`, `regex_match`, `regex_deny`, `required_keywords`. Unrecognized types return `status: "UNKNOWN_TYPE"` (not silently ignored). Regex patterns are validated by `safe-regex2` before execution.

---

## Evaluator Registry

Custom invariant evaluators let you add domain-specific checks that run when their invariant ID appears in the constitution.

```typescript
import {
  registerInvariantEvaluator,
  getEvaluator,
  listEvaluators,
  clearEvaluators,
} from "@sanna-ai/core";
import type { InvariantEvaluatorFn } from "@sanna-ai/core";
```

```typescript
type InvariantEvaluatorFn = (
  context: string,
  output: string,
  constitution: Constitution,
  checkConfig: Record<string, unknown>,
) => CheckResult;

function registerInvariantEvaluator(invariantId: string, evaluator: InvariantEvaluatorFn): void
// Throws if invariantId already registered.

function getEvaluator(invariantId: string): InvariantEvaluatorFn | undefined
function listEvaluators(): string[]
function clearEvaluators(): void  // for test isolation
```

See [docs/cookbook.md](./cookbook.md#2-register-a-custom-invariant-evaluator) for a step-by-step example.

---

## LLM Judge (optional semantic evaluators)

Optional LLM-backed semantic evaluation via the Anthropic Messages API. Distinct from C1-C5 heuristic checks -- operates at the semantic level.

```typescript
import { LLMJudge, LLMEvaluationError, enableLlmChecks, registerLlmEvaluators } from "@sanna-ai/core";
import type { LLMJudgeOptions } from "@sanna-ai/core";

interface LLMJudgeOptions {
  apiKey?: string;    // or ANTHROPIC_API_KEY env var
  model?: string;     // default: "claude-sonnet-4-5-20250929"
  baseUrl?: string;   // default: "https://api.anthropic.com"
  timeout?: number;   // ms, default: 30000
}

class LLMJudge {
  constructor(options?: LLMJudgeOptions)
  evaluate(checkId: string, context: string, output: string, constitution?: Constitution): Promise<CheckResult>
}

class LLMEvaluationError extends Error {}
```

Available check aliases: `LLM_C1` (context grounding), `LLM_C2` (fabrication detection), `LLM_C3` (instruction adherence), `LLM_C4` (false certainty), `LLM_C5` (premature compression). Registered under `INV_LLM_*` invariant IDs.

```typescript
// Enable all five LLM checks (registers them in the evaluator registry)
enableLlmChecks({ apiKey: "sk-ant-..." });

// Or a subset
const judge = new LLMJudge({ apiKey: "sk-ant-..." });
registerLlmEvaluators(judge, ["LLM_C1", "LLM_C2"]);
```

---

## OpenTelemetry

```typescript
import { receiptToSpan, SannaSpanExporter } from "@sanna-ai/core";
import type { ReceiptSpanOptions } from "@sanna-ai/core";
```

`@opentelemetry/api` is an optional peer dependency. Spans carry a pointer + integrity hash (`sanna.content_hash`) to the receipt, not the full receipt JSON. Individual check statuses are emitted as `sanna.c1` through `sanna.c5` span attributes.

```typescript
import { trace } from "@opentelemetry/api";

const tracer = trace.getTracer("my-agent");
receiptToSpan(result.receipt as unknown as Record<string, unknown>, tracer, {
  artifactUri: "s3://receipts/my-receipt.json",
});
```

```typescript
class SannaSpanExporter {
  constructor(tracer: Tracer)
  exportReceipt(receipt: Record<string, unknown>, options?: ReceiptSpanOptions): Span
  exportBatch(receipts: Record<string, unknown>[], options?: ReceiptSpanOptions): Span[]
}
```

---

## Reasoning (library components)

Exported as library components; **not wired into `sannaObserve`** as a pre-execution gate.

```typescript
import { HeuristicJudge, ReasoningPipeline, JudgeVerdict } from "@sanna-ai/core";
import type { JudgeResult, BaseJudge, ReasoningPipelineOptions, ReasoningResult } from "@sanna-ai/core";
```

`JudgeVerdict`: enum of judge outcomes. `HeuristicJudge`: applies heuristic rules to evaluate reasoning quality. `ReasoningPipeline`: chains multiple judges. These are building blocks for custom pre-execution reasoning workflows; they do not gate the `sannaObserve` wrapper.

---

## Approval

Multi-party approval workflows for constitutions. Approval signatures are Ed25519-signed and cryptographically bound to the constitution hash.

```typescript
import {
  createApprovalRequest,
  signApproval,
  verifyApproval,
  isApprovalExpired,
  ApprovalStore,
} from "@sanna-ai/core";
import type { CreateApprovalOptions, ApprovalStoreFilters } from "@sanna-ai/core";

// Create a request
const request = createApprovalRequest(constitutionHash, "governance-team", {
  required_approvals: 2,
  expires_in_hours: 72,
});

// Sign it (each approver calls this with their own key)
const privateKey = loadPrivateKey("~/.sanna/keys/<key-id>.key");
signApproval(request, privateKey);

// Verify all signatures
const publicKeys = new Map([["<key-id>", loadPublicKey("~/.sanna/keys/<key-id>.pub")]]);
const result = verifyApproval(request, publicKeys);
console.log(result.valid, result.verified_count, result.required_count);

// Persist approvals
const store = new ApprovalStore(".sanna/approvals.json");
store.save(request);
```

---

## Identity

Signed assertions about agents, operators, and organizations. Claims are Ed25519-signed with configurable expiry.

```typescript
import {
  createIdentityClaim,
  verifyIdentityClaim,
  IdentityRegistry,
} from "@sanna-ai/core";
import type { CreateClaimOptions } from "@sanna-ai/core";

// Create and sign a claim
const claim = createIdentityClaim(
  "agent_identity",
  subjectKeyId,
  { name: "support-agent", version: "1.0.0", operator: "Acme Corp" },
  signingKey,
  { expires_in_hours: 8760 },
);

// Verify a claim
const result = verifyIdentityClaim(claim, publicKey);
console.log(result.valid, result.expired, result.signature_valid);
```

`IdentityRegistry` maintains a collection of verified claims, indexed by `subject_key_id` and `claim_type`, with revocation support.

---

## Safe I/O

Atomic file writes, symlink protection, and path validation. These are utility functions for writing governance artifacts safely.

```typescript
import {
  safeWriteFile, safeWriteJson, safeWriteYaml,
  safeReadFile, validatePath, isSymlink, ensureDirectory, secureTempDir,
} from "@sanna-ai/core";

// Atomic write: temp file + fsync + rename; refuses symlink targets
safeWriteFile("receipt.json", JSON.stringify(receipt), { mode: 0o600 });
safeWriteJson("receipt.json", receipt);
safeWriteYaml("constitution.yaml", constitutionData);

// Read with symlink protection
const content = safeReadFile("constitution.yaml");
// With path traversal protection:
const content2 = safeReadFile("subdir/file.yaml", "/allowed/base/");

// Path validation
const { valid, resolved, error } = validatePath("../escape", "/base/dir");
// valid === false; error = "Path escapes base directory"

// Secure temp directory (0o700 permissions)
const tmpDir = secureTempDir("sanna-");
```

---

## Constitution

```typescript
import {
  loadConstitution, parseConstitution, validateConstitutionData,
  verifyConstitutionSignature, computeFileContentHash,
  signConstitution, saveConstitution,
} from "@sanna-ai/core";

// Load from file (validates signature if provenance.signature present)
const constitution = loadConstitution("constitution.yaml");

// Parse from a plain object (e.g., deserialized YAML)
const constitution2 = parseConstitution(rawObject);

// Verify Ed25519 signature
const pubKey = loadPublicKey("~/.sanna/keys/<key-id>.pub");
const valid = verifyConstitutionSignature(constitution, pubKey);

// Get SHA-256 content hash of a constitution file (for bundle creation)
const contentHash = computeFileContentHash("constitution.yaml");

// Sign and save
const privateKey = loadPrivateKey("~/.sanna/keys/<key-id>.key");
const signed = signConstitution(constitution, privateKey, "governance-team");
saveConstitution(signed, "constitution.yaml");
```

---

## Constitution Diff

```typescript
import {
  diffConstitutions, formatDiffText, formatDiffJson, isDriftingConstitution,
} from "@sanna-ai/core";
import type { DiffResult, DiffEntry, DiffSection } from "@sanna-ai/core";

const diff = diffConstitutions(constitutionA, constitutionB);
console.log(formatDiffText(diff));   // human-readable unified diff
console.log(formatDiffJson(diff));   // machine-readable JSON

// Check if a constitution has diverged materially
if (isDriftingConstitution(diff)) {
  console.warn("Governance drift detected");
}
```

---

## Bundle

Evidence bundles are self-contained zip archives for auditors: receipt, constitution, and public key(s) in one file. Verification requires no network access.

```typescript
import { createBundle, verifyBundle } from "@sanna-ai/core";
import type { CreateBundleOptions, BundleVerificationResult, BundleCheck } from "@sanna-ai/core";

// Create
const bundlePath = createBundle({
  receiptPath: "receipt.json",
  constitutionPath: "constitution.yaml",
  publicKeyPath: "~/.sanna/keys/<key-id>.pub",
  outputPath: "evidence.zip",
  description: "Q2 2026 governance audit",
  constitutionPublicKeyPath: "~/.sanna/keys/<author-key-id>.pub",  // optional
});

// Verify (7-step check: structure, schema, fingerprint, constitution sig, provenance chain, receipt sig, trust anchor)
const result = verifyBundle("evidence.zip");
console.log(result.valid);
for (const check of result.checks) {
  console.log(`  [${check.passed ? "PASS" : "FAIL"}] ${check.name}: ${check.detail}`);
}
```

---

## Cryptography

```typescript
import {
  generateKeypair, sign, verify,
  loadPrivateKey, loadPublicKey, getKeyId,
  exportPrivateKeyPem, exportPublicKeyPem,
} from "@sanna-ai/core";
import type { SannaKeypair, KeyObject } from "@sanna-ai/core";

// Generate a new Ed25519 keypair
const keypair = generateKeypair();
// keypair.privateKey, keypair.publicKey are KeyObject instances

// Sign and verify raw data
const data = Buffer.from("message", "utf-8");
const signature = sign(data, keypair.privateKey);
const valid = verify(data, signature, keypair.publicKey);

// Load from PEM files
const privateKey = loadPrivateKey("~/.sanna/keys/<key-id>.key");
const publicKey = loadPublicKey("~/.sanna/keys/<key-id>.pub");

// Get the key ID (SHA-256 fingerprint of the public key)
const keyId = getKeyId(publicKey);

// Export to PEM strings
const privatePem = exportPrivateKeyPem(keypair.privateKey);
const publicPem = exportPublicKeyPem(keypair.publicKey);
```

Keys use PKCS#8 (private) and SPKI (public) PEM encoding. Key IDs are the SHA-256 fingerprint of the public key bytes. Keys generated by the Python SDK are interchangeable.

---

## Hashing

```typescript
import { canonicalize, hashBytes, hashContent, hashObj, EMPTY_HASH } from "@sanna-ai/core";

// RFC 8785 JSON Canonicalization Scheme (uses the `canonicalize` library)
// Keys sorted, NFC Unicode, integer-only numerics
const canonical = canonicalize({ z: 2, a: 1 });  // '{"a":1,"z":2}'

// SHA-256 of raw bytes -> 64-hex
const hash = hashBytes(Buffer.from("hello", "utf-8"));

// SHA-256 of a UTF-8 string with Sanna text normalization -> 64-hex
// Applies NFC, CRLF normalization, per-line trailing whitespace strip, leading/trailing trim
const contentHash = hashContent("some text");

// SHA-256 of the canonical JSON of an object -> 64-hex
const objHash = hashObj({ a: 1, b: "two" });

// SHA-256 of zero bytes (sentinel for absent fields)
console.log(EMPTY_HASH);  // "e3b0c44298fc1c149afbf4c8996fb924..."
```

Rejects non-integer floats, NaN, Infinity, and BigInt (throws `TypeError`). Integer-valued floats (`1.0`) are preserved as-is since JavaScript does not distinguish them from integers.

---

## Manifest

```typescript
import {
  generateManifest, getSuppressedPatterns, MANIFEST_VERSION,
  VALID_SUPPRESSION_REASONS,
  SUPPRESSION_REASON_CANNOT_EXECUTE,
  SUPPRESSION_REASON_POLICY_DENIED,
  SUPPRESSION_REASON_ESCALATION_SUPPRESSED,
  SUPPRESSION_REASON_SERVER_DEFAULT_DENIED,
  SUPPRESSION_REASON_CONSTITUTION_INVALID,
  SUPPRESSION_REASON_CONTENT_MODE_REDACTED,
  SUPPRESSION_REASON_UNKNOWN,
} from "@sanna-ai/core";
import type { Manifest, McpSurface, CliSurface, HttpSurface, Surfaces } from "@sanna-ai/core";
```

`generateManifest` produces the `com.sanna.manifest` extension payload embedded in `session_manifest` receipts. `getSuppressedPatterns` returns the set of commands/endpoints that the constitution forbids on a given surface. Used internally by the interceptors; available for custom integrations.

---

## Redaction

```typescript
import { applyRedaction, makeRedactionMarker } from "@sanna-ai/core";
import type { RedactionConfig, RedactionMarker } from "@sanna-ai/core";

interface RedactionConfig {
  enabled: boolean;
  mode?: "hash_only";                          // only "hash_only" supported
  fields?: string[];                           // default: ["arguments", "result_text"]
}
```

When `enabled: true`, `applyRedaction` replaces specified receipt fields with deterministic spec section 2.11.1 markers (`{ __redacted__: true, original_hash: "<64-hex>" }`) **before** signing. The receipt signature covers the markers, not the original content. `content_mode` is set to `"redacted"` in receipt metadata.

---

## Anomaly

```typescript
import { redactAttemptedField } from "@sanna-ai/core";

function redactAttemptedField(value: string, contentMode?: string | null): string
```

Used by interceptors to redact attempted command/endpoint fields in anomaly receipts when `contentMode === "redacted"`. Returns the original value when content mode is not `"redacted"`.
