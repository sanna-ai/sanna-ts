# sanna-ts — Architecture

TypeScript SDK monorepo implementing the Sanna governance protocol. AGPL-3.0.
All 4 npm packages at **1.4.0** in source (npm publish deferred to post-cleanup
milestone per SAN-222 close). Receipts emit `tool_name: "sanna-ts"` and
`tool_version: "1.4.0"` (bare semver). SPEC_VERSION="1.4",
CHECKS_VERSION="9". Implements Sanna Protocol v1.4.

---

## Structure

- `packages/core/` — `@sanna-ai/core` (SDK: crypto, receipts, constitutions, governance, sinks)
- `packages/cli/` — `@sanna-ai/cli` (16 commands)
- `packages/gateway/` — `@sanna-ai/gateway` (MCP enforcement proxy)
- `packages/mcp-server/` — `@sanna-ai/mcp-server` (10 governance tools via MCP)
- `examples/constitutions/` — 6 gateway constitution templates with evaluation order docs
- `spec/` — git submodule → sanna-ai/sanna-protocol (golden fixtures, schemas)

---

## @sanna-ai/core (`packages/core/src/`)

Core SDK library. Exports all protocol types, crypto, receipts, and sinks.
ESM + CJS dual output.

| Module | Role |
|---|---|
| `hashing.ts` | RFC 8785 JCS canonicalization, SHA-256 |
| `crypto.ts` | Ed25519 via Node.js native crypto — ZERO external deps |
| `constitution.ts` | YAML parsing, validation, signing, signature verification |
| `evaluator.ts` | 4-tier authority evaluation with exact-match + opt-in glob |
| `receipt.ts` | Fingerprint dispatch ladder (12/14/16/20 fields by cv), UUID, Ed25519 signing. 4-action enforcement override. `SPEC_VERSION`, `CHECKS_VERSION`, `TOOL_VERSION`, `TOOL_NAME` constants. |
| `verifier.ts` | Schema + signature + fingerprint + content hash + status consistency + timestamp verification. v1.4 required-field assertion at cv>=9 (tool_name). v1.3 required-field assertion at cv>=8 (enforcement_surface, invariants_scope). Legacy warning path for cv=6/7 receipts missing v1.3 fields. Error text byte-equivalent to Python SDK (spec §10, §13). |
| `checks.ts` | Coherence checks engine (boundary, authority, halt condition, invariant) |
| `invariants.ts` | Invariant check definitions and runner (safe-regex2 ReDoS protection) |
| `middleware.ts` | Constitutional middleware pipeline with pre/post hooks, ReceiptSink integration |
| `store.ts` | SQLite receipt persistence (better-sqlite3, WAL mode) |
| `drift.ts` | Drift analysis with linear regression and breach projection |
| `bundle.ts` | Evidence bundle create/verify (adm-zip, 7-step verification) |
| `approval.ts` | Multi-party approval workflows with quorum logic |
| `identity.ts` | Ed25519 identity claims with issuance and verification |
| `safe-io.ts` | Hardened file I/O (symlink checks, atomic writes, size limits) |
| `constitution-diff.ts` | Structural diffing between constitution versions |
| `evaluator-registry.ts` | Custom invariant evaluator registry (register, get, list, clear) |
| `evaluators/llm.ts` | LLM-as-Judge semantic evaluators via Anthropic Messages API (fetch, zero deps) |
| `otel-exporter.ts` | OpenTelemetry bridge: receipt → span (pointer + integrity hash) |
| `reasoning/` | Reasoning evaluation pipeline with heuristic judge |
| `sinks/cloud-http-sink.ts` | HTTPS receipt delivery (retry, batch, buffer-and-retry, native fetch) |
| `sinks/composite-sink.ts` | Fan-out to multiple sinks with failure isolation |
| `sinks/local-sqlite-sink.ts` | SQLite persistence via ReceiptStore wrapper |
| `sinks/null-sink.ts` | No-op sink for testing |
| `types.ts` | Shared TypeScript interfaces (Receipt, ReceiptSink, ContentMode, FailurePolicy, SinkResult, etc.) |

---

## @sanna-ai/cli (`packages/cli/`)

16 commands via commander: `init`, `keygen`, `sign`, `verify`,
`verify-constitution`, `approve`, `inspect`, `diff`, `demo`,
`check-config`, `drift-report`, `gateway`, `migrate`, `bundle-create`,
`bundle-verify`, `generate`. ESM-only with shebang, bin: `sanna`.

---

## @sanna-ai/gateway (`packages/gateway/src/`)

MCP enforcement proxy — sits between client and downstream MCP servers.

| Module | Role |
|---|---|
| `config.ts` | YAML config loading, validation, `$ENV{}` interpolation, permission warnings, content_mode config |
| `gateway.ts` | Core proxy: tool interception, authority evaluation, receipt generation, ReceiptSink, content mode attestation, receipt chaining via escalation fingerprint tracking, per-session workflow_id |
| `downstream.ts` | Child process MCP server connections via StdioClientTransport (env allowlist) |
| `escalation.ts` | HMAC-SHA256 escalation token management (SHA-256 hashed at rest) |
| `receipt-v2.ts` | Receipt triad hashing (input/reasoning/action) |
| `pii.ts` | PII redaction (email, SSN, phone, IP, credit card; ReDoS-safe CC detection, depth-limited recursion) |
| `circuit-breaker.ts` | CLOSED/OPEN/HALF_OPEN failure isolation |
| `tool-namespace.ts` | `{downstream}_{tool}` namespacing |
| `schema-mutation.ts` | `_justification` parameter injection/extraction |
| `migrate.ts` | Claude Desktop / Cursor config migration |
| `webhook.ts` | Webhook token delivery with SSRF protection (private IP blocking, no redirects) |
| `file-delivery.ts` | File-based token delivery (atomic writes, TTL pruning, size caps) |

---

## @sanna-ai/mcp-server (`packages/mcp-server/`)

10 MCP tools via stdio transport: `evaluate_authority`, `generate_receipt`,
`verify_receipt`, `query_receipts`, `drift_report`, `get_constitution`,
`verify_constitution`, `list_checks`, `check_constitution_approval`,
`verify_identity_claims`.

---

## Key Decisions

- **Node 22+ required** — native Ed25519 support (`node:crypto`); no external crypto deps.
- **PEM key format** — PKCS8/SPKI, matches Python `cryptography` library for cross-SDK interop.
- **Python falsy semantics** — empty arrays/objects treated as falsy in fingerprint computation to match Python's `None` serialization.
- **ESM + CJS dual output** for core; ESM-only for cli, gateway, mcp-server.
- **canonicalize and safe-regex2 bundled** into core via tsup `noExternal` (no `createRequire` shim needed).
- **better-sqlite3** for receipt store — synchronous API, WAL mode.
- **MCP SDK import paths** — `Client` from `@modelcontextprotocol/sdk/client/index.js`; `Server` from `@modelcontextprotocol/sdk/server/index.js`; `InMemoryTransport` from `@modelcontextprotocol/sdk/inMemory.js` for integration tests.
- **bare semver tool_version** — `TOOL_VERSION = "1.4.0"` (post-SAN-222; was `"sanna-ts/1.3.0"`). SDK identity moved to the new `tool_name` field (`TOOL_NAME = "sanna-ts"`). This decouples receipt-emitted SDK identity from the version string.

---

## Security Hardening

All items below are load-bearing for SOC 2 / IETF audit.

- Credit card regex uses two-pass approach (strip separators, match digit runs) to avoid ReDoS.
- Invariant regex patterns validated by safe-regex2 before execution; unsafe patterns fail-closed with `UNSAFE_PATTERN` status.
- Unknown/undetectable invariant types fail closed with `UNKNOWN_TYPE` status.
- Invalid regex patterns fail closed with `ERRORED` status.
- Gateway verifies constitution Ed25519 signature on start (enforced mode throws, permissive warns).
- Authority matching uses exact match + opt-in glob (`*` patterns only); no substring matching.
- Downstream env allowlist: only `PATH`, `HOME`, `TMPDIR`, `NODE_ENV`, etc. passed to child processes; explicit `env` config overlaid.
- `IdentityRegistry.register()` rejects expired claims.
- `ApprovalStore` uses atomic writes (`safeWriteJson`) for persistence.
- `safe-io.ts` symlink detection uses `path.parse/path.sep` for cross-platform support.
- Escalation tokens: only SHA-256 hash stored at rest; raw HMAC token returned to caller but never persisted.
- Config secrets support `$ENV{VAR_NAME}` interpolation to avoid plaintext in YAML.
- Gateway config file permission warning on group/world-readable files (non-Windows).
- `redactInObject` has `maxDepth` limit (default 20) to prevent stack overflow on deep objects.
- Webhook delivery: HTTPS-only, no redirect following (`redirect: "error"`), private IP blocking (RFC 1918/6598/loopback/link-local), DNS rebinding protection, 1 MB response body limit.
- Custom evaluator errors produce `passed: true` with `ERRORED` status (no false halts from evaluator failures).
- `CloudHTTPSink`: no-retry on 400/401/403; 409 treated as success (duplicate); exponential backoff with jitter on 429/503/5xx; buffer-and-retry via JSONL for resilience.

---

## Receipt Schema

### Fingerprint dispatch ladder (by `checks_version`)

| cv | Fields | Protocol era |
|---|---|---|
| `>= 9` | 20 | v1.4 (SAN-222): adds tool_name, agent_model, agent_model_provider, agent_model_version at positions 17–20 |
| `== 8` | 16 | v1.3 (SAN-213): adds enforcement_surface, invariants_scope at positions 15–16 |
| `6` or `7` | 14 | v1.1 era: adds parent_receipts_hash, workflow_id_hash at positions 13–14 |
| `< 6` | 12 | Pre-v1.0: original 12 fields |

### 20-field fingerprint (cv=9, v1.4 — current)

Pipe-delimited SHA-256 input:
- Fields 1–12: `correlation_id`, `context_hash`, `output_hash`, `checks_version`, `checks_hash`, `constitution_hash`, `enforcement_hash`, `coverage_hash`, `authority_hash`, `escalation_hash`, `trust_hash`, `extensions_hash`
- Field 13: `parent_receipts_hash` — SHA-256 of canonicalized `parent_receipts` array. `EMPTY_HASH` if null/absent.
- Field 14: `workflow_id_hash` — SHA-256 of UTF-8 `workflow_id`. `EMPTY_HASH` if null/absent.
- Field 15: `enforcement_surface_hash` — `hash_text(enforcement_surface)`. Required at cv>=8 (v1.3+).
- Field 16: `invariants_scope_hash` — `hash_text(invariants_scope)`. Required at cv>=8 (v1.3+).
- Field 17: `tool_name_hash` — `hash_text(tool_name)`. Required at cv>=9 (v1.4+).
- Field 18: `agent_model_hash` — `hash_text(agent_model)`. `EMPTY_HASH` if null/absent.
- Field 19: `agent_model_provider_hash` — `hash_text(agent_model_provider)`. `EMPTY_HASH` if null/absent.
- Field 20: `agent_model_version_hash` — `hash_text(agent_model_version)`. `EMPTY_HASH` if null/absent.

### Required fields by version

**v1.3 required (cv>=8, SAN-213):**
- `enforcement_surface`: `"middleware" | "gateway" | "cli_interceptor" | "http_interceptor"` — labels the code path that emitted the receipt. Hardcoded at every emit site; never read from trace data or caller-declared sources.
- `invariants_scope`: `"full" | "authority_only" | "limited" | "none"` — declares which invariants actually ran.

**v1.4 required (cv>=9, SAN-222):**
- `tool_name`: `"sanna-ts"` — canonical SDK identity. Constant `TOOL_NAME` in `receipt.ts`.

**v1.4 nullable optionals (cv>=9, SAN-222):**
- `agent_model`: captures LLM model name. `null` = opt-out; absent = not captured.
- `agent_model_provider`: LLM provider string.
- `agent_model_version`: LLM version string.

### Prior fields (v1.1)

- `parent_receipts`: `string[] | null` — fingerprints of parent receipts (participates in fingerprint)
- `workflow_id`: `string | null` — groups related receipts (participates in fingerprint)
- `content_mode`: `'full' | 'redacted' | 'hashes_only' | null` — metadata only, NOT in fingerprint
- `content_mode_source`: `string | null` — provenance of mode selection, NOT in fingerprint

### Enforcement override

4-action enforcement override applied at receipt construction time (never via post-hoc mutation):
- `halted` → `FAIL`
- `warned` → `WARN`
- `escalated` → `WARN`
- `allowed` → `PASS`

Override applies when the computed status would be `PASS` but the enforcement action indicates otherwise. Mirrors Python `verify.py:479-491` in `verifier.ts`.

---

## ReceiptSink Architecture

`ReceiptSink` interface (`types.ts`): `store()`, `storeBatch?()`, `flush?()`, `close?()`

| Sink | Implementation |
|---|---|
| `CloudHTTPSink` | POST `/v1/receipts` (single) or `/v1/receipts/batch`. Retry: 429/503/5xx with exponential backoff. No retry: 400/401/403. 409 = success (duplicate). Buffer-and-retry via JSONL. |
| `CompositeSink` | Fan-out with `Promise.allSettled()`, failure isolation, error aggregation. |
| `LocalSQLiteSink` | Wraps `ReceiptStore` as a sink. |
| `NullSink` | No-op for testing. |

**Middleware:** `sannaObserve()` accepts `sink` option; calls `sink.store()` after receipt generation (fire-and-forget).

**Gateway:** Constructor accepts optional `ReceiptSink`. Legacy `receipts.store_path` auto-wraps in `LocalSQLiteSink` with deprecation warning. Content mode from config; `workflow_id` per session; receipt chaining via escalation fingerprint tracking.

---

## Gateway Receipt Chaining

- **Escalation → execution:** When an escalation is approved, the execution receipt's `parent_receipts` includes the escalation receipt's `full_fingerprint`.
- `workflow_id` is set per gateway session (generated on `start()`).
- `content_mode` read from gateway config (`receipts.content_mode`); `content_mode_source = "local_config"`.
- Escalation fingerprints tracked in `_escalationReceiptFingerprints` map for chaining.

---

## Cross-Language Compatibility

Python (`sanna`) and TypeScript (`sanna-ts`) emit interoperable receipts verified against shared golden fixtures.

### Fingerprint eras

- v1.0 Python fixtures: 12-field (cv="5")
- v1.1 era fixtures: 14-field (cv="6" or "7")
- v1.3 fixtures: 16-field (cv="8")
- v1.4 fixtures: 20-field (cv="9") — current

### Test fixture strategy

`cross-language.test.ts` loads v1.4 fixtures from the `sanna-protocol` submodule. Verifies full fingerprint + signature + content hashes against Python-generated fixtures. v1.0 legacy fixtures skip fingerprint recomputation (expected 12-field mismatch).

### Enforcement.action vocabulary

TS internal decision verbs (`"halt"` / `"escalate"` / `"allow"`) map to canonical past-participle forms (`"halted"` / `"escalated"` / `"allowed"`) via `ENFORCEMENT_ACTION_MAP` at all 3 interceptor/gateway emit sites. Python uses past-participles natively.

### Verifier error text

Verifier error text (SAN-214) is byte-equivalent cross-SDK for status mismatches and legacy warnings — third-party tooling can pattern-match on these strings without SDK-specific branches. Language: `"cryptographically valid but semantically defective"` (spec §10 / §13).

---

## ADR Convention

Architectural decisions affecting cross-SDK behavior are recorded in
`sanna-protocol/docs/decisions/` (bootstrapped in a follow-up PR per SAN-326
sequencing). Reference tickets by ID (e.g., SAN-222) in commit messages and
PR bodies — never embed notion.so URLs in committed files.
