# CLAUDE.md — sanna-ts

TypeScript monorepo for the Sanna protocol. AGPL-3.0. All packages at v1.0.0.

## Structure

- packages/core/ — @sanna-ai/core (SDK: crypto, receipts, constitutions, governance, sinks)
- packages/cli/ — @sanna-ai/cli (16 commands: init, keygen, sign, verify, verify-constitution, approve, inspect, diff, demo, check-config, drift-report, gateway, migrate, bundle-create, bundle-verify, generate)
- packages/gateway/ — @sanna-ai/gateway (MCP enforcement proxy)
- packages/mcp-server/ — @sanna-ai/mcp-server (10 governance tools via MCP)
- examples/constitutions/ — 6 gateway constitution templates with evaluation order docs
- spec/ — git submodule → sanna-ai/sanna-protocol (golden fixtures, schemas)

## Build & Test

- npm install (from root, workspaces auto-linked)
- npm run build (tsup, builds all 4 packages)
- npm test (vitest, 771 tests across 44 files)

## Packages

### @sanna-ai/core (packages/core/src/)

- hashing.ts — RFC 8785 JCS canonicalization, SHA-256
- crypto.ts — Ed25519 via Node.js native crypto, ZERO external deps
- constitution.ts — YAML parsing, validation, signing, signature verification
- evaluator.ts — 4-tier authority evaluation with exact-match + opt-in glob
- receipt.ts — 14-field fingerprint (v1.1), UUID, Ed25519 signing
- verifier.ts — schema + signature + fingerprint + timestamp verification
- checks.ts — coherence checks engine (boundary, authority, halt condition, invariant)
- invariants.ts — invariant check definitions and runner (safe-regex2 ReDoS protection)
- middleware.ts — constitutional middleware pipeline with pre/post hooks, ReceiptSink integration
- store.ts — SQLite receipt persistence (better-sqlite3, WAL mode)
- drift.ts — drift analysis with linear regression and breach projection
- bundle.ts — evidence bundle create/verify (adm-zip, 7-step verification)
- approval.ts — multi-party approval workflows with quorum logic
- identity.ts — Ed25519 identity claims with issuance and verification
- safe-io.ts — hardened file I/O (symlink checks, atomic writes, size limits)
- constitution-diff.ts — structural diffing between constitution versions
- evaluator-registry.ts — custom invariant evaluator registry (register, get, list, clear)
- evaluators/llm.ts — LLM-as-Judge semantic evaluators via Anthropic Messages API (fetch, zero deps)
- otel-exporter.ts — OpenTelemetry bridge: receipt → span (pointer + integrity hash)
- reasoning/ — reasoning evaluation pipeline with heuristic judge
- sinks/types.ts — ReceiptSink interface, SinkResult, FailurePolicy
- sinks/cloud-http-sink.ts — HTTPS receipt delivery (retry, batch, buffer-and-retry, native fetch)
- sinks/composite-sink.ts — fan-out to multiple sinks with failure isolation
- sinks/local-sqlite-sink.ts — SQLite persistence via ReceiptStore wrapper
- sinks/null-sink.ts — no-op sink for testing
- types.ts — shared TypeScript interfaces (Receipt, ReceiptSink, ContentMode, etc.)

### @sanna-ai/cli (packages/cli/)

16 commands via commander: init, keygen, sign, verify, verify-constitution, approve, inspect, diff, demo, check-config, drift-report, gateway, migrate, bundle-create, bundle-verify, generate. ESM-only with shebang, bin: `sanna`.

### @sanna-ai/gateway (packages/gateway/src/)

MCP enforcement proxy — sits between client and downstream MCP servers:

- config.ts — YAML config loading, validation, $ENV{} interpolation, permission warnings
- gateway.ts — core proxy (tool interception, authority evaluation, receipt generation, ReceiptSink, content mode attestation, receipt chaining)
- downstream.ts — child process MCP server connections via StdioClientTransport (env allowlist)
- escalation.ts — HMAC-SHA256 escalation token management (SHA-256 hashed at rest)
- receipt-v2.ts — receipt triad hashing (input/reasoning/action)
- pii.ts — PII redaction (email, SSN, phone, IP, credit card; ReDoS-safe CC detection, depth-limited recursion)
- circuit-breaker.ts — CLOSED/OPEN/HALF_OPEN failure isolation
- tool-namespace.ts — `{downstream}_{tool}` namespacing
- schema-mutation.ts — `_justification` parameter injection/extraction
- migrate.ts — Claude Desktop / Cursor config migration
- webhook.ts — webhook token delivery with SSRF protection (private IP blocking, no redirects)
- file-delivery.ts — file-based token delivery (atomic writes, TTL pruning, size caps)

### @sanna-ai/mcp-server (packages/mcp-server/)

10 MCP tools: evaluate_authority, generate_receipt, verify_receipt, query_receipts, drift_report, get_constitution, verify_constitution, list_checks, check_constitution_approval, verify_identity_claims. Stdio transport.

## Key Decisions

- Node 22+ required (native Ed25519 support)
- PEM key format matches Python `cryptography` library (PKCS8/SPKI)
- Empty arrays/objects use Python falsy semantics for fingerprint compatibility
- All cross-language interop verified against golden fixtures from sanna-protocol
- ESM + CJS dual output for core; ESM-only for cli, gateway, mcp-server
- canonicalize and safe-regex2 bundled into core via tsup noExternal (no createRequire shim)
- better-sqlite3 for receipt store (synchronous API, WAL mode)
- MCP SDK: Client from `@modelcontextprotocol/sdk/client/index.js`, Server from `@modelcontextprotocol/sdk/server/index.js`
- InMemoryTransport from `@modelcontextprotocol/sdk/inMemory.js` for integration tests

## Security Hardening

- Credit card regex uses two-pass approach (strip separators, match digit runs) to avoid ReDoS
- Invariant regex patterns validated by safe-regex2 before execution; unsafe patterns fail-closed with UNSAFE_PATTERN status
- Unknown/undetectable invariant types fail closed with UNKNOWN_TYPE status
- Invalid regex patterns fail closed with ERRORED status
- Gateway verifies constitution Ed25519 signature on start (enforced mode throws, permissive warns)
- Authority matching uses exact match + opt-in glob (* patterns only); no substring matching
- Downstream env allowlist: only PATH, HOME, TMPDIR, NODE_ENV, etc. passed to child processes; explicit env config overlaid
- IdentityRegistry.register() rejects expired claims
- ApprovalStore uses atomic writes (safeWriteJson) for persistence
- safe-io.ts symlink detection uses path.parse/path.sep for cross-platform support
- Escalation tokens: only SHA-256 hash stored at rest, raw HMAC token returned to caller but never persisted
- Config secrets support $ENV{VAR_NAME} interpolation to avoid plaintext in YAML
- Gateway config file permission warning on group/world-readable files (non-Windows)
- redactInObject has maxDepth limit (default 20) to prevent stack overflow on deep objects
- Webhook delivery: HTTPS-only, no redirect following (redirect: "error"), private IP blocking (RFC 1918/6598/loopback/link-local), DNS rebinding protection, 1 MB response body limit
- Custom evaluator errors produce passed: true with ERRORED status (no false halts from evaluator failures)

## Receipt Schema (v1.1)

14-field fingerprint (pipe-delimited, SHA-256):
- Fields 1–12: correlation_id, context_hash, output_hash, checks_version, checks_hash, constitution_hash, enforcement_hash, coverage_hash, authority_hash, escalation_hash, trust_hash, extensions_hash
- Field 13: parent_receipts_hash — SHA-256 of canonicalized parent_receipts array. EMPTY_HASH if null/absent.
- Field 14: workflow_id_hash — SHA-256 of UTF-8 workflow_id string. EMPTY_HASH if null/absent.

New receipt fields (v1.1):
- parent_receipts: string[] | null — fingerprints of parent receipts (participates in fingerprint)
- workflow_id: string | null — groups related receipts (participates in fingerprint)
- content_mode: 'full' | 'redacted' | 'hashes_only' | null — metadata only, NOT in fingerprint
- content_mode_source: string | null — provenance of mode selection, NOT in fingerprint

SPEC_VERSION = "1.1", CHECKS_VERSION = "6", tool_version = "sanna-ts/1.0.0"

## ReceiptSink Architecture

ReceiptSink interface (types.ts): store(), storeBatch?(), flush?(), close?()
- CloudHTTPSink: POST /v1/receipts (single) or /v1/receipts/batch. Retry: 429/503/5xx with exponential backoff. No retry: 400/401/403. 409 = success (duplicate). Buffer-and-retry via JSONL file.
- CompositeSink: fan-out with Promise.allSettled(), failure isolation, error aggregation
- LocalSQLiteSink: wraps ReceiptStore as sink
- NullSink: no-op for testing

Middleware: sannaObserve() accepts `sink` option, calls sink.store() after receipt generation (fire-and-forget).
Gateway: constructor accepts optional ReceiptSink. Legacy receipts.store_path auto-wraps in LocalSQLiteSink with deprecation warning. Content mode from config, workflow_id per session, receipt chaining via escalation fingerprint tracking.

## Protocol Spec

This SDK implements Sanna Protocol v1.1. See spec/spec/sanna-protocol-v1.0.md.
