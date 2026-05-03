## [Unreleased] -- 2026-05-03 (SAN-380)

### Fixed
- Gateway ListToolsRequestSchema handler: session_manifest emission
  protected by shared-promise pattern. Concurrent tools/list calls
  await the same emission promise (exactly one manifest emitted;
  second call waits for completion). No TOCTOU gap.
  Cross-SDK parity with sanna-repo SAN-380 Prompt A.

### Tickets
- SAN-380 Prompt B (this entry; TS half). Closes SAN-380.

## [Unreleased] -- 2026-05-03 (SAN-379)

### Fixed
- CLI + HTTP interceptors: enforcement.enforcement_mode now emits
  schema-conformant values (halt/warn/log) instead of interceptor
  mode values (enforce/audit/passthrough). Mapping: enforce->halt,
  audit->warn, passthrough->log. Cross-SDK parity with sanna-repo PR #49.

### Tickets
- SAN-379 TS follow-up (this entry).

## [Unreleased] -- 2026-05-03 (SAN-397)

### Added
- `AnomalyTracking` interface + `AuthorityBoundaries.anomaly_tracking`
  (per-surface opt-in for CLI/HTTP invocation_anomaly emission). Default:
  both false (backward compat).
- CLI interceptor: when `anomaly_tracking.cli === true`, suppressed-command
  attempts emit `cli_invocation_anomaly` receipt (substitutes for
  `cli_invocation_halted`). Extensions: `com.sanna.anomaly.attempted_command`.
  parent_receipts chains to active CLI session_manifest.
- HTTP interceptor: when `anomaly_tracking.http === true`, suppressed-endpoint
  attempts emit `api_invocation_anomaly` receipt. Extensions:
  `com.sanna.anomaly.attempted_endpoint`. parent_receipts chains to active
  HTTP session_manifest.
- Spec submodule bumped to include SAN-397 Prompt A (constitution.schema.json
  gains anomaly_tracking field).

### Hash backward-compat
- `constitutionToSignableDict` omits `anomaly_tracking` when at defaults
  (both false). Pre-v1.5 constitutions hash IDENTICALLY without re-signing.
  Cross-language hash parity with Python PR #48.

### Cross-SDK
- Extension shape matches Python byte-for-byte (SAN-395 Section 2.22.2).
- content_mode on receipt envelope only (Section 2.22.5 spec-ahead-of-impl
  consistent with gateway + Python interceptors).

### Tickets
- SAN-397 Prompt C (this entry; TS half). Closes SAN-397.
- Companion: Prompt A (protocol, PR #27), Prompt B (Python, PR #48).

## [Unreleased] -- 2026-05-02 (SAN-359)

### Fixed
- Gateway ListToolsRequestSchema handler now returns empty tools when
  `_emitSessionManifest` fails (generation or persistence). Previously
  the gateway caught manifest failures silently and returned the full
  filtered tool list -- a governance leak.
- `_manifestFailed` state is sticky: once manifest fails, ALL subsequent
  tools/list calls return empty for the gateway lifecycle.
- Belt-and-suspenders: handler wraps `_emitSessionManifest` in try/catch
  as catch-all for unexpected failures.

### Security
- Per PRD CT-7 (fail-closed): no tool-name data leaks to the agent on
  manifest failure. Response is `{ tools: [] }`. Cross-SDK parity with
  sanna-repo SAN-359 Prompt A (PR #47).

### Tickets
- SAN-359 Prompt B (this entry; TS half). Closes SAN-359.
- Companion: SAN-359 Prompt A (Python, PR #47, merged).

## [Unreleased] -- 2026-05-02 (SAN-394)

### Fixed
- `checkSchema()` in verifier.ts now runs ajv-driven validation against the
  bundled receipt.schema.json (draft-2020-12) as a second pass after the
  existing hand-rolled required-field checks. Catches all conditional allOf
  rules: B1 (session_manifest enforcement-absent), B2 (mixed requires multi-
  surface), A1 (cv=10 agent_identity), A3 (com.sanna.manifest implies
  session_manifest), B3 (com.sanna.anomaly implies anomaly event_type), B4
  (anomaly requires com.sanna.anomaly), MODIFY (modify_with_constraints
  requires recording fields), R1+R2 (content_mode redaction rules).
- ajv validates ONLY the allOf conditional rules (not the full schema) to
  avoid duplicating hand-rolled required-field checks with different messages.
  allOf rules have no $ref/$defs dependencies and extract cleanly.
- `ajv-formats` added to production dependencies (previously test-only
  transitive).

### Cross-SDK
- Verdict-level parity restored: same schema-violating receipt now produces
  errors in both Python (jsonschema) and TS (ajv) verifiers. Error message
  TEXT differs between libraries (expected); error PRESENCE is parity-gated.
- Existing byte-equal messages (SAN-370 cv=10, SAN-222 cv=9, SAN-213 cv=8)
  preserved unchanged; ajv pass is additive, not a replacement.

### Tickets
- SAN-394 (this entry).
- Adjacent: SAN-358 (semantic checks, already merged), SAN-395 (spec B3/B4,
  already merged).

## [Unreleased] -- 2026-05-02 (SAN-358 Prompt B)

### Added
- New module `packages/core/src/verifier-manifest.ts` with `verifySessionManifestReceipt()` (9 checks) and `verifyInvocationAnomalyReceipt()` (3 checks). Mirror of Python `src/sanna/verify_manifest.py` from SAN-358 Prompt A (PR #46). Cross-SDK byte-equal verdict text.
- New public function `verifyReceiptSet(receipts, publicKey?)` in verifier.ts for cross-receipt parent-resolution. `verifyReceipt()` signature unchanged (backward compat).
- `Check` interface added to types.ts; optional `checks` field on `VerificationResult`.
- Spec submodule bumped to 0f99a44 (SAN-395: reserves com.sanna.anomaly namespace + B3/B4 schema rules).

### Cross-SDK
- Every Check.message string matches Python character-for-character.
- Cross-language verdict fixture (SAN-358 Prompt C) will assert identical verdicts.

### Tickets
- SAN-358 Prompt B (this entry; TS half).
- Companion: SAN-358 Prompt A (Python, PR #46 merged), SAN-358 Prompt C (sanna-protocol fixture).
- Adjacent: SAN-394 (TS schema-validator gap; orthogonal), SAN-395 (merged; spec namespace).

## [Unreleased] -- 2026-05-02 (SAN-368)

### Added
- **TypeScript parity for sanna-verify aarm.** New module `packages/core/src/aarm.ts` mirrors the Python implementation at sanna-repo f2b53a5. Same SANNA_TO_AARM decision-enum mapping, same six per-requirement check functions (R1 pre-execution interception, R2 parent_receipts chain, R3 constitution policy_hash, R4 decision-enum subset + STEP_UP chain check, R5 fingerprint + signature integrity with redacted-receipt acceptance, R6 cv-aware identity binding), aggregate report, JSON + human output formats.
- `sanna-verify-aarm` CLI subcommand in the TS CLI package. Same flags + exit codes as Python (0 PASS/PARTIAL, 1 FAIL, 2 file errors, 3 internal errors).
- Cross-SDK verdict parity test: TS aggregator produces verdict structure matching Python reference output for the same receipt set (AC #5 closed for the cross-language fixture parity contract).
- New tests in `packages/core/tests/san368-aarm-verifier.test.ts` mirroring Python coverage: 42 tests covering per-check PASS/FAIL/PARTIAL/N/A, STEP_UP chain check, R6 dispatch, redacted-receipt R5 acceptance, fixture-set integration, and cross-SDK parity.

### Compatibility
- **Cross-SDK verdict byte-equal:** TS aggregator and Python aggregator produce identical aggregate_status + per-check status for identical receipt sets (modulo generated_at timestamp).

### Out of scope
- **Spec section "How to verify AARM conformance"** (AC #6). Lands in sanna-protocol SAN-368 portion.
- **SARIF output format.** Marked optional; deferred.

### Tickets
- SAN-368 (this entry; sanna-ts TypeScript portion)
- Predecessor: sanna-repo SAN-368 portion (Python implementation, MERGED at sanna-repo f2b53a5)
- Companion: sanna-protocol SAN-368 portion (operational docs, separate Opus prompt)
- Cross-references: SAN-356 G2, SAN-361, SAN-369, SAN-370, SAN-371

## [Unreleased] -- 2026-05-02 (SAN-369)

### Added
- **MODIFY authority decision recording infrastructure (TypeScript).** `buildModifyAuthorityDecision(action, original, transformed, transformations, options?)` constructs an object matching `AuthorityDecisionRecord` with `decision=modify_with_constraints` and the three required MODIFY recording fields (`tool_input_original`, `tool_input_transformed`, `transformations_applied`) per spec Section 2.7. Validates at construction: transformations is a non-empty array of `{type, target_field, rationale}` objects; `original` and `transformed` are string or plain object (null and arrays rejected). Cross-SDK byte-equal parity with Python helper (`sanna-repo c2c6a39`): identical inputs produce identical record shape, key order, and value semantics. Records produced by the helper satisfy the A1' conditional rule in `receipt.schema.json`.
- New test coverage in `packages/core/tests/san369-modify-recording.test.ts`: 9 tests covering valid construction, key-order parity with Python, construction-time errors for malformed inputs, deterministic byte-equality, and cross-SDK byte-equal shape parity against a hardcoded Python reference output.

### Out of scope
- **Constitution-rule-driven MODIFY emission.** Authority evaluation does NOT yet return `modify_with_constraints`. Rule engine is a separate ticket.
- **Cross-SDK fixture file.** Lands in sanna-protocol SAN-369 portion (hand-constructed + signed with the committed e58ed3e keypair).
- **Implementer's guide example.** Lands in sanna-protocol SAN-369 portion.

### Tickets
- SAN-369 (this entry; sanna-ts TypeScript portion)
- Predecessor: sanna-repo SAN-369 portion (Python helper, MERGED at sanna-repo c2c6a39)
- Companion: sanna-protocol SAN-369 portion (implementer's guide + cross-SDK fixture, separate PR)
- Verifier rejection of MODIFY receipts missing the three fields: SAN-368

## [Unreleased] -- 2026-05-01 (SAN-371)

### Added
- **TypeScript verifier emits CV9_LEGACY-prefixed warning on cv=9 receipts.** When `verifyReceipt(...)` processes a receipt with `checks_version=9`, the warnings array now includes a string starting with `CV9_LEGACY:` indicating partial R6 conformance only (agent_identity is absent at cv<10 per spec Section 2.19). Receipt remains valid; the warning is informational. Cross-SDK parity: warning text is byte-equal to the Python sanna verifier emission.
- New test coverage in `packages/core/tests/cv9-legacy-warning.test.ts` validating: cv=9 receipts emit exactly one CV9_LEGACY warning; cv=10 receipts emit no CV9_LEGACY warning; archive cv=9 fixtures emit the warning.

### Compatibility
- **No-action-required for existing signed cv=9 receipts.** Pre-v1.5 receipts remain cryptographically valid; their 20-field fingerprints continue to verify. Verification output now includes the CV9_LEGACY informational warning.
- **Cross-SDK warning-text byte-equal:** matches Python sanna verifier emission exactly. Audit consumers can pattern-match on the `CV9_LEGACY:` prefix regardless of which SDK verified the receipt.

### Tickets
- SAN-371 (this entry; sanna-ts TypeScript portion -- closes SAN-371)
- Predecessors:
  - SAN-371 sanna-protocol portion (migration memo, MERGED at sanna-protocol a684a33)
  - SAN-371 sanna-repo portion (Python verifier CV9_LEGACY emission, MERGED at sanna-repo ed5ae77)

## [Unreleased] -- 2026-05-01 (SAN-389)

### Fixed
- **Restored strict cross-SDK signature verification.** The cross-language test (`packages/core/tests/cross-language.test.ts`) added a `getVerifyKey()` helper that skipped Ed25519 signature verification when a fixture's `receipt_signature.key_id` did not match the bundled `test-author.pub`. The helper masked an upstream sanna-protocol artifact divergence (cv=10 fixtures signed with a key not in the spec submodule). With sanna-protocol now bundling a self-consistent keypair (commit e58ed3e), the workaround is no longer needed; strict signature verification works for cv=9 archive AND cv=10 active fixtures.

### Changed
- **Bumped `spec/` submodule pin** from 9ee7527 to e58ed3e (sanna-protocol main HEAD post-artifact-self-consistency fix).
- Removed `getVerifyKey()` helper from cross-language.test.ts; all callsites now use the top-loaded `pubKey` directly.

### Compatibility
- **Cross-SDK byte-equal contract intact:** cv=10 fingerprints byte-equal across the sanna-protocol keypair rotation (formula uses pipe-joined receipt fields, not signing key). cross-language.test.ts validates this via fingerprint comparison.
- **Receipt signature compatibility:** post-bump, the bundled `spec/fixtures/keypairs/test-author.pub` matches the cv=10 fixture signatures (test_key_id = 6edb993...). Strict signature verification works in both directions.

### Tickets
- SAN-389 (this entry; sanna-protocol portion merged at e58ed3e)
- Cross-SDK contract: SAN-355
- Unblocks: SAN-386 (v1.5 release coordination)
- Forward-pointer: SAN-391 (make generate_fixtures.py deterministic; idempotent keypair + frozen reference timestamps)

## [Unreleased] -- 2026-05-01 (SAN-370 Prompt C)

### Changed
- **Package versions:** all 4 packages (cli, core, gateway, mcp-server) bumped 1.4.0 -> 1.5.0 (v1.5 SHIPPED moment for TS SDK runtime).
- `packages/core/src/receipt.ts`: SPEC_VERSION 1.4 -> 1.5; CHECKS_VERSION 9 -> 10; TOOL_VERSION 1.4.0 -> 1.5.0.
- `packages/core/src/types.ts`: added `agent_identity?: Record<string, unknown>` field to Receipt interface (spec Section 2.19; AARM R6 binding).
- `packages/core/src/receipt.ts` generateReceipt: accepts `agent_identity` param with cv-dispatch. When provided (and has `agent_session_id`), emits cv=10 with 21-field fingerprint formula adding `agent_identity_hash` at field 21 = `hashObj(agent_identity)`. When absent (library middleware path), emits cv=9 legacy with 20-field formula and hardcoded "1.4"/"9" overrides for byte-equal compatibility with archive fixtures.
- `packages/core/src/receipt.ts` computeFingerprintInput: cv>=10 branch added (21-field formula).
- `packages/core/src/verifier.ts`: cv>=10 required-field check (agent_identity + agent_session_id sub-field). Mirrors Python verify.py post-Prompt-B + SAN-385.
- `packages/gateway/src/gateway.ts`: added `MCPGateway._agentSessionId` (crypto.randomUUID() at constructor; stable for instance lifetime). 3 generateReceipt callers pass `agent_identity: { agent_session_id: this._agentSessionId }` -> cv=10.
- `packages/core/src/interceptors/child-process-interceptor.ts`: lazy-init module-level `_agentSessionId` on first emitReceipt; passed to generateReceipt -> cv=10.
- `packages/core/src/interceptors/fetch-interceptor.ts`: lazy-init module-level `_agentSessionId` on first emit; passed to both generateReceipt callers (invocation + session_manifest) -> cv=10.
- `spec/` submodule: bumped from 03160f1 (post-SAN-378 Prompt A) to 9ee7527 (post-SAN-370 Prompt A; v1.5 protocol artifact).
- Tests: SDK constant assertions flipped to "1.5" / "10" / "1.5.0"; receipt-field assertions case-by-case per emission path; new `packages/core/tests/v15-integrity.test.ts` covers cv=10 emission + verifier required-field check + wire-format parity (agent_identity absent for cv=9, present for cv=10); cross-language.test.ts updated for cv=10 fixtures + getVerifyKey helper for sanna-protocol keypair rotation handling.

### Per-emission-site cv discipline (SAN-370 Issue Y)
- gateway / cli_interceptor (child-process) / http_interceptor (fetch) surfaces emit cv=10 with populated agent_identity.
- middleware surface (sannaObserve / library middleware path) emits cv=9 legacy with no agent_identity, per spec Section 2.19 line 781-782.

### Compatibility
- **Cross-SDK byte-equal restored:** Python (post-SAN-385) and TypeScript (post-SAN-370 Prompt C) emit identical wire format for cv=9 receipts (`agent_identity` absent) and cv=10 receipts (`agent_identity` dict with `agent_session_id`). cross-language.test.ts validates byte-equal fingerprint computation.
- **Receipt fingerprint compatibility:** existing signed cv=9 receipts continue to verify via the 20-field formula; verifier dispatches on `checks_version`. Re-emission post-upgrade from gateway/interceptor produces cv=10 with field 21; library middleware re-emission preserves cv=9 byte-equal output.
- **Wire format alignment:** TS naturally omits undefined optional fields via JSON.stringify; cv=9 emissions have no `agent_identity` key (parity with Python post-SAN-385).
- **Release coordination (SAN-386):** v1.5 SDK lockstep deployment + customer notification required BEFORE any production deploy of cv=10 emission. Merging this PR ships v1.5 to main; npm publish + customer SDK upgrade is gated by SAN-386.

### Tickets
- SAN-370 Prompt C (this entry) -- closes SAN-370
- Predecessors: SAN-370 Prompt A (sanna-protocol 9ee7527), Prompt B (sanna-repo a0ee706), SAN-385 (sanna-repo 36832e3)
- Forward-pointers: SAN-383 (cv<10 negative schema rule, Backlog), SAN-384 (content_mode agent_identity redaction, Backlog), SAN-386 (release coordination, Up Next), SAN-387 (typed AgentIdentityBinding interface, Backlog), SAN-388 (cross-language test archive coverage, Backlog)
- Out-of-scope: SAN-368, SAN-369, SAN-371

## [Unreleased] -- 2026-04-30 (SAN-378 Prompt C)

### Changed
- packages/core/src/manifest.ts: _generateCliSurface and _generateHttpSurface now emit suppression_reasons: Record<string, string> per v1.5 spec Section 2.20.2. Empty dict {} when no suppressions; populated when the constitution declares cannot_execute or must_escalate-with-visibility-suppressed. Mirrors Python SAN-378 Prompt B (sanna-repo e8fb027) and the mcp surfaces existing suppression_reasons algorithm. Cross-SDK byte-equal output preserved.
- packages/core/src/manifest.ts: CliSurface and HttpSurface interfaces updated to include suppression_reasons field.
- spec/ submodule pin bumped from sanna-protocol f89c8c9 to 03160f1 (SAN-378 Prompt A merge: MC-006 + MC-007 fixture vectors updated to include suppression_reasons).
- packages/core/tests/manifest.test.ts: Existing TS manifest tests updated with suppression_reasons assertions for cli/http surface output (8 assertions added across 4 CLI + 4 HTTP tests -- Issue 14-equivalent for SAN-378).

### Compatibility
- **Receipt fingerprint compatibility:** post-SAN-378 receipts include suppression_reasons in cli/http surfaces (per v1.5 Section 2.20.2). This changes the canonical JSON shape and therefore the receipt fingerprint when cli/http surfaces have suppressed entries. Existing signed receipts remain valid (signature is over what was emitted). Re-emission of the same input post-upgrade produces a different fingerprint than pre-upgrade. Verifiers should accept receipts as-emitted; cross-version fingerprint replay is not a conformance test.
- **Cross-SDK lockstep restored:** with this PRs merge, sanna-ts and sanna-repo both emit cli/http surfaces with suppression_reasons. The bounded divergence window (between SAN-378 Prompt B merge and this merge) closes.

### Tickets
- SAN-378 Prompt C (this entry)
- Companion: SAN-378 Prompt A (sanna-protocol fixture update, MERGED at 03160f1), SAN-378 Prompt B (sanna-repo Python implementation, MERGED at e8fb027). SAN-376 (cross-SDK fixture origin), SAN-203 (TS manifest origin, will be annotated post-done on full SAN-378 close), SAN-377 (spec clarification, MERGED), SAN-382 (R1 schema-rule enforcement gap, deferred Backlog).

## [Unreleased] -- 2026-04-30 (SAN-209)

### Added
- packages/core/src/manifest.ts: generateManifest gains surfaces and contentMode params per v1.5 Section 2.14 (post-SAN-377). Cross-SDK byte-equal with Python (SAN-206) via canonical hashContent helper.
- Gateway _emitSessionManifest: passes surfaces=["mcp"] + contentMode. Captures _manifestFullFingerprint BEFORE persistence (Issue 18 governance-honest fail-closed).
- Gateway _suppressedToolNames Set<string> populated by tools/list filter loop. Stores PREFIXED names. Used by _handleToolCall to substitute invocation_anomaly receipt for invocation_halted/invocation_escalated when name is suppressed.
- Gateway _emitInvocationAnomaly: emits invocation_anomaly receipt per v1.5 Section 2.12 + 2.16.3. Receipt: event_type=invocation_anomaly, enforcement_surface=gateway, enforcement.action=halted, enforcement.enforcement_mode=halt, status=FAIL, invariants_scope=authority_only, parent_receipts=[<full_fingerprint>], extensions[com.sanna.anomaly]={attempted_tool, suppression_basis}. Signed via signReceipt if signing key configured.
- packages/core/src/interceptors/child-process-interceptor.ts: patchChildProcess emits per-surface session_manifest at init time. surfaces=["cli"], enforcement_surface=cli_interceptor. Mode-aware fail-closed/fail-open.
- packages/core/src/interceptors/fetch-interceptor.ts: patchFetch entry mirrors CLI. surfaces=["http"], enforcement_surface=http_interceptor.
- New tests: manifest-content-vectors.test.ts (loads SAN-376 fixtures), manifest-content-modes.test.ts (redacted + hashes_only with AJV schema validation), gateway.test.ts TestSessionManifestParentChain (cannot_execute + must_escalate-suppressed + typo negative).

### Changed
- spec/ submodule pin bumped from sanna-protocol 5bfee54 to f89c8c9.
- packages/core/src/evaluator.ts matchesCondition: normalize condition string the same way as context (underscores -> spaces) before keyword extraction. Fixes must_escalate matching when condition contains underscores (e.g. "send_email"). Pre-existing bug revealed by SAN-376 fixture MC-003.

### Compatibility
- generateManifest signature backwards-compatible.
- Gateway session_manifest receipts now include only surfaces.mcp. SAN-203 inherited multi-surface defect resolved.
- Gateway session_manifest receipts under contentMode=redacted/hashes_only apply spec-conformant redaction. SAN-203 inherited content_mode defect resolved.
- New invocation_anomaly receipts SUBSTITUTE for invocation_halted/invocation_escalated on suppressed-tool calls (one receipt per call, not two).
- CLI/HTTP interceptors emit session_manifest at patch time. mode=enforce raises if sink rejects manifest.

### Out of scope (follow-ups filed)
- CLI/HTTP invocation_anomaly variants: pending constitution opt-in field.
- Cross-SDK fixture vectors (MC-008 + redacted/hashes_only): SAN-380 post-this-merge.
- Race condition in session_manifest single-emission across both SDKs: SAN-381.
- spec/impl divergence on cli/http suppression_reasons: SAN-378.

### Tickets
- SAN-209 (this entry)
- Companion: SAN-206 (Python, MERGED 97668d1), SAN-203 (TS origin, annotated x2), SAN-202 (Python origin, annotated x2), SAN-204, SAN-205, SAN-376, SAN-377 (merged), SAN-378/379/380/381 (deferred).

## [Unreleased] -- 2026-04-30 (SAN-203)

### Added
- New module `packages/core/src/manifest.ts` with `generateManifest(constitution, mcpTools?)`. Mirror of Python's `src/sanna/manifest.py` from sanna-repo SAN-202 PR #37. Produces the `com.sanna.manifest` extension dict per v1.5 spec Section 2.20: snake_case keys; deterministic sorted lists; stable suppression_reason enum (Section 2.21); per-surface breakdown (mcp / cli / http); fail-closed when constitution is null.
- Gateway `tools/list` handler applies authority filtering: suppress `cannot_execute` tools; suppress `must_escalate` tools when `constitution.authority_boundaries.escalation_visibility === 'suppressed'`; deliver others. Suppressed tools are absent from the response (anti-enumeration).
- Gateway emits a `session_manifest` receipt on the FIRST tools/list call per gateway lifecycle. State-tracked via `_manifestEmitted: boolean`. Receipt has `event_type="session_manifest"`, `invariants_scope="none"`, `enforcement` absent (per v1.5 Section 2.16.3). Cross-language parity with Python (sanna-repo SAN-202).

### Compatibility
- Pre-Manifest gateway behavior preserved when no constitution is loaded: tools pass through unfiltered, no manifest receipt emitted.
- v1.4-era constitutions (no `escalation_visibility`) default to `"visible"` per SAN-205 TS half (PR #26). must_escalate tools remain in tools/list as before.

### Tickets
- SAN-203 (this entry)
- Companion: SAN-202 (Python, PR #37 merged), SAN-209 (TS interceptor manifest emission), SAN-206 (Python interceptor manifest emission), SAN-205 (constitution authority enum, merged), SAN-375 (TS schema sync, merged), SAN-204 (v1.5 protocol schema, merged).

## [Unreleased] -- 2026-04-30 (SAN-205)

### Added
- `AuthorityBoundaries.escalation_visibility` (v1.5+, default `"visible"`; backward compatible).
- `Composition` interface + optional `Constitution.composition` field.
- `AuthorityDecisionType` extended from `"halt" | "allow" | "escalate"` to add `"modify"` and `"defer"` (v1.5+; reserved for future runtime evaluators starting with SAN-369). evaluateAuthority does not return either value in v1.5.
- `BoundaryType` legal values extended with `modify_with_constraints` and `defer_for_context` (v1.5+; reserved).

### Hash backward-compat
- `constitutionToSignableDict` builds `authority_boundaries` manually; `escalation_visibility` is included ONLY when non-default (`"suppressed"`). Pre-v1.5 constitutions hash IDENTICALLY without re-signing. Mirrors the Python fix from PR #36 (sanna-repo SAN-205 Python half).

### Compatibility
- v1.4-era constitutions WITHOUT escalation_visibility or composition parse cleanly; defaults applied. No migration needed.
- Cross-language hash parity preserved: TS and Python produce identical hashes for the same v1.4-era constitution.

### Tickets
- SAN-205 TS half (this entry; companion Python PR #36 already merged in sanna-repo).
- Companion: SAN-203 (TS gateway filtering, depends on this), SAN-204, SAN-375 (already merged), SAN-374 (already merged).

## [Unreleased] -- 2026-04-30

### Changed
- Submodule `spec/` bumped from sanna-protocol commit `72097f2` to `5bfee54` (post-SAN-204; sanna-protocol v1.5 release). v1.5 introduces 10 new event_type values, the `mixed` enforcement_surface, agent_identity field (required at cv=10), the com.sanna.manifest extension namespace, the suppression_reason enum, and the modify_with_constraints + defer_for_context authority decisions.

### Compatibility
- cv=9 receipts continue to validate against the new schema (SAN-204 used CONDITIONAL cv=10 rules so the new requirements are no-ops at cv<10). All existing tests pass.
- This bump alone does NOT activate cv=10 in the SDK. SDK code flips CHECKS_VERSION 9 -> 10 in SAN-370.

### Tickets
- SAN-375 (this entry)
- Companion: SAN-374 (sanna-repo schema sync, already merged), SAN-205 (constitution authority enum + escalation_visibility), SAN-203/209/370/371 (TS feature work that depends on this sync).

# Changelog

All notable changes to the sanna-ts SDK are documented here.
Format: Keep a Changelog. Versioning: Semantic Versioning.

## [1.4.0] - 2026-04-21

### Added
- New required top-level field `tool_name` (v1.4+, required at cv>=9). Canonical SDK identity constant `"sanna-ts"` in TS. Participates in fingerprint as position 17.
- New optional nullable fields `agent_model`, `agent_model_provider`, `agent_model_version`. Capture LLM model identity at receipt generation. Null = opt-out; absent = not captured. Fingerprint positions 18-20.
- Verifier v1.4 required-field check: rejects cv>=9 receipts missing `tool_name`. Error text byte-equivalent to Python SDK and spec §13.
- Verifier 20-field fingerprint dispatch for cv>=9.

### Changed
- `SPEC_VERSION` bumped to `"1.4"`.
- `CHECKS_VERSION` bumped to `"9"`.
- `TOOL_VERSION` changed to bare semver `"1.4.0"` (was tool-qualified `"sanna-ts/1.3.0"`). SDK identity now lives in the new `tool_name` field.
- All 4 npm packages bumped to `1.4.0` (core was `1.1.1`; cli, gateway, mcp-server were `1.0.2`). Closes the package-version lag noted in SAN-217.
- Fingerprint algorithm extended from 16 to 20 fields at cv=9. Legacy receipts (cv=8, cv=6/7, cv=5) unchanged.
- Spec submodule advanced to sanna-protocol main (1532f28), picking up v1.4 schema and canonical fixtures.

### Security (SAN-228)

- **Pin 4 transitive deps to patched versions via `package.json` overrides:**
  hono ≥4.12.12 (auth bypass, cookie injection, SSE injection, path traversal),
  @hono/node-server ≥1.19.13 (auth bypass via encoded slashes),
  express-rate-limit ≥8.2.2 (IPv4-mapped IPv6 bypass),
  path-to-regexp ≥8.4.0 (ReDoS × 2).
  All 4 are transitive through `@modelcontextprotocol/sdk`, which still
  declares ranges admitting vulnerable versions. SAN-253 tracks upstream
  coordination. Overrides can be removed when upstream catches up.
- **CI gate:** `npm audit --omit=dev --audit-level=high` now fails PRs on
  any HIGH or CRITICAL advisory in production deps.
- **Dependabot:** enabled via `.github/dependabot.yml` for ongoing scans.

## [1.3.0] - 2026-04-19

### Added
- 16-field fingerprint formula (CHECKS_VERSION 8) with
  enforcement_surface_hash and invariants_scope_hash at positions
  15-16. SAN-213.
- Required Receipt fields enforcement_surface and invariants_scope
  for v1.3+ receipts.
- 4-action enforcement override in generateReceipt:
  halted→FAIL, warned→WARN, escalated→WARN (only when computed
  status is PASS). Mirrors Python receipt.py:678-692.
- Verifier 4-action enforcement override in checkStatusConsistency.
  Mirrors Python verify.py:479-491.
- Verifier v1.3 required-field assertion: rejects cv>=8 receipts
  missing enforcement_surface or invariants_scope. Mirrors Python
  verify.py:900-919.
- Centralized TOOL_VERSION constant in receipt.ts; bundle.ts
  imports it.
- Hardcoded enforcement_surface labels at all emit sites:
  middleware ("middleware"), child-process-interceptor
  ("cli_interceptor"), fetch-interceptor ("http_interceptor"),
  gateway ("gateway"), mcp-server ("middleware"), cli demo and
  generate ("middleware").
- Vocabulary normalization: TS internal decision verbs
  ("halt"/"escalate"/"allow") map to canonical Sanna spec
  enforcement.action values ("halted"/"escalated"/"allowed") via
  ENFORCEMENT_ACTION_MAP at all interceptor and gateway emit sites.
- Cross-language v1.3 fixture verification test.
- HALT-regression guard tests at child-process and fetch
  interceptors.

### Changed
- SPEC_VERSION 1.1 → 1.3.
- CHECKS_VERSION 7 → 8.
- tool_version default sanna-ts/1.1.0 → sanna-ts/1.3.0.
- Spec submodule advanced to sanna-protocol v1.3.

### Removed
- Non-spec "HALT" status value from interceptor receipts. Status
  now derived from enforcement.action via the canonical mapping.
- Stale local CHECKS_VERSION="6" override in mcp-server. Now
  imports from core.
