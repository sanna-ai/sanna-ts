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
