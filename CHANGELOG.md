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
