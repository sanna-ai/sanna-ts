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
