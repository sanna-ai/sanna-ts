# Changelog

All notable changes to the sanna-ts SDK are documented here.
Format: Keep a Changelog. Versioning: Semantic Versioning.

## [Unreleased] -- 2026-07-09 (SAN-863)

### Changed
- `@sanna-ai/core`: `invariants_scope` is now DERIVED from observed execution instead of defaulting to `"full"` when a caller omits it. Assurance metadata must reflect what actually ran, not the most flattering value; a receipt that omitted `invariants_scope` previously claimed full invariant coverage even when a declared invariant never executed. `generateReceipt` (`packages/core/src/receipt.ts`) now computes the emitted scope from the `checks` array: every invariant declared by the constitution must have produced an executed check entry (status not in the not-evaluated set) or the claim is downgraded to `"limited"`. A caller-supplied scope other than `"full"` (for example `"authority_only"` or `"none"`) is still honored unchanged -- it is never upgraded, since those values already understate coverage. `sannaObserve` (`packages/core/src/middleware.ts`) now passes the constitution's declared invariant IDs through so the derivation uses the true declared set rather than a proxy; the gateway and MCP server call sites are unchanged and continue to rely on the proxy (the invariant IDs present in the emitted checks), matching the equivalent Python SDK surfaces.
- TS's not-evaluated status set is wider than Python's: in addition to `NOT_CHECKED` and `ERRORED`, the built-in invariant runners in `packages/core/src/invariants.ts` also emit `UNKNOWN_TYPE` (the invariant's rule could not be classified) and `UNSAFE_PATTERN` (a regex pattern was rejected before evaluation as a ReDoS guard) -- both mean the declared rule did not run and are treated as not-evaluated for coverage purposes. This does not change enforcement outcomes; whether a check ran (coverage) and what it decided (pass/fail) remain independent questions.

### Added
- When `invariants_scope` is downgraded to `"limited"`, the receipt now carries a `com.sanna.coverage` extension (`extensions["com.sanna.coverage"]`) with `invariants_declared`, `invariants_executed`, and a `skipped` list of `{id, reason}` entries (`reason` is the observed status, or `"DROPPED"` if the invariant never produced a check entry at all). This extension participates in the receipt fingerprint and signature like any other extension field.
- `packages/core/tests/san863-invariants-scope.test.ts` (new): covers the derivation directly -- unrecognized invariants, invariants that never reach the checks array, explicit `null` vs `undefined` status handling, a caller-declared `"full"` being downgraded when execution does not support it, a caller-declared `"authority_only"` being honored unchanged in both directions, the zero-declared-invariants case, C1-C5 coherence checks not affecting coverage, fingerprint/signature self-consistency for both the `"full"` and `"limited"` shapes, and a negative control that no code path emits `"full"` while invariants are missing.
- `packages/core/tests/middleware.test.ts`: new `SAN-863` describe block drives the derivation end-to-end through `sannaObserve` with a real constitution, proving the declared-invariant-ID wiring from the resolved constitution through to the emitted `invariants_scope` and coverage extension.

### Security
- Because `invariants_scope` and any new `com.sanna.coverage` extension participate in the fingerprint (`computeFingerprintInput`, fields 12 and 16), **receipt fingerprints change** for any caller whose checks previously included a declared invariant that did not actually execute. This is expected and correct: those receipts were previously claiming a coverage guarantee the SDK could not back up. Fingerprints computed by prior versions of the SDK for such receipts are not comparable to fingerprints computed by this version. Receipts where every declared invariant executed, or where the caller declares a non-`"full"` scope explicitly (interceptors, gateway authority-only paths), are unaffected.

## [Unreleased] -- 2026-07-09 (SAN-848)

### Fixed
- `@sanna-ai/gateway`: the Receipt Triad is now embedded at `extensions["com.sanna.gateway"].receipt_triad` instead of a top-level `receipt_triad` property. The canonical `receipt.schema.json` has `additionalProperties: false` at the top level and does not declare `receipt_triad` there, so every gateway-emitted receipt previously failed full JSON-schema validation. This also corrects `action_hash`, which used to hash the real downstream tool result -- a semantic contradiction of the gateway-boundary definition (the gateway is a proxy and cannot attest to what the downstream server actually executed). `action_hash` now equals `input_hash` with `context_limitation: "gateway_boundary"`, matching Python's `sanna.gateway.receipt_v2.compute_receipt_triad` / `sanna.gateway.server._generate_receipt`.
- `computeActionHash` removed from `@sanna-ai/gateway` (packages/gateway/src/receipt-v2.ts, re-exported from index.ts) -- its only callers were the three triad-construction sites in `gateway.ts`, all of which now derive `action_hash` from `input_hash` directly. `buildReceiptTriad` no longer takes an `action_hash` parameter; it derives `action_hash` and sets `context_limitation: "gateway_boundary"` internally.

### Security
- Because the triad now lives inside `extensions`, which participates in the receipt fingerprint (`packages/core/src/receipt.ts` `computeFingerprintInput`), **gateway receipt fingerprints change** relative to prior `@sanna-ai/gateway` versions for the same logical tool call. This is expected: the triad is now actually covered by the cryptographic fingerprint and signature it previously was not. Fingerprints computed by prior versions of the SDK for gateway receipts are not comparable to fingerprints computed by this version.

### Added
- `packages/gateway/tests/san848-receipt-triad-placement.test.ts` (new): drives real allow/halt/escalate tool calls through a signed gateway and asserts (1) the triad lives at `extensions["com.sanna.gateway"].receipt_triad` with `action_hash === input_hash` and `context_limitation === "gateway_boundary"`, and the old top-level `receipt_triad` property is absent; (2) each receipt's fingerprint recomputes to its own stated `full_fingerprint`/`receipt_fingerprint` and its signature independently verifies (self-consistency, allow + halt + escalate); (3) each receipt passes the COMPLETE canonical `receipt.schema.json` (not just the `allOf` conditional slice `packages/core/src/verifier.ts` compiles) via a dedicated Ajv instance, with a negative control proving a reintroduced top-level `receipt_triad` property fails `additionalProperties: false`; (4) a redaction-enabled receipt still passes its own fingerprint recomputation.

### Known Issues (discovered during SAN-848, not fixed here -- follow-up needed)
- `packages/gateway/src/gateway.ts`'s allow-path response construction ("m. Return result with receipt metadata") pushes the `_sanna_receipt` summary text block onto `resultContent`, which is the SAME array object as `receipt.outputs.content` (set via `outputs: { content: result.content }` in `_buildReceipt` without cloning). That in-place mutation happens AFTER the receipt has already been fingerprinted and signed. Any `ReceiptSink` implementation that retains a live object reference instead of serializing synchronously at `store()` time (unlike the shipping `LocalSQLiteSink`/`CloudHTTPSink`, which happen to serialize before their first internal `await`) would observe a receipt whose `outputs.content` no longer matches what was signed -- a real, orthogonal self-consistency defect, out of SAN-848's scope (it is unrelated to where the Receipt Triad lives). `san848-receipt-triad-placement.test.ts`'s `CaptureSink` snapshots via `structuredClone` at store-time specifically to avoid conflating this pre-existing defect with SAN-848's own fix.
- The spec's Appendix E.3 ("Receipt Triad Extension Fields") documents gateway extension fields as flat properties directly under `extensions["com.sanna.gateway"]` (`input_hash`, `reasoning_hash`, `action_hash`, `assurance`, `justification_present`, `justification_evaluated`) -- not nested under a `receipt_triad` sub-key, and using `assurance` rather than `context_limitation`. Python's actual gateway implementation (`sanna.gateway.receipt_v2.GatewayReceiptV2`, `RECEIPT_VERSION_2 = "2.0"`) already diverges from that documented shape by nesting under `receipt_triad` with `context_limitation`, alongside sibling `receipt_version`/`action`/`enforcement` sub-objects Appendix E.3 does not mention at all. This TS fix intentionally matches Python's actual v2.0 shape (per SAN-848's cross-SDK parity mandate), so it now shares that pre-existing divergence from Appendix E.3 rather than introducing a new one. Separately, spec Section 7.5 ("Gateway Boundary") is written as part of the first-class top-level Receipt Triad section (7.1-7.4), suggesting gateway receipts may have originally been intended to also carry first-class top-level `input_hash`/`reasoning_hash`/`action_hash`/`context_limitation` fields (the same mechanism `packages/core/src/interceptors/*.ts` use for CLI/HTTP receipts) -- in practice neither SDK's gateway does this; the top-level mechanism is treated as interceptor-specific (see the `hasTopTriad` / "Interceptor assurance" comment in `packages/core/src/verifier.ts`). Not changed here (would require changing sanna-protocol and/or Python); flagged for a follow-up ticket to reconcile Appendix E.3 with the actual v2.0 shape.

---

## [Unreleased] -- 2026-06-18 (SAN-818)

### Security
- `@sanna-ai/core` hashing: `__proto__` (and any prototype-setter) keys are now included in canonical hashing and signing instead of being silently dropped — fixes a signature/fingerprint bypass and restores cross-SDK parity with the Python SDK (SAN-818). Objects with a `__proto__` own data property (e.g. from `JSON.parse`) are now faithfully canonicalized; fingerprints of objects without `__proto__` are byte-identical to the previous behavior.

---

## [Unreleased] -- 2026-06-10 (SAN-803)

### Added
- `docs/ts-sdk-reference.md` -- TypeScript SDK reference (structural twin of the Python pair, TS-derived behavior including the interceptor behavior matrix with exact thrown types per surface and a confirmed no-reasoning-gate statement for sannaObserve).
- `docs/cookbook.md` -- TypeScript SDK cookbook (delta recipes: subprocess and fetch interceptors, custom invariant evaluator, drift report, evidence bundle, CloudHTTPSink delivery to Sanna Cloud).

### Fixed
- README hero: "the gateway surface enforces governance pre-execution" corrected to "the gateway and interceptor surfaces enforce governance pre-execution" (packages/core/src/index.ts lines 201-207 ship patchChildProcess + patchFetch).
- README hero verb agreement; CLI Reference table completed (12 -> 17 commands: approve, bundle-create, bundle-verify, generate, verify-aarm).

---

## [1.5.0] - 2026-06-09

### 2026-06-09 (SAN-519)

#### Changed
- Cleared all pre-existing lint errors across packages/*/src (tseslint recommended); 4 targeted inline suppressions with rationale (heuristic-judge.ts interface-required params; AnyFn pass-through alias uses any (not unknown) so .apply() call sites keep the original Function semantics -- the unknown variant failed the DTS typecheck (caught by CI Build)); zero behavior changes (full suite unchanged: 73 files, 1545 tests).
- CI now gates `npm run lint` (new step after Build) so lint errors cannot accumulate silently.

---

### 2026-06-09 (SAN-796 gold polish)

#### Fixed
- CLI --version now reports the real package version (was hard-coded 1.0.0); derived from package.json at runtime.
- Internal @sanna-ai/* dependencies pinned to ^1.5.0 (were "*", which npm publishes literally -- could pair new packages with the old core 1.1.1).
- cli/gateway/mcp-server now ship LICENSE (AGPL-3.0) and README.md (files arrays referenced them but they did not exist).
- gateway dist bin had a stacked shebang (source shebang + tsup banner both emitted); removed source shebang so tsup banner is the sole injector.
- @sanna-ai/core npm README: protocol version v1.3 -> v1.5; SPEC_VERSION "1.3" -> "1.5"; CHECKS_VERSION "8" -> "10"; TOOL_VERSION "sanna-ts/1.3.0" -> "1.5.0"; computeFingerprintInput description updated to cover 21-field (cv>=10) and 20-field (cv>=9) paths.
- Root README CLI command count 16 -> 17.

#### Added
- Version-parity test: TOOL_VERSION must equal @sanna-ai/core package.json version.

---

### 2026-06-09 (SAN-796 / SAN-797 / SAN-798)

#### Security
- Bump hono (^4.12.25) and qs (^6.15.2) out of the MODERATE advisory ranges (transitive via the gateway @modelcontextprotocol/sdk path). Closes SAN-798. Dep-update SLA SAN-501 / SOC 2 6.6 evidence trail.

#### Changed
- Declare `tsx` as a devDependency so a clean offline `npm ci && npm test` no longer relies on npx auto-fetching it (SAN-797).

#### Fixed
- README quickstart: install `@sanna-ai/cli` for the `sanna` commands (core has no bin); corrected the gateway invocation; version notes 1.4.0 -> 1.5.0 (SAN-796 Part 2).

---

### 2026-06-03 (SAN-765 Phase D3)

#### Added

- **`packages/core/tests/allow-conformance.test.ts`** (new): cross-SDK allow-disposition conformance test (SAN-765). Drives the fetch and child_process interceptors with an allowed (can_execute) action in enforce mode and asserts the emitted receipt matches the shared protocol fixture (`allow_disposition_vectors`), including `assurance="partial"` per spec Section 7.3. Companion to the sanna-repo allow-conformance suite; both SDKs now assert the same allowed-path vector. action_hash is not pinned (the executed action's output hash is environment-dependent).

---

### 2026-06-03 (SAN-765 Phase D2)

#### Changed

- **`packages/core/src/verifier.ts`** (`checkSchema`): added spec Section 7.3 assurance rule -- an authority-only receipt that carries a Receipt Triad must have `assurance="partial"`; any other value is a verifier error. Error text matches Python `verify.py` byte-for-byte for cross-SDK consistency (SAN-765, lockstep with sanna-repo C2). Allow-list consumer assertions land in Phase D3.
- **`packages/core/tests/verifier-7.3-assurance.test.ts`** (new): two-case verifier rule test driven by a real allowed-action interceptor receipt (`echo hello` via child_process interceptor, `invariants_scope=authority_only`, `assurance=partial`). Asserts no 7.3 error on the valid receipt and the exact 7.3 message + `valid=false` on a tampered `assurance=full` copy.
- **`packages/core/tests/escalate-conformance.test.ts`**: added `assurance: string` to the `DispositionVector.expected` interface and replaced the placeholder comment with `expect(receipt.assurance).toBe(expected.assurance)`, closing the SAN-765 cross-SDK conformance gap in this test.

---

### 2026-06-03 (SAN-765 Phase D1)

#### Changed

- **`spec`** (submodule): bumped pin to 323c7af (protocol main HEAD), picking up spec 7.3 assurance-when-triad enforcement and cross-SDK conformance vectors (SAN-765 #49). Verifier enforcement in sanna-ts lands in Phase D2.

---

### 2026-06-03 (SAN-789)

#### Changed

- **`packages/core/tests/spec-pin-integrity.test.ts`**: harden the spec-pin-integrity test to deepen a shallow submodule clone before the is-ancestor check, fixing a cross-SDK-smoke false negative. A depth-1 clone lacks the parent chain between origin/main and an older-but-merged pin, causing merge-base --is-ancestor to wrongly report the pin unreachable; the fix calls git fetch --unshallow when the submodule is detected as shallow. Genuinely dangling or unmerged pins still fail. (SAN-789, follow-up to SAN-667)

---

### 2026-06-03 (SAN-765)

#### Changed

- **`packages/core/src/interceptors/fetch-interceptor.ts`**, **`packages/core/src/interceptors/child-process-interceptor.ts`**: HTTP and subprocess interceptors now emit `assurance: "partial"` unconditionally, fixing a spec section 7.3 non-conformance. The prior `halted ? "partial" : "full"` emitted `"full"` for executed actions that were never reasoning-evaluated; authority-only interceptors must always emit `"partial"` regardless of outcome. Fingerprint-inert. (SAN-765)

---

### 2026-06-02 (SAN-752)

#### Changed

- **README.md**: corrected schema version claims to match the current implementation. Receipt Schema v1.5 (was v1.4): spec_version "1.5" (was "1.4"), checks_version "10" (was "9"), 21-field fingerprint (was 20), adding agent_identity at fingerprint position 21. Schema reference table, example receipt JSON, and cross-language compatibility note updated consistently. Protocol version reference updated to v1.5; corrected the sannaObserve enforcement framing (post-execution detection and attestation; pre-execution prevention is on the gateway surface). (SAN-752)

---

### 2026-06-02 (SAN-667)

#### Added

- **`packages/core/tests/spec-pin-integrity.test.ts`**: cross-SDK parity -- ports sanna-repo's spec-submodule pin-on-protocol-main guard to sanna-ts. Fails CI if the `spec` submodule is ever pinned to a commit not reachable on sanna-protocol `origin/main` (dangling or unmerged PR-branch HEAD -- supply-chain control). Network-unavailable paths skip on local dev but throw loudly in CI (`CI`/`GITHUB_ACTIONS` env). Matches the invariant enforced by sanna-repo (SAN-667).

---

### 2026-05-29 (SAN-745)

#### Added

- **`packages/core/tests/escalate-conformance.test.ts`**: cross-SDK escalate-disposition conformance test. Drives the fetch + child_process interceptors with a must_escalate decision in enforce mode and asserts the emitted receipt matches the shared protocol fixture (`spec/fixtures/multi-surface-vectors.json` -> `escalate_disposition_vectors`) and that the action did not execute. The sanna-repo (Python) suite asserts the same vector (SAN-745 PR3b), making the cross-SDK escalate agreement a single shared contract.

#### Changed

- **`spec` submodule**: bumped to `4b73ec3` (sanna-protocol main) to consume `escalate_disposition_vectors` (SAN-745).

#### Notes

- `assurance` is not asserted by the conformance test: TS interceptors emit it, Python interceptors do not yet (SAN-765). The agreed disposition fields are asserted (event_type, enforcement.action, enforcement_mode, status, enforcement_surface, invariants_scope, action_hash).

#### Fixed

- **Enforce mode now blocks `must_escalate` dispositions in the fetch and child_process interceptors** (SAN-745). Previously a constitution decision of `escalate` was non-blocking in enforce mode on the fetch interceptor and on the child_process direct-argv entrypoints (`spawn`, `spawnSync`, `exec`/`execSync` without shell operators, `execFile`, `execFileSync`, `fork`), so an action requiring human approval executed anyway. Escalate now fails closed exactly like `halt`: the action does not execute, and the interceptor emits an `*_escalated` receipt (`enforcement.action: "escalated"`, `status: "WARN"`, `assurance: "partial"`, halted action hash) before raising. Matches the Python SDK and the in-pipeline escalate blocking already present for shell commands.

#### Notes

- Behavior change: code that previously continued past an `escalate` decision in enforce mode now receives the same simulated failure as a halt (`fetch` -> `TypeError`/`ECONNREFUSED`; child_process -> `ENOENT`). Audit and passthrough modes are unchanged (escalate still executes).

---

### 2026-05-14 (SAN-538)

#### Added

- **Regression tests for `-0` normalization + BigInt rejection at the signing-prep boundary** (SAN-538): 10 new test cases in `packages/core/tests/hashing.test.ts` covering `normalizeFloats` / `sanitizeForSigning` / `canonicalize` for both edges (scalar + nested in object/array). Closes the test-coverage gap surfaced during SAN-537 (which added the alias-identity test catching structural drift; this PR adds semantic-drift coverage). The corrected behavior was shipped by SAN-527 + SAN-537; this PR ensures future refactors cannot silently regress without test failures. `Object.is` checks are used alongside `===` to defeat JavaScript's `-0 === 0` trivial pass.

#### Notes

- No source changes. No behavior changes. Pure test coverage addition.
- Tests would fail if `normalizeFloats` were modified to no longer normalize `-0` OR to no longer throw `TypeError` on BigInt -- explicit regression guards per SAN-538 ACs 4 and 5.
- Cross-references: SAN-538 (this ticket), SAN-527 (introduced `normalizeFloats`), SAN-537 (centralized via `sanitizeForSigning` alias), SAN-294 (TS crypto PBT covering NaN/Infinity but not these edges).

---

### 2026-05-13 (SAN-537)

#### Changed

- **`sanitizeForSigning`** is now a single canonical re-export in `@sanna-ai/core`
  (`packages/core/src/crypto.ts`), aliasing `normalizeFloats` from `hashing.ts`.
  Removes three inline duplicate implementations that existed in `aarm.ts`,
  `constitution.ts`, and `verifier.ts`. Net reduction in source lines; behavior
  preserved at all existing call sites. Two correctness-positive edge-case
  improvements: `-0` now normalizes to `0`, and `BigInt` throws `TypeError`
  at the sanitization layer (rather than passing through to JCS). Mirrors
  SAN-524 centralization methodology from sanna-repo. (SAN-537)

---

### 2026-05-13 (SAN-527)

#### Changed

- **[BREAKING]** `canonicalize` in `@sanna-ai/core` now rejects non-integer
  floats with `TypeError`. Pre-SAN-527, canonicalize delegated to RFC 8785
  JCS which accepted any number (e.g., `canonicalize(1.5)` returned `"1.5"`).
  The rejection now matches Python `canonical_json_bytes` behavior and
  conforms to spec section 3.2 ("MUST reject any JSON value that is a
  floating-point number in signing and hashing contexts"). Also rejects
  BigInt explicitly (Sanna receipts use Number type only).
  Pre-customer state means no external consumer should be affected. Internal
  callers were audited in Phase 1 and classified as data-shape-safe.
  (SAN-527)

---

### 2026-05-12 (SAN-294)

#### Added

- **`packages/core/tests/property-crypto.test.ts`**: property-based test suite using fast-check (^3.20.0 added to `@sanna-ai/core` dev deps). TypeScript mirror of SAN-293 (Hypothesis-based PBT in sanna-repo; merged 2026-05-12 as 2ffd764). 30 tests across 10 property categories:
  1. `canonicalize` invariant under dict key reordering (key-sorted output)
  2. `hashContent` NFC-scope invariance (ADR-004 normative); `hashObj` NFC byte-differentiation (no NFC normalization inside objects)
  3. `computeFingerprints` deterministic on repeat calls (3a) and stable across canonical-JSON round-trip (3b)
  4. `[] vs null` produces distinct fingerprints for `parent_receipts` (cv=6) and `agent_identity.privilege_scope` (cv=10, spec Section 2.19 optional array-of-strings field)
  5. Integer-valued numbers serialize without decimal point — cross-SDK byte-parity with Python's int coercion (5a); non-integer floats are accepted by `canonicalize` (serialized as JSON) but rejected by the signing path via `sanitizeForSigning` to prevent cross-SDK divergence (5b)
  6. `NaN`, `+Infinity`, `-Infinity` all throw in `canonicalize` (three explicit cases)
  7. `sign` + `verify` round-trip on arbitrary Buffer; tampered message and tampered signature both fail verification
  8. cv-aware field-count dispatch: cv=5→12-field, cv=6/7→14-field, cv=8→16-field, cv=9→20-field, cv=10→21-field (verified by differential receipt pairs at each boundary)
  9. Redaction marker shape (spec Section 2.11.1): fixture-based byte-parity against `spec/fixtures/gateway-redaction-vectors.json` (cross-SDK canonical source from SAN-516); PBT on arbitrary strings; NFC-invariance of markers
  10. Fingerprint cross-site parity: static-analysis test (10a) asserts all four consumers (`verifier.ts`, `aarm.ts`, `redaction.ts`, `bundle.ts`) import `computeFingerprints` from `./receipt.js` with no inline declarations; sample-equality integration (10b) runs `applyRedactionMarkers` and verifies stored fingerprint matches a direct `computeFingerprints` call on the updated receipt

  sanna-ts is centralized on `computeFingerprints`; static-analysis test (10a) catches drift if any consumer copies the function inline. Companion SAN-524 brings sanna-repo to equivalent centralization parity.

  `SANNA_FAST_CHECK_NUM_RUNS` env var overrides the default 100 examples per property for nightly extended runs. Per-test timeout is 30s. Extended 1000-run pass confirmed clean.

  Pairs with: SAN-293 (sanna-repo Hypothesis PBT; merged 2026-05-12 as 2ffd764).

### 2026-05-12 (SAN-516 PR 3 of 3)

#### Added (BACKWARD-INCOMPATIBLE VERIFIER TIGHTENING)

- **`checkGatewayRedactionMarkersCorrect(receipt) -> string[]`** in `packages/core/src/verifier.ts`: new TS verifier-side enforcement for spec section 2.11.1 marker objects. Emits umbrella stable error code `REDACTION_CLAIM_WITHOUT_MARKER` for three rejection cases: (a) content_mode='redacted' claimed but no valid markers in inputs.context or outputs.response, (b) marker dict has `__redacted__=true` but missing or invalid `original_hash`, (c) content_mode='full' claimed but markers are present (claim/state mismatch). Mirrors sanna-repo Python verifier byte-identically at the error-code level (cross-SDK error semantics aligned).
- **Internal helper `isRedactionMarker(value)`** in `packages/core/src/verifier.ts`: validates spec section 2.11.1 marker shape (`{__redacted__: true, original_hash: <64-hex>}`). TS parallel of Python `_is_redaction_marker`. NOT exported (module-private).
- **`packages/core/tests/cross-sdk-gateway-redaction-vectors.test.ts`**: new vitest fixture-consumer test suite consuming `spec/fixtures/gateway-redaction-vectors.json` (15 total tests: 2 canary + 4 marker + 1 fix12 + 5 apply_redaction + 3 verifier_rejection).

#### Changed

- **`spec/` submodule pin** bumped from `aa1ccc1e6e24faa77801463f6c171f9a0e4d0d2c` to `d69977132ba3be4f7a144c8e43a2ff1c65019c91` (sanna-protocol PR #42 squash; SAN-516 PR 1 of 3).

#### Backward-compatibility note

Verifier-tightening change. Receipts that previously passed verification with `content_mode='redacted'` but no spec section 2.11.1 markers, OR `content_mode='full'` with markers present, will now FAIL verification with the stable umbrella error code `REDACTION_CLAIM_WITHOUT_MARKER`. Pre-customer state means no real-world impact; cross-SDK aligned with sanna-repo PR #67 (Python verifier; merged 2026-05-12 squash cd8b422).

#### Why this matters

SAN-249 + SAN-250 (closed 2026-05-12) brought both SDKs into spec section 2.11.1 marker-shape conformance at the EMISSION side. SAN-516 PR 1 of 3 (sanna-protocol) shipped the cross-SDK conformance fixture. PR 2 of 3 (sanna-repo) added the Python verifier rejection. This PR closes the audit-trail loop by adding the equivalent TS verifier rejection. Both verifiers now reject incomplete-state receipts with the SAME stable umbrella error code, providing cross-SDK error semantics for downstream consumers of `VerifyResult.errors`.

Per CLAUDE.md governance principles 'Cross-SDK coherence is load-bearing' + 'Verifier-side enforcement is non-negotiable'.

#### SAN-516 ticket closure pending

After this PR merges, the SAN-516 ticket can move to Done (all 3 PRs landed). A small follow-up may add sanna-protocol AGENTS.md documenting the cross-SDK verifier rejection contract (AC item 5; not blocking).

---

### 2026-05-12 (SAN-250)

#### Changed (BREAKING)

- **Receipt redaction model rewritten to spec section 2.11.1 marker objects.** Previously, the gateway used pattern-detection + in-place string substitution (e.g., `"user@example.com"` -> `"[EMAIL_REDACTED]"`), which is NOT spec section 2.11.1 conformant. Now, redaction produces marker objects matching the Python SDK byte-for-byte: `{__redacted__: true, original_hash: '<sha256-hex>'}` where `original_hash = SHA-256(NFC(value).encode("utf-8")).hex()`.
- **`gateway.yaml` config schema BREAKING CHANGE**: the `pii:` block is replaced by a `redaction:` block matching the Python SDK shape:
  - Before: `pii: { enabled: true, patterns: [...] }`
  - After:  `redaction: { enabled: true, mode: "hash_only", fields: ["arguments", "result_text"] }`
  - The `mode` field is currently restricted to `"hash_only"`; `"pattern_redact"` is reserved for future use and rejected at config load.
- **`@sanna-ai/sanna-gateway` public API BREAKING CHANGE**: `redactPII`, `redactInObject`, `PiiPattern`, `RedactionResult` are no longer exported. The new field-level marker API is in `@sanna-ai/core`. Customers consuming the old pattern-detection symbols must migrate to `applyRedaction` from `@sanna-ai/core`.
- **`@sanna-ai/core` new exports**: `applyRedaction`, `makeRedactionMarker`, type `RedactionConfig`, type `RedactionMarker`.
- **fetch-interceptor, child-process-interceptor, core middleware** now accept a `redactionConfig` option. When `enabled: true`, the receipt's `inputs.context` and `outputs.response` (or any subset per `fields`) are replaced with marker objects BEFORE signing. Content hashes and fingerprints are recomputed against the marker-bearing receipt. `content_mode` is auto-set to `'redacted'`; `content_mode_source` to `'local_config'` (matches sanna-repo).
- **spec section 2.11.4 FIX-12 pre-existing-marker injection guard ported.** Pre-existing marker dicts are re-redacted via Python-equivalent `JSON.dumps(sort_keys=True, ensure_ascii=True)` serialization with `(', ', ': ')` separators. Cross-SDK byte-identical with sanna-repo's `_apply_redaction_markers`.

#### Removed

- `packages/gateway/src/pii.ts` and `packages/gateway/tests/pii.test.ts` deleted. Pattern-detection + substring substitution is non-conformant. If a pattern-detection-only utility is wanted later (a non-redacting PII detector for warning emission), file a follow-up ticket.

#### Audit-trail rationale

`content_mode_source='local_config'` (existing enum value), NOT a new `'middleware_redaction_config'` value. The middleware-vs-gateway provenance distinction is carried by the `enforcement_surface` field per spec section 2.16. Both SDKs use `'local_config'` for receipts emitted from local SDK configuration. Cross-SDK byte parity preserved on this field.

#### Why this matters

Before this change, sanna-ts shipped receipts with `content_mode='redacted'` metadata but no spec section 2.11.1 markers in the actual content fields. A Python verifier reading a TS-redacted receipt could not distinguish "spec-conformant redaction" from "metadata claim without redaction artifact". After this change, both SDKs produce byte-identical marker shapes; cross-SDK verifier-side enforcement (rejection of `content_mode='redacted'` without markers) becomes meaningful.

Paired with: SAN-249 (Python; merged 2026-05-12 squash commit 8daad7d). Pairs with new Sprint 17 P0 ticket for cross-SDK fixtures + verifier rejection of receipts claiming `content_mode='redacted'` without spec section 2.11.1 markers (filed 2026-05-11; will dispatch after SAN-250 merges).

---

### 2026-05-10 (SAN-488)

#### Changed

- **Cosmetic test-title cleanup.** Renamed two stale describe(...) block
  titles in sanna-ts to drop the "BLOCKED ON SAN-487 (authority
  bypass)" suffix. The tests were unblocked by SAN-487 PR 2
  (sanna-ts commit `bc931f6`, merged 2026-05-06) -- the
  `describe.skip(...)` was removed at that time, but the title
  strings retained the stale "BLOCKED" label. Tests execute
  successfully; the label was misleading audit-trail noise.
  - `packages/core/tests/child-process-interceptor.test.ts:1399`
  - `packages/core/tests/fetch-interceptor.test.ts:1135`
  Both renamed to "... -- end-to-end (SAN-406 + SAN-487)" form.

#### Why this matters

- Future test-output readers seeing `BLOCKED ON SAN-487 (authority
  bypass)` in describe titles would assume the test is still blocked
  or that SAN-487 isn't fixed. Both are false. Cleanup eliminates the
  audit-trail confusion potential.
- No functional change. No assertion changes, no test-body changes.
- CHANGELOG.md historical reference (the original SAN-406 entry
  quoting the old describe.skip string) is unchanged -- historical
  audit-trail content is immutable.

#### Cross-references

- SAN-487 PR 2 (sanna-ts commit `bc931f6`, merged 2026-05-06) -- the
  fix that unblocked the tests; left the stale titles.
- SAN-406 -- the underlying redaction-emission ticket the tests
  exercise.

### 2026-05-10 (SAN-508)

#### Fixed (security)

- **Patched 3 production-dep CVEs** (1 HIGH + 2 MODERATE) via npm
  package overrides in root `package.json`:
  - `fast-uri` ^3.1.2 (was transitive 3.1.0): patches
    GHSA-q3j6-qgpj-74h6 + GHSA-v39h-62p7-jpjc. Path:
    `ajv-formats` -> `ajv` -> `fast-uri`. HIGH severity.
  - `hono` ^4.12.18 (was overridden at ^4.12.12, transitive 4.12.15):
    patches 5 advisories. Path: `@modelcontextprotocol/sdk` -> `hono`.
    MODERATE severity.
  - `ip-address` ^10.1.1 (was transitive 10.1.0): patches
    GHSA-v2v4-37r5-5v8g. Path:
    `@modelcontextprotocol/sdk` -> `ip-address`. MODERATE severity.
- **Side-effect bumps from pristine lock-file resolution:** 99 other
  transitive packages bumped to caret-compatible newer versions during
  npm's full re-resolution pass (required because npm 11.x preserves
  existing lock + cache resolutions; the only way to apply override-
  constrained re-resolution is `npm cache clean --force && rm -rf
  node_modules package-lock.json && npm install --prefer-online`). All
  99 bumps are within the same major and verified non-breaking by the
  full test suite (1467/1467). Bump families: esbuild platform
  binaries, rolldown platform binaries, rollup platform binaries,
  vite, ajv, express-rate-limit, jose, zod, zod-to-json-schema, and
  smaller build/lint toolchain deps.

#### Changed

- **`overridesRationale` string** in `package.json` extended with a
  SAN-508 sentence. Existing SAN-228 + SAN-253 references preserved.

#### Why this matters

- SOC 2 6.6 (Vulnerability Management): per SAN-501 SLA, security
  advisories are merged within 7 days. CVEs were published 2026-05-10;
  this fix lands within 1 day -- well inside SLA.
- CI's `npm audit --omit=dev --audit-level=high` step was failing on
  every sanna-ts PR (and on origin/main itself) until this lands.
  Unblocks SAN-493 PR 3 of 3 (sanna-ts PR #52) to merge with green CI
  after rebase.
- Patch-level bumps within the same major (caret syntax) avoid
  upstream-breaking jumps. ajv and @modelcontextprotocol/sdk continue
  to function with the patched transitives.

#### Out of scope

- Upstream coordination with @modelcontextprotocol/sdk to release a
  version that pulls patched hono + ip-address directly. Tracked as
  ongoing SAN-253 coordination. This PR pins via overrides until
  upstream catches up.
- pnpm-lock.yaml is NOT updated by this PR. Per memory rule
  `reference_sanna_ts_uses_npm_not_pnpm.md`, sanna-ts uses npm; pnpm-
  lock is vestigial in tree and gets caught up by dependabot's next
  pass.

#### Cross-references

- SAN-501 -- dep-update SLA + SOC 2 6.6 evidence (the policy this PR
  satisfies).
- SAN-228 -- original overrides block + dependabot configuration.
- SAN-253 -- upstream MCP SDK coordination on transitive CVEs.
- SAN-493 PR 3 of 3 (sanna-ts PR #52) -- blocked on this; unblocks
  after merge.

### 2026-05-10 (SAN-493 PR 3 of 3)

#### Changed

- **`tools/generate-state-doc.ts`**: drops git-SHA from the
  `docs/state.md` header. The pre-fix header was
  `<!-- generated: TS  git-sha: SHA -->`; post-fix it is
  `<!-- generated: TS -->`. The SHA was always one-commit-stale
  because regen runs pre-commit (per the sealed-gate pattern,
  HEAD at regen time is the parent commit), so the embedded SHA
  never matched the commit that landed the state.md update. Now
  the file contains only derived state from sources of truth
  (per-package versions + test counts, receipt constants, spec
  submodule SHA, latest CHANGELOG entry); commit SHAs come from
  `git log`.
- **`gitSha()` function removed** from `generate-state-doc.ts`
  (was used only for the header; now dead code).
- **`generateFull()` signature simplified** from
  `(root, sha, timestamp)` to `(root, timestamp)`. Internal API
  change; no external callers.
- **`main()` regen print statement** drops the `sha=${sha}, `
  field; keeps tests + spec_version + tool_version.

#### Added

- **`packages/core/tests/state-md-header.test.ts`** (new file):
  regression guard asserting the `git-sha:` substring does NOT
  appear in the first 5 lines of the committed state.md. Catches
  a future re-introduction of the embedded SHA. No side effects
  (reads state.md directly; does not invoke the regen command).

#### Why this matters

- Eliminates a known one-commit-stale audit artifact in state.md.
  Auditors reading the file previously saw a SHA that didn't match
  the commit it landed in; post-fix, the file contains no SHA and
  refers auditors to `git log` for that information.
- Removes the extra round-trip (regen post-first-commit) that
  Sonnet workarounds previously required. One-commit PRs become
  possible again for state-only changes.
- Cross-SDK consistency: closes the loop on SAN-493. Same fix
  pattern landed in sanna-protocol (PR #39, merged 16798d6) and
  sanna-repo (PR #63, merged 39b1152). All 3 repos now produce
  state.md with identical header format.
- The fix is mechanism-only: per-package versions + receipt
  constants + spec submodule SHA on a clean tree are byte-
  identical to pre-fix. The aggregate test count goes 65 -> 66
  due to the new regression-guard test (a real new test, real
  count); core test count goes 48 -> 49.

#### Out of scope

- Cleanup of the untracked `packages/core/tests/anomaly.test 2.ts`
  macOS Finder duplicate -- separate hygiene ticket. The
  generator uses `git ls-files`, so the count is unaffected by
  this untracked file.
- Bumping the `spec` submodule pin (currently `aa1ccc1`,
  pre-SAN-498). Separate concern.

#### Cross-references

- SAN-493 PR 1 of 3 -- sanna-protocol (PR #39, merged 16798d6).
- SAN-493 PR 2 of 3 -- sanna-repo (PR #63, merged 39b1152).
- SAN-492 PR 1 (sanna-protocol PR #36) -- where this surfaced,
  workaround commit `ca2de52`.
- Memory rule `feedback_state_md_hard_gate_before_commit.md`.
- Memory rule `feedback_state_md_regen_commands_per_repo.md`.
- Memory rule `reference_sanna_ts_uses_npm_not_pnpm.md`.

### 2026-05-07 (SAN-492)

#### Added

- **Full ReasoningConfig type system** in `packages/core/src/types.ts`:
  ReasoningConfig + GLCCheckConfig + GLCMinimumSubstanceConfig +
  GLCNoParrotingConfig + GLCLLMCoherenceConfig + JudgeConfig +
  InvariantJudgeOverride. Mirrors Python's structure
  (`sanna-repo/src/sanna/constitution.py:286-440`) for byte-equal
  cross-SDK canonicalization. Constitution interface now exposes
  `reasoning?: ReasoningConfig | null`.
- **`inspect_scripts: boolean`** added to `CliPermissions` interface
  (default `false`). Closes a feature-parity gap with Python's
  `CliPermissions.inspect_scripts`. Schema formalized this field in
  v1.1.0 (sanna-protocol PR #36).
- Cross-SDK byte-parity regression test for v2 in
  `packages/core/tests/cross-language.test.ts` loading
  `spec/fixtures/constitution-signable-vectors-v2.json` (20 vectors).
- v1 backwards-compat canary asserting `minimal.yaml` (v1-signed)
  verifies under v1 dispatch.

#### Changed

- **TypeScript SDK aligned to v2 unified canonical signable form.**
  `constitutionToSignableDict` accepts a `signingVersion: number = 2`
  parameter. v1 path preserved unchanged for legacy verification of
  currently-signed customer constitutions; v2 path mirrors the
  reference generator at `spec/tools/generate_signable_vectors_v2.py`
  byte-for-byte. Sign defaults to v2; verify reads
  `signature.scheme` and dispatches via a defensive
  `_parseSigningVersion` helper. Unrecognized/malformed schemes are
  rejected at the verify level by returning `false` (preserving the
  existing boolean return contract).
- **`saveConstitution` explicitly passes `signingVersion: 1`** to
  preserve existing customer-visible YAML output. Save-time YAML
  output is unchanged by this release; only sign-time canonical bytes
  shift to v2 by default.
- Spec submodule pin advanced from `3aea629` to `aa1ccc1` (3-commit
  delta covering SAN-492 spec/schema/vectors/generator + state.md SHA
  fix + receipt schema enum widen).
- YAML loader (`loadConstitutionString` or equivalent) now parses
  `reasoning` and `cli_permissions.inspect_scripts`; previously dropped
  silently.

#### Notes

- **Customer-visible save-path output unchanged.** Existing TS callers
  of `saveConstitution` get the same YAML output as before. v2
  canonical bytes are produced only at sign-time.
- **policy_hash scope unchanged.** `compute_constitution_hash`
  continues to cover the v1 subset (excludes cli_permissions,
  api_permissions, composition). v2 constitution signatures
  additionally cover those fields. Asymmetry is intentional and
  documented in spec Section 5.3.

#### Tickets

- SAN-492 (this entry; TypeScript SDK portion -- closes the
  cross-3-repo v2 alignment work). Companion sanna-protocol PR #36
  (spec + schema + vectors + reference generator) and sanna-repo PR
  #61 (Python SDK alignment) already merged.

### 2026-05-07 (SAN-490)

#### Changed

- **Canonical signable form aligned to Python.** `constitutionToSignableDict`
  at `packages/core/src/constitution.ts:691-696` now emits `null` explicitly
  for absent optional sub-fields of `must_escalate.target` (`url`, `handler`).
  The previous object-spread pattern (`{ ...r.target }`) omitted undefined
  fields entirely, producing canonical bytes that diverged from Python's
  `dataclasses.asdict()` output. After this change, TS-signed and
  Python-signed constitutions produce byte-identical canonical signable
  bytes for the same input.
- **Spec submodule pin advanced** from `cc2602a` to `3aea629`. The submodule
  delta is the SAN-490 sanna-protocol portion (cross-SDK byte-equal contract
  fixture + schema null-acceptance + spec canonical form Section 6.9 / 13.5).

#### Added

- Cross-SDK byte-parity regression test in
  `packages/core/tests/cross-language.test.ts` loading
  `spec/fixtures/constitution-signable-vectors.json` and asserting byte-equal
  canonical signable output for all 5 vectors.
- New public API `computeCanonicalSignableJson(constitution: Constitution): string`
  exposing the canonical signable bytes pipeline for cross-SDK parity testing.
  Wraps the existing internal `constitutionToSignableDict` -> `sanitizeForSigning`
  -> `canonicalize` flow with no behavioral change.

#### Notes

- **Save-path output change.** `saveConstitution` at
  `packages/core/src/constitution.ts:881` consumes `constitutionToSignableDict`,
  so YAML output for constitutions whose `must_escalate.target` previously
  omitted `url` or `handler` will now include those fields as explicit
  `null`. The schema accepts both forms (per `sanna_constitution` >=
  `"1.0.1"`); existing YAML files at rest are unaffected.
- **Verification of constitutions previously signed by sanna-ts.** Any
  constitution previously signed by sanna-ts whose `must_escalate.target`
  omitted `url` or `handler` was signed over canonical bytes that lacked
  those fields. After this change, sanna-ts recomputes canonical bytes that
  include explicit `null`, producing a different signable byte sequence.
  Such a constitution will not verify against this version of sanna-ts;
  re-signing produces a verifiable artifact under the aligned form.

#### Tickets

- SAN-490 (this entry; sanna-ts portion -- the canonicalization alignment).
  Companion sanna-repo regression test follows in a separate PR that bumps
  the spec submodule pin.

### 2026-05-07 (SAN-404)

#### Security

- **Pre-commit hook.** Added `.pre-commit-config.yaml` with
  `pre-commit/pre-commit-hooks` `detect-private-key` to block any future
  PEM private key from entering the repo. CI runs the same hook on every
  pull request via inline `pip install pre-commit` +
  `pre-commit run --all-files`. The exclude is scoped to exactly
  `^packages/core/tests/crypto\.test\.ts$` -- the legitimate PEM-format
  assertion test (around line 37-38) verifying `exportPrivateKeyPem()`
  returns valid PEM format. No other path is whitelisted; any other
  tracked file containing PEM markers is still blocked.

#### Changed

- Spec submodule pin advanced from `95e87e5` to `cc2602a`. The submodule
  delta is the SAN-404 sanna-protocol rotation (test-author +
  test-attacker key rotation, fixture regeneration, pre-commit hook
  addition) plus the follow-on CI fix. The TypeScript SDK consumes the
  rotated cross-SDK fixtures (key_ids `a1b0635d...` for test-author and
  `d610a877...` for test-attacker; old `6edb...3af61` and `02dd...12de6`
  REVOKED). SDK source is unchanged -- key_ids are read dynamically from
  `spec/fixtures/golden-hashes.json` and
  `spec/fixtures/bundle-trust-vectors.json`.

#### Fixed

- Five test modules that loaded `spec/fixtures/keypairs/test-author.key`
  at module scope -- a file deleted by SAN-404 PR 1's forward-only key
  rotation -- now use an ephemeral keypair via `generateKeypair()`. The
  cross-SDK pub-key load (`test-author.pub`) is preserved where present;
  only the private-key load was replaced. Affects crypto.test.ts,
  receipt.test.ts, verifier.test.ts, receipt-chaining.test.ts, and
  cv9-legacy-warning.test.ts.
- `packages/core/tests/cross-language.test.ts:347-352` V15_EXPECTED
  full_fingerprint pins updated for `escalated`, `fail-halted`, and
  `full-featured` to match the post-rotation values in
  `spec/fixtures/golden-hashes.json`. `pass-single-check` is unchanged
  (no enforcement block; fingerprint stable across rotation).

#### Tickets

- SAN-404 (this entry; sanna-ts portion). Companion sanna-protocol PR
  #34 and sanna-repo PR #59 already merged.

### 2026-05-06 (SAN-487)

#### Fixed
- **CRITICAL authority bypass** (TS side): mirror of sanna-repo PR 1 fix
  (commit 2c02f76). Under `content_mode=redacted` (or `hashes_only`), CLI
  and HTTP interceptors populated `_state.suppressedPatterns` from the
  manifest's `patterns_suppressed` list -- which had been redacted to
  `["<redacted>"]`. Operators who configured redacted/hashes_only mode for
  privacy got ZERO ENFORCEMENT.
- The fix mirrors the gateway's pattern (sanna-repo `server.py:2079-2111`
  sources `_suppressedToolNames` directly from constitution policies). New
  helper `getSuppressedPatterns(constitution, surface)` returns the raw
  `Set<string>` of suppressed patterns from constitution data, bypassing
  `generateManifest()` entirely. Both CLI and HTTP interceptors now use
  this helper for enforcement state population.

#### Added
- `packages/core/src/manifest.ts` exports
  `getSuppressedPatterns(constitution: Constitution, surface: "cli" | "http"): Set<string>`.
  Mirror of Python's `sanna.manifest.get_suppressed_patterns` (SAN-487 PR 1
  @ 2c02f76); cross-SDK behavioral parity guaranteed by mirrored authority
  semantics. Helper does NOT take contentMode -- enforcement state is
  contentMode-independent (the entire point of this fix).
- 9 unit tests in `packages/core/tests/manifest.test.ts` (new top-level
  describe `"getSuppressedPatterns (SAN-487)"`) mirroring the Python suite.
  Reuses existing file-local helpers `bareConstitution` / `makeCliCommand` /
  `makeCliPermissions` / `makeApiEndpoint` / `makeApiPermissions`. Includes
  a regression guard asserting `getSuppressedPatterns.length === 2` (no
  contentMode parameter).
- 6 integration tests in `child-process-interceptor.test.ts` and
  `fetch-interceptor.test.ts` with REAL bodies (previously empty
  placeholders under `describe.skip` with SAN-487 cite from SAN-406 PR 2).
  Each test uses `patchChildProcess({...contentMode: "<mode>"})` or
  `patchFetch({...contentMode: "<mode>"})` to set up the interceptor,
  triggers the suppressed pattern, finds the anomaly receipt, and asserts
  on `ext.attempted_command` / `ext.attempted_endpoint`:
  - redacted mode -> `"<redacted>"`
  - hashes_only mode -> matches `/^[0-9a-f]{64}$/`
  - full mode -> raw value (regression guard)

#### Changed
- Removed `describe.skip(...)` from `child-process-interceptor.test.ts`
  (line 1396) and `fetch-interceptor.test.ts` (line 1132). The 6 tests now
  execute. Updated the SAN-487 cite comment block above each describe to
  a post-fix note explaining the SAN-406 + SAN-487 storyline.

#### Tickets
- SAN-487 PR 2 of 2 (this entry; sanna-ts mirror; CLOSES SAN-487). PR 1
  (sanna-repo) merged at 2c02f76 (2026-05-06). With this PR, SAN-487
  closes; the customer-facing content_mode=redacted/hashes_only toggle
  now works end-to-end (emission + enforcement) across both SDKs.

#### Cross-SDK byte-equal verification
Helper unit tests assert identical Set membership for identical inputs;
combined with PR 1's Python-side helper unit tests, both SDKs produce
identical suppression sets for the same constitution. Integration tests
prove the end-to-end path: SAN-406 emission redaction (PR 2 / 77acc44) +
SAN-487 enforcement state fix (this PR) work together to deliver the
documented content_mode behavior.

### 2026-05-06 (SAN-406)

#### Added
- `packages/core/tests/redaction-vectors.test.ts`: consumes the cross-SDK
  fixture `spec/fixtures/redaction-vectors.json` (added to sanna-protocol in
  SAN-406 PR 3 at commit 95e87e5; consumed by sanna-repo in PR 4 at
  0809568). 26 tests: 1 fixture-well-formedness check, 1 bidirectional
  vector-ID-set contract canary, 9 parametrized helper_vectors
  (`redactAttemptedField(input, mode) === expected`), 6 parametrized
  verifier_vectors (NEGATIVE cases: raw value under redacted/hashes_only ->
  marker check FAILS), 9 parametrized derived positive verifier cases (each
  non-full helper_vector's `expected` value -> marker check PASS; full mode
  -> no marker check emitted). Top-level fixture read via readFileSync
  serves as the hard fixture-presence canary (vitest collection-error
  semantics); equivalent to PR 4's separate test_fixture_file_exists.
- These tests are INDEPENDENT of SAN-487. They call the helper + verifier
  DIRECTLY (no interceptor traversal). The 6 end-to-end interceptor tests
  skipped under describe.skip("SAN-406 redaction emission ... -- BLOCKED ON
  SAN-487 (authority bypass)") in PR 2 remain skipped.

#### Changed
- Bumped `spec` submodule pin from 6795979 to 95e87e5 (sanna-protocol PR
  SAN-406 PR 3). Phase 0 scope sanity check verifies bump pulls in EXACTLY
  ONE commit (the new fixture). No operational schema copy in sanna-ts
  (verifier loads schema directly from submodule); submodule bump is the
  only sync operation needed.

#### Tickets
- SAN-406 PR 5 of 5 (this entry; sanna-ts fixture consumption; CLOSES
  SAN-406). PR 1 (sanna-repo emission + verifier) merged at 817bf1a.
  PR 2 (sanna-ts mirror) merged at 77acc44. PR 3 (sanna-protocol fixture)
  merged at 95e87e5. PR 4 (sanna-repo fixture consumption) merged at
  0809568. With this PR, SAN-406 closes; SAN-439 closes as superseded.
- Related: SAN-487 (CRITICAL authority bypass; orthogonal to this PR's
  scope). The new redaction-vectors.test.ts tests are INDEPENDENT of
  SAN-487; the 6 end-to-end tests skipped under SAN-487 cite remain
  skipped.

#### Cross-SDK byte-equal verification
PR 4 (Python) verified `redact_attempted_field("rm", "hashes_only")` produces
`58466ebdd352f801198118e294e38715f864985fd87977f348bfcd7db62e7c76`. PR 5
(this; TypeScript) calls `redactAttemptedField("rm", "hashes_only")` and
asserts the SAME hex via the helper-cli-hashes-only test. Both SDKs
produce identical output -> cross-SDK byte-equal contract proven.

---

### 2026-05-06 (SAN-406)

#### Added
- `packages/core/src/anomaly.ts`: `redactAttemptedField(value, contentMode)`
  helper implementing Section 2.22.5 single-value redaction for
  com.sanna.anomaly extension emissions. Three modes: "full"/undefined/null/""
  (raw, current behavior preserved), "redacted" (literal `<redacted>`),
  "hashes_only" (SHA-256 hex lowercase via canonical `hashContent`).
  Cross-SDK parity with sanna-repo's `src/sanna/anomaly.py`.
- Verifier semantic check that emits Check.name `"redaction_markers_correct"`
  (snake_case STRING for cross-SDK parity with Python's emission). Implemented
  in `packages/core/src/verifier-manifest.ts` as
  `checkRedactionMarkersCorrect`. Runs from both `verifySessionManifestReceipt`
  and `verifyInvocationAnomalyReceipt` (placed BEFORE the receiptSet null
  early-return). Subsumes SAN-439 scope; that ticket superseded by SAN-406.
- Tests: `packages/core/tests/anomaly.test.ts` (11 helper unit tests),
  extended `packages/core/tests/verifier-manifest.test.ts` with 12 verifier
  tests including a placement-regression guard AND a cross-SDK Check.name
  parity guard, gateway integration tests in gateway.test.ts for redacted
  + hashes_only modes.

#### Fixed
- `child-process-interceptor.ts:870`, `fetch-interceptor.ts:763`, and
  `gateway.ts:1027`: `attempted_command` / `attempted_endpoint` /
  `attempted_tool` now apply Section 2.22.5 field-level redaction at
  emission time. Closes AUDIT-008 (CRITICAL) on the TS side. Mirror of
  SAN-406 PR 1 (sanna-repo, 817bf1a).

#### Skipped
- 6 CLI/HTTP integration tests in
  `packages/core/tests/child-process-interceptor.test.ts` and
  `packages/core/tests/fetch-interceptor.test.ts` (under
  `describe.skip("SAN-406 ... -- BLOCKED ON SAN-487 (authority bypass)")`)
  await SAN-487's fix. Same authority-bypass design gap exists in TS
  interceptors (suppressedPatterns populated from redacted manifest at
  child-process-interceptor.ts:825 and fetch-interceptor.ts:718).
  Test code preserved as harness for SAN-487 re-enable.

#### Security
- Closes the AUDIT-008 emission gap on the TS side. Cross-SDK fixture in
  PR 3 (sanna-protocol); SDK CI consumption in PRs 4 + 5.
- `hashes_only` mode is for audit-time deterministic comparison, NOT
  privacy. Operators relying on strong privacy MUST use `redacted`.

#### Tickets
- SAN-406 PR 2 of 5 (this entry; sanna-ts emission + verifier check).
  PR 1 (sanna-repo Python) merged at 817bf1a. PR 3 (sanna-protocol
  fixture), PR 4 + 5 (SDK CI consumption) follow.
- Related: SAN-487 (CRITICAL authority bypass under content_mode=redacted
  in CLI/HTTP interceptors; cross-SDK; 6 skipped tests cite it).

### 2026-05-06 (SAN-486)

#### Added
- `packages/core/tests/bundle-trust-anchor-vectors.test.ts`: consumes the cross-SDK
  fixture `spec/fixtures/bundle-trust-vectors.json` (added to sanna-protocol in
  SAN-403 PR 3 of 3 at commit 6795979). Asserts every vector's expected `valid`
  and `trust_anchored` against the actual `verifyBundle()` verdict. 11 tests:
  well-formedness, bidirectional vector-ID-set contract, 2 bundle internal-
  reference sanity assertions, and 7 parametrized vector cases. Top-level
  fixture read serves as the hard fixture-presence canary (vitest reports
  collection error if submodule uninitialized).

#### Changed
- Bumped `spec` submodule pin from baa517f to 6795979. The bump pulls in
  sanna-protocol commits SAN-381 (R1 aggregate_suppression_reasons schema
  rule), SAN-383 (A1' cv<10 forbids agent_identity schema rule), SAN-372
  (archive escalated.json regression guard), SAN-373 (spec Section 2.17.2 ->
  2.18.4 cross-reference), in addition to SAN-403 PR 3. Runtime already
  implements these rules; the bump is a schema-resync, not a behavior change.
  Verified by full test suite green post-bump with no new failures vs
  pre-bump baseline.

#### Tickets
- SAN-486 (this entry). Closes the "run by both SDK CIs" acceptance criterion
  of SAN-403 on the TypeScript side. SAN-485 closed the Python side at
  sanna-repo commit eda4dda. With both SDK consumption tickets merged,
  SAN-403 closes.

### 2026-05-05 (SAN-403)

#### Added
- `verifyBundle(..., trustedKeyIds)` parameter (Set<string> | null). When
  non-null, the bundle's receipt key_id and every constitution signature
  key_id must appear in the supplied set or verification fails closed.
  Empty Set is the explicit "trust nothing" signal.
- `--trusted-key-ids <FILE>` CLI flag and `SANNA_TRUSTED_KEY_IDS` env var
  on `sanna bundle-verify`. File format: newline-separated 64-hex key_ids,
  lowercase, '#' comments allowed. Malformed lines reject with line number;
  empty file rejects.
- `BundleVerificationResult.trust_anchored` boolean indicating whether the
  verdict was evaluated against an external anchor (regardless of pass/fail).
- Stderr warning banner when no anchor is supplied and --json is not used
  (and `trust_anchored: false` in --json output). Operators see that the
  verdict is self-consistent only -- the bundle internally agrees but no
  external authority confirms the key_id's identity claim.
- Verification steps display updated from "(7-step)" to "(8-step)".

#### Security
- Closes the bundle-forge attack vector at the verifier level (cross-SDK
  parity with sanna-repo PR merged at 912a058). An adversary who re-signs a
  genuine receipt + constitution with their own key and repackages the bundle
  would, prior to this change, get a `valid: true` verdict. With a trust
  anchor, the forgery is now caught. Without an anchor, the warning makes
  the limitation visible. Approval signature key_ids are NOT yet checked
  against the trust anchor (known limitation; matches Python).

#### Tickets
- SAN-403 PR 2 of 3 (this entry; TypeScript SDK). PR 1 (Python SDK in
  sanna-repo) merged. PR 3 (sanna-protocol cross-SDK forged-bundle fixture
  + spec/SECURITY.md updates) follows.

### 2026-05-05 (SAN-405)

#### Fixed
- Gateway non-anomaly path emitted `enforcement_mode` directly from config
  DSL ({enforced, advisory, permissive}) into the receipt, violating the
  receipt schema enum ({halt, warn, log}). Python verifier rejected such
  receipts; TS verifier silently accepted (cross-SDK divergence on a
  normative enforcement field). The anomaly path at gateway.ts (~996)
  already hardcoded "halt" correctly and is unchanged.

#### Added
- `configModeToEnforcementLevel()` helper: maps config DSL to spec enum
  (enforced->halt, advisory->warn, permissive->log) with fail-loud behavior
  on unsupported values (defense against malformed runtime config that
  bypasses the TypeScript type).
- Regression tests covering all three config modes through the non-anomaly
  halted path, plus a fail-loud test for unknown modes.

#### Tickets
- SAN-405 (this entry).
- Pairs the separate ticket on TS verifier full-schema enforcement, which
  would catch this class of cross-SDK emission divergence at verifier time.

### 2026-05-03 (SAN-380)

#### Fixed
- Gateway ListToolsRequestSchema handler: session_manifest emission
  protected by shared-promise pattern. Concurrent tools/list calls
  await the same emission promise (exactly one manifest emitted;
  second call waits for completion). No TOCTOU gap.
  Cross-SDK parity with sanna-repo SAN-380 Prompt A.

#### Tickets
- SAN-380 Prompt B (this entry; TS half). Closes SAN-380.

### 2026-05-03 (SAN-379)

#### Fixed
- CLI + HTTP interceptors: enforcement.enforcement_mode now emits
  schema-conformant values (halt/warn/log) instead of interceptor
  mode values (enforce/audit/passthrough). Mapping: enforce->halt,
  audit->warn, passthrough->log. Cross-SDK parity with sanna-repo PR #49.

#### Tickets
- SAN-379 TS follow-up (this entry).

### 2026-05-03 (SAN-397)

#### Added
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

#### Hash backward-compat
- `constitutionToSignableDict` omits `anomaly_tracking` when at defaults
  (both false). Pre-v1.5 constitutions hash IDENTICALLY without re-signing.
  Cross-language hash parity with Python PR #48.

#### Cross-SDK
- Extension shape matches Python byte-for-byte (SAN-395 Section 2.22.2).
- content_mode on receipt envelope only (Section 2.22.5 spec-ahead-of-impl
  consistent with gateway + Python interceptors).

#### Tickets
- SAN-397 Prompt C (this entry; TS half). Closes SAN-397.
- Companion: Prompt A (protocol, PR #27), Prompt B (Python, PR #48).

### 2026-05-02 (SAN-359)

#### Fixed
- Gateway ListToolsRequestSchema handler now returns empty tools when
  `_emitSessionManifest` fails (generation or persistence). Previously
  the gateway caught manifest failures silently and returned the full
  filtered tool list -- a governance leak.
- `_manifestFailed` state is sticky: once manifest fails, ALL subsequent
  tools/list calls return empty for the gateway lifecycle.
- Belt-and-suspenders: handler wraps `_emitSessionManifest` in try/catch
  as catch-all for unexpected failures.

#### Security
- Per PRD CT-7 (fail-closed): no tool-name data leaks to the agent on
  manifest failure. Response is `{ tools: [] }`. Cross-SDK parity with
  sanna-repo SAN-359 Prompt A (PR #47).

#### Tickets
- SAN-359 Prompt B (this entry; TS half). Closes SAN-359.
- Companion: SAN-359 Prompt A (Python, PR #47, merged).

### 2026-05-02 (SAN-394)

#### Fixed
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

#### Cross-SDK
- Verdict-level parity restored: same schema-violating receipt now produces
  errors in both Python (jsonschema) and TS (ajv) verifiers. Error message
  TEXT differs between libraries (expected); error PRESENCE is parity-gated.
- Existing byte-equal messages (SAN-370 cv=10, SAN-222 cv=9, SAN-213 cv=8)
  preserved unchanged; ajv pass is additive, not a replacement.

#### Tickets
- SAN-394 (this entry).
- Adjacent: SAN-358 (semantic checks, already merged), SAN-395 (spec B3/B4,
  already merged).

### 2026-05-02 (SAN-358 Prompt B)

#### Added
- New module `packages/core/src/verifier-manifest.ts` with `verifySessionManifestReceipt()` (9 checks) and `verifyInvocationAnomalyReceipt()` (3 checks). Mirror of Python `src/sanna/verify_manifest.py` from SAN-358 Prompt A (PR #46). Cross-SDK byte-equal verdict text.
- New public function `verifyReceiptSet(receipts, publicKey?)` in verifier.ts for cross-receipt parent-resolution. `verifyReceipt()` signature unchanged (backward compat).
- `Check` interface added to types.ts; optional `checks` field on `VerificationResult`.
- Spec submodule bumped to 0f99a44 (SAN-395: reserves com.sanna.anomaly namespace + B3/B4 schema rules).

#### Cross-SDK
- Every Check.message string matches Python character-for-character.
- Cross-language verdict fixture (SAN-358 Prompt C) will assert identical verdicts.

#### Tickets
- SAN-358 Prompt B (this entry; TS half).
- Companion: SAN-358 Prompt A (Python, PR #46 merged), SAN-358 Prompt C (sanna-protocol fixture).
- Adjacent: SAN-394 (TS schema-validator gap; orthogonal), SAN-395 (merged; spec namespace).

### 2026-05-02 (SAN-368)

#### Added
- **TypeScript parity for sanna-verify aarm.** New module `packages/core/src/aarm.ts` mirrors the Python implementation at sanna-repo f2b53a5. Same SANNA_TO_AARM decision-enum mapping, same six per-requirement check functions (R1 pre-execution interception, R2 parent_receipts chain, R3 constitution policy_hash, R4 decision-enum subset + STEP_UP chain check, R5 fingerprint + signature integrity with redacted-receipt acceptance, R6 cv-aware identity binding), aggregate report, JSON + human output formats.
- `sanna-verify-aarm` CLI subcommand in the TS CLI package. Same flags + exit codes as Python (0 PASS/PARTIAL, 1 FAIL, 2 file errors, 3 internal errors).
- Cross-SDK verdict parity test: TS aggregator produces verdict structure matching Python reference output for the same receipt set (AC #5 closed for the cross-language fixture parity contract).
- New tests in `packages/core/tests/san368-aarm-verifier.test.ts` mirroring Python coverage: 42 tests covering per-check PASS/FAIL/PARTIAL/N/A, STEP_UP chain check, R6 dispatch, redacted-receipt R5 acceptance, fixture-set integration, and cross-SDK parity.

#### Compatibility
- **Cross-SDK verdict byte-equal:** TS aggregator and Python aggregator produce identical aggregate_status + per-check status for identical receipt sets (modulo generated_at timestamp).

#### Out of scope
- **Spec section "How to verify AARM conformance"** (AC #6). Lands in sanna-protocol SAN-368 portion.
- **SARIF output format.** Marked optional; deferred.

#### Tickets
- SAN-368 (this entry; sanna-ts TypeScript portion)
- Predecessor: sanna-repo SAN-368 portion (Python implementation, MERGED at sanna-repo f2b53a5)
- Companion: sanna-protocol SAN-368 portion (operational docs, separate Opus prompt)
- Cross-references: SAN-356 G2, SAN-361, SAN-369, SAN-370, SAN-371

### 2026-05-02 (SAN-369)

#### Added
- **MODIFY authority decision recording infrastructure (TypeScript).** `buildModifyAuthorityDecision(action, original, transformed, transformations, options?)` constructs an object matching `AuthorityDecisionRecord` with `decision=modify_with_constraints` and the three required MODIFY recording fields (`tool_input_original`, `tool_input_transformed`, `transformations_applied`) per spec Section 2.7. Validates at construction: transformations is a non-empty array of `{type, target_field, rationale}` objects; `original` and `transformed` are string or plain object (null and arrays rejected). Cross-SDK byte-equal parity with Python helper (`sanna-repo c2c6a39`): identical inputs produce identical record shape, key order, and value semantics. Records produced by the helper satisfy the A1' conditional rule in `receipt.schema.json`.
- New test coverage in `packages/core/tests/san369-modify-recording.test.ts`: 9 tests covering valid construction, key-order parity with Python, construction-time errors for malformed inputs, deterministic byte-equality, and cross-SDK byte-equal shape parity against a hardcoded Python reference output.

#### Out of scope
- **Constitution-rule-driven MODIFY emission.** Authority evaluation does NOT yet return `modify_with_constraints`. Rule engine is a separate ticket.
- **Cross-SDK fixture file.** Lands in sanna-protocol SAN-369 portion (hand-constructed + signed with the committed e58ed3e keypair).
- **Implementer's guide example.** Lands in sanna-protocol SAN-369 portion.

#### Tickets
- SAN-369 (this entry; sanna-ts TypeScript portion)
- Predecessor: sanna-repo SAN-369 portion (Python helper, MERGED at sanna-repo c2c6a39)
- Companion: sanna-protocol SAN-369 portion (implementer's guide + cross-SDK fixture, separate PR)
- Verifier rejection of MODIFY receipts missing the three fields: SAN-368

### 2026-05-01 (SAN-371)

#### Added
- **TypeScript verifier emits CV9_LEGACY-prefixed warning on cv=9 receipts.** When `verifyReceipt(...)` processes a receipt with `checks_version=9`, the warnings array now includes a string starting with `CV9_LEGACY:` indicating partial R6 conformance only (agent_identity is absent at cv<10 per spec Section 2.19). Receipt remains valid; the warning is informational. Cross-SDK parity: warning text is byte-equal to the Python sanna verifier emission.
- New test coverage in `packages/core/tests/cv9-legacy-warning.test.ts` validating: cv=9 receipts emit exactly one CV9_LEGACY warning; cv=10 receipts emit no CV9_LEGACY warning; archive cv=9 fixtures emit the warning.

#### Compatibility
- **No-action-required for existing signed cv=9 receipts.** Pre-v1.5 receipts remain cryptographically valid; their 20-field fingerprints continue to verify. Verification output now includes the CV9_LEGACY informational warning.
- **Cross-SDK warning-text byte-equal:** matches Python sanna verifier emission exactly. Audit consumers can pattern-match on the `CV9_LEGACY:` prefix regardless of which SDK verified the receipt.

#### Tickets
- SAN-371 (this entry; sanna-ts TypeScript portion -- closes SAN-371)
- Predecessors:
  - SAN-371 sanna-protocol portion (migration memo, MERGED at sanna-protocol a684a33)
  - SAN-371 sanna-repo portion (Python verifier CV9_LEGACY emission, MERGED at sanna-repo ed5ae77)

### 2026-05-01 (SAN-389)

#### Fixed
- **Restored strict cross-SDK signature verification.** The cross-language test (`packages/core/tests/cross-language.test.ts`) added a `getVerifyKey()` helper that skipped Ed25519 signature verification when a fixture's `receipt_signature.key_id` did not match the bundled `test-author.pub`. The helper masked an upstream sanna-protocol artifact divergence (cv=10 fixtures signed with a key not in the spec submodule). With sanna-protocol now bundling a self-consistent keypair (commit e58ed3e), the workaround is no longer needed; strict signature verification works for cv=9 archive AND cv=10 active fixtures.

#### Changed
- **Bumped `spec/` submodule pin** from 9ee7527 to e58ed3e (sanna-protocol main HEAD post-artifact-self-consistency fix).
- Removed `getVerifyKey()` helper from cross-language.test.ts; all callsites now use the top-loaded `pubKey` directly.

#### Compatibility
- **Cross-SDK byte-equal contract intact:** cv=10 fingerprints byte-equal across the sanna-protocol keypair rotation (formula uses pipe-joined receipt fields, not signing key). cross-language.test.ts validates this via fingerprint comparison.
- **Receipt signature compatibility:** post-bump, the bundled `spec/fixtures/keypairs/test-author.pub` matches the cv=10 fixture signatures (test_key_id = 6edb993...). Strict signature verification works in both directions.

#### Tickets
- SAN-389 (this entry; sanna-protocol portion merged at e58ed3e)
- Cross-SDK contract: SAN-355
- Unblocks: SAN-386 (v1.5 release coordination)
- Forward-pointer: SAN-391 (make generate_fixtures.py deterministic; idempotent keypair + frozen reference timestamps)

### 2026-05-01 (SAN-370 Prompt C)

#### Changed
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

#### Per-emission-site cv discipline (SAN-370 Issue Y)
- gateway / cli_interceptor (child-process) / http_interceptor (fetch) surfaces emit cv=10 with populated agent_identity.
- middleware surface (sannaObserve / library middleware path) emits cv=9 legacy with no agent_identity, per spec Section 2.19 line 781-782.

#### Compatibility
- **Cross-SDK byte-equal restored:** Python (post-SAN-385) and TypeScript (post-SAN-370 Prompt C) emit identical wire format for cv=9 receipts (`agent_identity` absent) and cv=10 receipts (`agent_identity` dict with `agent_session_id`). cross-language.test.ts validates byte-equal fingerprint computation.
- **Receipt fingerprint compatibility:** existing signed cv=9 receipts continue to verify via the 20-field formula; verifier dispatches on `checks_version`. Re-emission post-upgrade from gateway/interceptor produces cv=10 with field 21; library middleware re-emission preserves cv=9 byte-equal output.
- **Wire format alignment:** TS naturally omits undefined optional fields via JSON.stringify; cv=9 emissions have no `agent_identity` key (parity with Python post-SAN-385).
- **Release coordination (SAN-386):** v1.5 SDK lockstep deployment + customer notification required BEFORE any production deploy of cv=10 emission. Merging this PR ships v1.5 to main; npm publish + customer SDK upgrade is gated by SAN-386.

#### Tickets
- SAN-370 Prompt C (this entry) -- closes SAN-370
- Predecessors: SAN-370 Prompt A (sanna-protocol 9ee7527), Prompt B (sanna-repo a0ee706), SAN-385 (sanna-repo 36832e3)
- Forward-pointers: SAN-383 (cv<10 negative schema rule, Backlog), SAN-384 (content_mode agent_identity redaction, Backlog), SAN-386 (release coordination, Up Next), SAN-387 (typed AgentIdentityBinding interface, Backlog), SAN-388 (cross-language test archive coverage, Backlog)
- Out-of-scope: SAN-368, SAN-369, SAN-371

### 2026-04-30 (SAN-378 Prompt C)

#### Changed
- packages/core/src/manifest.ts: _generateCliSurface and _generateHttpSurface now emit suppression_reasons: Record<string, string> per v1.5 spec Section 2.20.2. Empty dict {} when no suppressions; populated when the constitution declares cannot_execute or must_escalate-with-visibility-suppressed. Mirrors Python SAN-378 Prompt B (sanna-repo e8fb027) and the mcp surfaces existing suppression_reasons algorithm. Cross-SDK byte-equal output preserved.
- packages/core/src/manifest.ts: CliSurface and HttpSurface interfaces updated to include suppression_reasons field.
- spec/ submodule pin bumped from sanna-protocol f89c8c9 to 03160f1 (SAN-378 Prompt A merge: MC-006 + MC-007 fixture vectors updated to include suppression_reasons).
- packages/core/tests/manifest.test.ts: Existing TS manifest tests updated with suppression_reasons assertions for cli/http surface output (8 assertions added across 4 CLI + 4 HTTP tests -- Issue 14-equivalent for SAN-378).

#### Compatibility
- **Receipt fingerprint compatibility:** post-SAN-378 receipts include suppression_reasons in cli/http surfaces (per v1.5 Section 2.20.2). This changes the canonical JSON shape and therefore the receipt fingerprint when cli/http surfaces have suppressed entries. Existing signed receipts remain valid (signature is over what was emitted). Re-emission of the same input post-upgrade produces a different fingerprint than pre-upgrade. Verifiers should accept receipts as-emitted; cross-version fingerprint replay is not a conformance test.
- **Cross-SDK lockstep restored:** with this PRs merge, sanna-ts and sanna-repo both emit cli/http surfaces with suppression_reasons. The bounded divergence window (between SAN-378 Prompt B merge and this merge) closes.

#### Tickets
- SAN-378 Prompt C (this entry)
- Companion: SAN-378 Prompt A (sanna-protocol fixture update, MERGED at 03160f1), SAN-378 Prompt B (sanna-repo Python implementation, MERGED at e8fb027). SAN-376 (cross-SDK fixture origin), SAN-203 (TS manifest origin, will be annotated post-done on full SAN-378 close), SAN-377 (spec clarification, MERGED), SAN-382 (R1 schema-rule enforcement gap, deferred Backlog).

### 2026-04-30 (SAN-209)

#### Added
- packages/core/src/manifest.ts: generateManifest gains surfaces and contentMode params per v1.5 Section 2.14 (post-SAN-377). Cross-SDK byte-equal with Python (SAN-206) via canonical hashContent helper.
- Gateway _emitSessionManifest: passes surfaces=["mcp"] + contentMode. Captures _manifestFullFingerprint BEFORE persistence (Issue 18 governance-honest fail-closed).
- Gateway _suppressedToolNames Set<string> populated by tools/list filter loop. Stores PREFIXED names. Used by _handleToolCall to substitute invocation_anomaly receipt for invocation_halted/invocation_escalated when name is suppressed.
- Gateway _emitInvocationAnomaly: emits invocation_anomaly receipt per v1.5 Section 2.12 + 2.16.3. Receipt: event_type=invocation_anomaly, enforcement_surface=gateway, enforcement.action=halted, enforcement.enforcement_mode=halt, status=FAIL, invariants_scope=authority_only, parent_receipts=[<full_fingerprint>], extensions[com.sanna.anomaly]={attempted_tool, suppression_basis}. Signed via signReceipt if signing key configured.
- packages/core/src/interceptors/child-process-interceptor.ts: patchChildProcess emits per-surface session_manifest at init time. surfaces=["cli"], enforcement_surface=cli_interceptor. Mode-aware fail-closed/fail-open.
- packages/core/src/interceptors/fetch-interceptor.ts: patchFetch entry mirrors CLI. surfaces=["http"], enforcement_surface=http_interceptor.
- New tests: manifest-content-vectors.test.ts (loads SAN-376 fixtures), manifest-content-modes.test.ts (redacted + hashes_only with AJV schema validation), gateway.test.ts TestSessionManifestParentChain (cannot_execute + must_escalate-suppressed + typo negative).

#### Changed
- spec/ submodule pin bumped from sanna-protocol 5bfee54 to f89c8c9.
- packages/core/src/evaluator.ts matchesCondition: normalize condition string the same way as context (underscores -> spaces) before keyword extraction. Fixes must_escalate matching when condition contains underscores (e.g. "send_email"). Pre-existing bug revealed by SAN-376 fixture MC-003.

#### Compatibility
- generateManifest signature backwards-compatible.
- Gateway session_manifest receipts now include only surfaces.mcp. SAN-203 inherited multi-surface defect resolved.
- Gateway session_manifest receipts under contentMode=redacted/hashes_only apply spec-conformant redaction. SAN-203 inherited content_mode defect resolved.
- New invocation_anomaly receipts SUBSTITUTE for invocation_halted/invocation_escalated on suppressed-tool calls (one receipt per call, not two).
- CLI/HTTP interceptors emit session_manifest at patch time. mode=enforce raises if sink rejects manifest.

#### Out of scope (follow-ups filed)
- CLI/HTTP invocation_anomaly variants: pending constitution opt-in field.
- Cross-SDK fixture vectors (MC-008 + redacted/hashes_only): SAN-380 post-this-merge.
- Race condition in session_manifest single-emission across both SDKs: SAN-381.
- spec/impl divergence on cli/http suppression_reasons: SAN-378.

#### Tickets
- SAN-209 (this entry)
- Companion: SAN-206 (Python, MERGED 97668d1), SAN-203 (TS origin, annotated x2), SAN-202 (Python origin, annotated x2), SAN-204, SAN-205, SAN-376, SAN-377 (merged), SAN-378/379/380/381 (deferred).

### 2026-04-30 (SAN-203)

#### Added
- New module `packages/core/src/manifest.ts` with `generateManifest(constitution, mcpTools?)`. Mirror of Python's `src/sanna/manifest.py` from sanna-repo SAN-202 PR #37. Produces the `com.sanna.manifest` extension dict per v1.5 spec Section 2.20: snake_case keys; deterministic sorted lists; stable suppression_reason enum (Section 2.21); per-surface breakdown (mcp / cli / http); fail-closed when constitution is null.
- Gateway `tools/list` handler applies authority filtering: suppress `cannot_execute` tools; suppress `must_escalate` tools when `constitution.authority_boundaries.escalation_visibility === 'suppressed'`; deliver others. Suppressed tools are absent from the response (anti-enumeration).
- Gateway emits a `session_manifest` receipt on the FIRST tools/list call per gateway lifecycle. State-tracked via `_manifestEmitted: boolean`. Receipt has `event_type="session_manifest"`, `invariants_scope="none"`, `enforcement` absent (per v1.5 Section 2.16.3). Cross-language parity with Python (sanna-repo SAN-202).

#### Compatibility
- Pre-Manifest gateway behavior preserved when no constitution is loaded: tools pass through unfiltered, no manifest receipt emitted.
- v1.4-era constitutions (no `escalation_visibility`) default to `"visible"` per SAN-205 TS half (PR #26). must_escalate tools remain in tools/list as before.

#### Tickets
- SAN-203 (this entry)
- Companion: SAN-202 (Python, PR #37 merged), SAN-209 (TS interceptor manifest emission), SAN-206 (Python interceptor manifest emission), SAN-205 (constitution authority enum, merged), SAN-375 (TS schema sync, merged), SAN-204 (v1.5 protocol schema, merged).

### 2026-04-30 (SAN-205)

#### Added
- `AuthorityBoundaries.escalation_visibility` (v1.5+, default `"visible"`; backward compatible).
- `Composition` interface + optional `Constitution.composition` field.
- `AuthorityDecisionType` extended from `"halt" | "allow" | "escalate"` to add `"modify"` and `"defer"` (v1.5+; reserved for future runtime evaluators starting with SAN-369). evaluateAuthority does not return either value in v1.5.
- `BoundaryType` legal values extended with `modify_with_constraints` and `defer_for_context` (v1.5+; reserved).

#### Hash backward-compat
- `constitutionToSignableDict` builds `authority_boundaries` manually; `escalation_visibility` is included ONLY when non-default (`"suppressed"`). Pre-v1.5 constitutions hash IDENTICALLY without re-signing. Mirrors the Python fix from PR #36 (sanna-repo SAN-205 Python half).

#### Compatibility
- v1.4-era constitutions WITHOUT escalation_visibility or composition parse cleanly; defaults applied. No migration needed.
- Cross-language hash parity preserved: TS and Python produce identical hashes for the same v1.4-era constitution.

#### Tickets
- SAN-205 TS half (this entry; companion Python PR #36 already merged in sanna-repo).
- Companion: SAN-203 (TS gateway filtering, depends on this), SAN-204, SAN-375 (already merged), SAN-374 (already merged).

### 2026-04-30

#### Changed
- Submodule `spec/` bumped from sanna-protocol commit `72097f2` to `5bfee54` (post-SAN-204; sanna-protocol v1.5 release). v1.5 introduces 10 new event_type values, the `mixed` enforcement_surface, agent_identity field (required at cv=10), the com.sanna.manifest extension namespace, the suppression_reason enum, and the modify_with_constraints + defer_for_context authority decisions.

#### Compatibility
- cv=9 receipts continue to validate against the new schema (SAN-204 used CONDITIONAL cv=10 rules so the new requirements are no-ops at cv<10). All existing tests pass.
- This bump alone does NOT activate cv=10 in the SDK. SDK code flips CHECKS_VERSION 9 -> 10 in SAN-370.

#### Tickets
- SAN-375 (this entry)
- Companion: SAN-374 (sanna-repo schema sync, already merged), SAN-205 (constitution authority enum + escalation_visibility), SAN-203/209/370/371 (TS feature work that depends on this sync).


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
