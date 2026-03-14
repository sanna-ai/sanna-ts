// @sanna-ai/core — Sanna protocol SDK

export {
  EMPTY_HASH,
  canonicalize,
  hashBytes,
  hashContent,
  hashObj,
} from "./hashing.js";

export {
  generateKeypair,
  sign,
  verify,
  loadPrivateKey,
  loadPublicKey,
  getKeyId,
  exportPrivateKeyPem,
  exportPublicKeyPem,
} from "./crypto.js";

export type { SannaKeypair, KeyObject } from "./crypto.js";

export {
  loadConstitution,
  parseConstitution,
  validateConstitutionData,
  verifyConstitutionSignature,
  computeFileContentHash,
  signConstitution,
  saveConstitution,
} from "./constitution.js";

export {
  evaluateAuthority,
  normalizeAuthorityName,
} from "./evaluator.js";

export {
  generateReceipt,
  signReceipt,
  computeFingerprints,
  computeFingerprintInput,
  SPEC_VERSION,
  CHECKS_VERSION,
} from "./receipt.js";

export type { ReceiptParams } from "./receipt.js";

export { verifyReceipt } from "./verifier.js";

export { ReceiptStore } from "./store.js";

export {
  DriftAnalyzer,
  calculateSlope,
  projectBreach,
  formatDriftReport,
  exportDriftReport,
} from "./drift.js";

export {
  createBundle,
  verifyBundle,
} from "./bundle.js";

export {
  checkC1ContextGrounding,
  checkC2ConstitutionalAlignment,
  checkC3InstructionAdherence,
  checkC4OutputConsistency,
  checkC5ConstraintSatisfaction,
  runCoherenceChecks,
} from "./checks.js";

export type { CoherenceCheckOptions } from "./checks.js";

export {
  loadInvariantChecks,
  runInvariantCheck,
  runAllInvariantChecks,
} from "./invariants.js";

export {
  registerInvariantEvaluator,
  getEvaluator,
  listEvaluators,
  clearEvaluators,
} from "./evaluator-registry.js";

export type { InvariantEvaluatorFn } from "./evaluator-registry.js";

export {
  LLMJudge,
  enableLlmChecks,
  registerLlmEvaluators,
  LLMEvaluationError,
} from "./evaluators/llm.js";

export type { LLMJudgeOptions } from "./evaluators/llm.js";

export { receiptToSpan, SannaSpanExporter } from "./otel-exporter.js";

export type { ReceiptSpanOptions } from "./otel-exporter.js";

export {
  JudgeVerdict,
  HeuristicJudge,
  ReasoningPipeline,
} from "./reasoning/index.js";

export type {
  JudgeResult,
  BaseJudge,
  ReasoningPipelineOptions,
  ReasoningResult,
} from "./reasoning/index.js";

export {
  sannaObserve,
  withSannaGovernance,
  SannaHaltError,
  buildTraceData,
} from "./middleware.js";

export {
  createApprovalRequest,
  signApproval,
  verifyApproval,
  isApprovalExpired,
  ApprovalStore,
} from "./approval.js";

export type { CreateApprovalOptions, ApprovalStoreFilters } from "./approval.js";

export {
  createIdentityClaim,
  verifyIdentityClaim,
  IdentityRegistry,
} from "./identity.js";

export type { CreateClaimOptions } from "./identity.js";

export {
  safeWriteFile,
  safeWriteJson,
  safeWriteYaml,
  safeReadFile,
  validatePath,
  isSymlink,
  ensureDirectory,
  secureTempDir,
} from "./safe-io.js";

export {
  diffConstitutions,
  formatDiffText,
  formatDiffJson,
  isDriftingConstitution,
} from "./constitution-diff.js";

export {
  NullSink,
  LocalSQLiteSink,
  CloudHTTPSink,
  CompositeSink,
} from "./sinks/index.js";
export type { CloudHTTPSinkOptions } from "./sinks/index.js";

export { patchChildProcess, unpatchChildProcess } from "./interceptors/index.js";
export type { PatchOptions } from "./interceptors/index.js";
export { evaluateCliAuthority, checkCliInvariants } from "./interceptors/cli-authority.js";

export type {
  Constitution,
  Boundary,
  HaltCondition,
  TrustTiers,
  TrustedSources,
  ConstitutionSignature,
  Provenance,
  AgentIdentity,
  Invariant,
  EscalationTargetConfig,
  EscalationRule,
  AuthorityBoundaries,
  AuthorityDecision,
  AuthorityDecisionType,
  BoundaryType,
  Receipt,
  CheckResult,
  ReceiptSignature,
  Enforcement,
  ConstitutionRef,
  VerificationResult,
  ReceiptQueryFilters,
  DriftStatus,
  CheckDriftDetail,
  AgentDriftSummary,
  DriftReport,
  BundleCheck,
  BundleVerificationResult,
  CreateBundleOptions,
  EnforcementMode,
  SannaObserveOptions,
  SannaResult,
  TraceData,
  InvariantDefinition,
  ApprovalRequest,
  ApprovalSignature,
  ApprovalStatus,
  ApprovalVerificationResult,
  IdentityClaim,
  IdentityClaimType,
  ClaimVerificationResult,
  FailurePolicy,
  SinkResult,
  ReceiptSink,
  SafeWriteOptions,
  PathValidationResult,
  ContentMode,
  DiffResult,
  DiffEntry,
  DiffSection,
  CliPermissions,
  CliCommand,
  CliInvariant,
  CliAuthorityDecision,
} from "./types.js";
