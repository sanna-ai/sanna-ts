/**
 * Sanna Protocol — shared type definitions.
 */

// ── Constitution types ───────────────────────────────────────────────

export interface Boundary {
  id: string;
  description: string;
  category: "scope" | "authorization" | "confidentiality" | "safety" | "compliance" | "custom";
  severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface HaltCondition {
  id: string;
  trigger: string;
  escalate_to: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  enforcement: "halt" | "warn" | "log";
}

export interface TrustTiers {
  autonomous: string[];
  requires_approval: string[];
  prohibited: string[];
}

export interface TrustedSources {
  tier_1: string[];
  tier_2: string[];
  tier_3: string[];
  untrusted: string[];
}

export interface ConstitutionSignature {
  value: string | null;
  key_id: string | null;
  signed_by: string | null;
  signed_at: string | null;
  scheme: string;
}

export interface Provenance {
  authored_by: string;
  approved_by: string[];
  approval_date: string;
  approval_method: string;
  change_history: Record<string, string>[];
  signature: ConstitutionSignature | null;
}

export interface AgentIdentity {
  agent_name: string;
  domain: string;
  description: string;
  extensions: Record<string, unknown>;
}

export interface Invariant {
  id: string;
  rule: string;
  enforcement: "halt" | "warn" | "log";
  check: string | null;
}

export interface EscalationTargetConfig {
  type: "log" | "webhook" | "callback";
  url?: string;
  handler?: string;
}

export interface EscalationRule {
  condition: string;
  target: EscalationTargetConfig | null;
}

export interface AuthorityBoundaries {
  cannot_execute: string[];
  must_escalate: EscalationRule[];
  can_execute: string[];
  default_escalation: string;
}

export interface Constitution {
  schema_version: string;
  identity: AgentIdentity;
  provenance: Provenance;
  boundaries: Boundary[];
  trust_tiers: TrustTiers;
  halt_conditions: HaltCondition[];
  invariants: Invariant[];
  policy_hash: string | null;
  authority_boundaries: AuthorityBoundaries | null;
  cli_permissions: CliPermissions | null;
  api_permissions: ApiPermissions | null;
  trusted_sources: TrustedSources | null;
}

// ── CLI Permissions types ────────────────────────────────────────────

export interface CliCommand {
  id: string;
  binary: string;
  authority: "can_execute" | "must_escalate" | "cannot_execute";
  argv_pattern?: string;  // default "*"
  description?: string;
  escalation_target?: string;
}

export interface CliInvariant {
  id: string;
  description: string;
  verdict: "halt" | "warn";
  pattern?: string;
  condition?: string;
}

export interface CliPermissions {
  mode: "strict" | "permissive";
  justification_required: boolean;
  commands: CliCommand[];
  invariants: CliInvariant[];
}

// ── CLI Authority types ──────────────────────────────────────────────

export interface CliAuthorityDecision {
  decision: "halt" | "allow" | "escalate";
  reason: string;
  rule_id?: string;
  escalation_target?: string;
}

// ── API Permissions types ────────────────────────────────────────────

export interface ApiEndpoint {
  id: string;
  url_pattern: string;
  authority: "can_execute" | "must_escalate" | "cannot_execute";
  methods?: string[];  // default ["*"]
  description?: string;
  escalation_target?: string;
}

export interface ApiInvariant {
  id: string;
  description: string;
  verdict: "halt" | "warn";
  pattern?: string;
}

export interface ApiPermissions {
  mode: "strict" | "permissive";
  justification_required: boolean;
  endpoints: ApiEndpoint[];
  invariants: ApiInvariant[];
}

// ── API Authority types ──────────────────────────────────────────────

export interface ApiAuthorityDecision {
  decision: "halt" | "allow" | "escalate";
  reason: string;
  rule_id?: string;
  escalation_target?: string;
}

// ── Authority evaluation types ───────────────────────────────────────

export type AuthorityDecisionType = "halt" | "allow" | "escalate";
export type BoundaryType = "cannot_execute" | "must_escalate" | "can_execute" | "uncategorized";

export interface AuthorityDecision {
  decision: AuthorityDecisionType;
  reason: string;
  boundary_type: BoundaryType;
}

// ── Receipt types ────────────────────────────────────────────────────

export interface CheckResult {
  check_id: string;
  name?: string;
  passed: boolean;
  severity: string;
  evidence: string | null;
  details?: string;
  status?: string;
  triggered_by?: string | null;
  enforcement_level?: string | null;
  check_impl?: string | null;
  replayable?: boolean | null;
}

export interface ReceiptSignature {
  signature: string;
  key_id: string;
  signed_by: string;
  signed_at: string;
  scheme: string;
}

export interface Enforcement {
  action: string;
  reason: string;
  failed_checks: string[];
  enforcement_mode: string;
  timestamp: string;
}

export interface ConstitutionRef {
  document_id: string;
  policy_hash: string;
  version?: string;
  source?: string;
  approved_by?: string | string[];
  approval_date?: string;
  approval_method?: string;
  signature_verified?: boolean;
  scheme?: string;
  constitution_approval?: unknown;
}

/** Content handling mode for receipt data. */
export type ContentMode = "full" | "redacted" | "hashes_only" | null;

/** Canonical SDK identity values for the tool_name field. */
export type ToolName = "sanna" | "sanna-ts";

/** A full Sanna receipt (signed or unsigned). */
export interface Receipt {
  spec_version: string;
  tool_version: string;
  checks_version: string;
  receipt_id: string;
  receipt_fingerprint: string;
  full_fingerprint: string;
  correlation_id: string;
  timestamp: string;
  inputs: Record<string, unknown>;
  outputs: Record<string, unknown>;
  context_hash: string;
  output_hash: string;
  checks: CheckResult[];
  checks_passed: number;
  checks_failed: number;
  status: string;
  /** Enforcement surface emitting this receipt. Required for v1.3+
   *  (CHECKS_VERSION >= 8). One of: "middleware", "gateway",
   *  "cli_interceptor", "http_interceptor". */
  enforcement_surface: string;
  /** Scope of invariants evaluated. Required for v1.3+. One of:
   *  "full", "authority_only", "limited", "none". */
  invariants_scope: string;
  /** Canonical SDK identity. Required for v1.4+ (CHECKS_VERSION >= 9).
   *  "sanna" for Python, "sanna-ts" for TypeScript. */
  tool_name: string;
  /** LLM model identifier, e.g. "claude-opus-4-7". Null = opt-out; absent = not captured. */
  agent_model?: string | null;
  /** LLM model provider, e.g. "anthropic". Null = opt-out; absent = not captured. */
  agent_model_provider?: string | null;
  /** LLM model version string, e.g. "20250514". Null = opt-out; absent = not captured. */
  agent_model_version?: string | null;
  parent_receipts?: string[] | null;
  workflow_id?: string | null;
  content_mode?: ContentMode;
  content_mode_source?: string | null;
  event_type?: string | null;
  context_limitation?: string | null;
  input_hash?: string | null;
  reasoning_hash?: string | null;
  action_hash?: string | null;
  assurance?: "full" | "partial" | null;
  receipt_signature?: ReceiptSignature;
  constitution_ref?: ConstitutionRef;
  enforcement?: Enforcement;
  evaluation_coverage?: Record<string, unknown>;
  authority_decisions?: Record<string, unknown>[];
  escalation_events?: Record<string, unknown>[];
  source_trust_evaluations?: Record<string, unknown>[];
  extensions?: Record<string, unknown>;
  identity_verification?: Record<string, unknown>;
  [key: string]: unknown;
}

// ── Verification types ───────────────────────────────────────────────

export interface VerificationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  checks_performed: string[];
}

// ── Store types ─────────────────────────────────────────────────────

export interface ReceiptQueryFilters {
  agent_id?: string;
  constitution_id?: string;
  correlation_id?: string;
  status?: string;
  enforcement?: boolean;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

// ── Drift types ─────────────────────────────────────────────────────

export type DriftStatus = "HEALTHY" | "WARNING" | "CRITICAL" | "INSUFFICIENT_DATA";

export interface CheckDriftDetail {
  check_id: string;
  total_evaluated: number;
  pass_count: number;
  fail_count: number;
  fail_rate: number;
  trend_slope: number;
  projected_breach_days: number | null;
  status: string;
}

export interface AgentDriftSummary {
  agent_id: string;
  constitution_id: string;
  status: DriftStatus;
  total_receipts: number;
  checks: CheckDriftDetail[];
  projected_breach_days: number | null;
}

export interface DriftReport {
  window_days: number;
  threshold: number;
  generated_at: string;
  agents: AgentDriftSummary[];
  fleet_status: string;
}

// ── Bundle types ────────────────────────────────────────────────────

export interface BundleCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface BundleVerificationResult {
  valid: boolean;
  checks: BundleCheck[];
  receipt_summary: Record<string, unknown> | null;
  errors: string[];
}

export interface CreateBundleOptions {
  receiptPath: string;
  constitutionPath: string;
  publicKeyPath: string;
  outputPath: string;
  description?: string;
}

// ── Middleware types ─────────────────────────────────────────────────

export type EnforcementMode = "enforced" | "advisory" | "permissive";

export interface SannaObserveOptions {
  constitution?: Constitution;
  constitutionPath?: string;
  constitutionPublicKeyPath?: string;
  signingKeyPath?: string;
  enforcementMode?: EnforcementMode;
  toolName?: string;
  contextParam?: string;
  queryParam?: string;
  parentReceipts?: string[] | null;
  workflowId?: string | null;
  sink?: ReceiptSink;
}

// ── ReceiptSink types ─────────────────────────────────────────────

export type FailurePolicy = "log_and_continue" | "throw" | "buffer_and_retry";

export interface SinkResult {
  success: boolean;
  error?: string;
  receiptId?: string;
}

export interface ReceiptSink {
  store(receipt: Receipt): Promise<SinkResult>;
  storeBatch?(receipts: Receipt[]): Promise<SinkResult[]>;
  flush?(): Promise<void>;
  close?(): Promise<void>;
}

export interface SannaResult<T> {
  output: T;
  receipt: Receipt;
  halted: boolean;
}

export interface TraceData {
  correlationId: string;
  query: string;
  context: string;
  output: string;
  constitution?: Constitution;
  checkResults?: CheckResult[];
}

export interface InvariantDefinition {
  id: string;
  rule: string;
  enforcement: "halt" | "warn" | "log";
  type?: string;
  pattern?: string;
  maxLength?: number;
  keywords?: string[];
}

// ── Approval types ─────────────────────────────────────────────────

export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired";

export interface ApprovalSignature {
  approver_key_id: string;
  approved_at: string;
  signature: string;
}

export interface ApprovalRequest {
  id: string;
  constitution_hash: string;
  requester: string;
  requested_at: string;
  expires_at: string;
  status: ApprovalStatus;
  required_approvals: number;
  approvals: ApprovalSignature[];
}

export interface ApprovalVerificationResult {
  valid: boolean;
  verified_count: number;
  required_count: number;
  details: Array<{
    approver_key_id: string;
    signature_valid: boolean;
    error?: string;
  }>;
}

// ── Identity types ─────────────────────────────────────────────────

export type IdentityClaimType = "agent_identity" | "operator_identity" | "organization";

export interface IdentityClaim {
  id: string;
  claim_type: IdentityClaimType;
  subject_key_id: string;
  claims: Record<string, string>;
  issued_at: string;
  expires_at: string;
  signature: string;
  signer_key_id: string;
  revoked?: boolean;
}

export interface ClaimVerificationResult {
  valid: boolean;
  expired: boolean;
  signature_valid: boolean;
  claim_type: IdentityClaimType;
  subject_key_id: string;
}

// ── Safe I/O types ─────────────────────────────────────────────────

export interface SafeWriteOptions {
  mode?: number;
  ensureDir?: boolean;
}

export interface PathValidationResult {
  valid: boolean;
  resolved: string;
  error?: string;
}

// ── Constitution diff types ────────────────────────────────────────

export interface DiffEntry {
  path: string;
  change_type: "added" | "removed" | "modified";
  old_value?: unknown;
  new_value?: unknown;
}

export type DiffSection =
  | "identity"
  | "provenance"
  | "boundaries"
  | "trust_tiers"
  | "halt_conditions"
  | "invariants"
  | "authority_boundaries"
  | "trusted_sources"
  | "metadata";

export interface DiffResult {
  sections: Record<DiffSection, DiffEntry[]>;
  total_changes: number;
  old_version?: string;
  new_version?: string;
}
