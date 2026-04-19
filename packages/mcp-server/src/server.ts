/**
 * Sanna MCP Server — governance tools for Model Context Protocol.
 *
 * Exposes 10 tools over stdio:
 *   - sanna_evaluate_authority — evaluate action permission
 *   - sanna_generate_receipt — generate a governance receipt
 *   - sanna_verify_receipt — verify receipt integrity
 *   - sanna_query_receipts — query stored receipts
 *   - sanna_drift_report — governance drift analytics
 *   - sanna_get_constitution — load and return constitution
 *   - sanna_verify_constitution — verify constitution signature
 *   - sanna_list_checks — list all coherence checks
 *   - sanna_check_constitution_approval — check approval status
 *   - sanna_verify_identity_claims — verify identity claims
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { readFileSync } from "node:fs";

import {
  evaluateAuthority,
  loadConstitution,
  verifyConstitutionSignature,
  computeFileContentHash,
  generateReceipt,
  signReceipt,
  verifyReceipt,
  computeFingerprints,
  ReceiptStore,
  DriftAnalyzer,
  formatDriftReport,
  exportDriftReport,
  loadPublicKey,
  loadPrivateKey,
  getKeyId,
  runCoherenceChecks,
  runAllInvariantChecks,
  verifyApproval,
  isApprovalExpired,
  verifyIdentityClaim,
  SPEC_VERSION,
  CHECKS_VERSION,
} from "@sanna-ai/core";

import type {
  Constitution,
  CheckResult,
  ApprovalRequest,
  IdentityClaim,
} from "@sanna-ai/core";

import type { KeyObject } from "node:crypto";

// ── Size guards ─────────────────────────────────────────────────────

const MAX_INPUT_BYTES = 1_048_576;  // 1 MB
const MAX_OUTPUT_BYTES = 524_288;    // 500 KB
const MAX_QUERY_LIMIT = 500;

function checkInputSize(value: string, fieldName: string): void {
  const bytes = Buffer.byteLength(value, "utf-8");
  if (bytes > MAX_INPUT_BYTES) {
    throw new Error(
      `${fieldName} exceeds maximum size: ${bytes} bytes > ${MAX_INPUT_BYTES} bytes (1 MB)`,
    );
  }
}

function truncateOutput(value: string): string {
  const bytes = Buffer.byteLength(value, "utf-8");
  if (bytes <= MAX_OUTPUT_BYTES) return value;
  // Binary search for truncation point
  let lo = 0, hi = value.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >>> 1;
    if (Buffer.byteLength(value.slice(0, mid), "utf-8") <= MAX_OUTPUT_BYTES - 100) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return value.slice(0, lo) + "\n... [truncated]";
}

// ── Tool definitions ────────────────────────────────────────────────

const TOOLS = [
  {
    name: "sanna_evaluate_authority",
    description:
      "Evaluate whether an action is permitted under a constitution's authority boundaries. " +
      "Returns ALLOW, DENY (halt), or ESCALATE with reason and boundary type.",
    inputSchema: {
      type: "object" as const,
      properties: {
        action_name: {
          type: "string",
          description: "Name of the action/tool to evaluate",
        },
        action_params: {
          type: "object",
          description: "Parameters for the action (optional)",
          default: {},
        },
        constitution_path: {
          type: "string",
          description: "Path to the constitution YAML file",
        },
      },
      required: ["action_name", "constitution_path"],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_generate_receipt",
    description:
      "Generate a Sanna governance receipt from query/context/response. " +
      "Runs C1-C5 coherence checks and constitutional invariant checks. " +
      "Optionally signs the receipt with a private key.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "The user query or prompt",
        },
        context: {
          type: "string",
          description: "Retrieved context or documents (max 500 KB)",
          default: "",
        },
        response: {
          type: "string",
          description: "The agent's response (max 500 KB)",
        },
        constitution_path: {
          type: "string",
          description: "Path to constitution YAML (optional)",
        },
        signing_key_path: {
          type: "string",
          description: "Path to Ed25519 private key for signing (optional)",
        },
        public_key_path: {
          type: "string",
          description: "Path to public key for constitution signature verification (optional)",
        },
      },
      required: ["query", "response"],
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
    },
  },
  {
    name: "sanna_verify_receipt",
    description:
      "Verify a Sanna receipt's integrity: schema, fingerprint, content hashes, " +
      "status consistency, and optionally Ed25519 signature.",
    inputSchema: {
      type: "object" as const,
      properties: {
        receipt_json: {
          type: "string",
          description: "JSON string of the receipt to verify (max 1 MB)",
        },
        public_key_path: {
          type: "string",
          description: "Path to Ed25519 public key for signature verification (optional)",
        },
      },
      required: ["receipt_json"],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_query_receipts",
    description:
      "Query stored receipts from a SQLite database. " +
      "Supports filtering by agent, status, time range, and enforcement. " +
      "Set analysis='drift' for governance drift analysis.",
    inputSchema: {
      type: "object" as const,
      properties: {
        db_path: {
          type: "string",
          description: "Path to the SQLite receipts database",
          default: ".sanna/receipts.db",
        },
        agent_id: {
          type: "string",
          description: "Filter by agent ID (optional)",
        },
        status: {
          type: "string",
          description: "Filter by status: PASS, FAIL, WARN (optional)",
          enum: ["PASS", "FAIL", "WARN"],
        },
        since: {
          type: "string",
          description: "Filter receipts after this ISO-8601 timestamp (optional)",
        },
        until: {
          type: "string",
          description: "Filter receipts before this ISO-8601 timestamp (optional)",
        },
        halt_only: {
          type: "boolean",
          description: "Only return receipts with enforcement actions (optional)",
          default: false,
        },
        limit: {
          type: "number",
          description: "Maximum number of receipts to return (max 500)",
          default: 100,
        },
        analysis: {
          type: "string",
          description: "Set to 'drift' for governance drift analysis instead of raw receipts",
          enum: ["drift"],
        },
      },
      required: [],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_drift_report",
    description:
      "Generate a governance drift report over stored receipts. " +
      "Shows per-agent failure rates, trends, and projected threshold breaches.",
    inputSchema: {
      type: "object" as const,
      properties: {
        db_path: {
          type: "string",
          description: "Path to the SQLite receipts database",
          default: ".sanna/receipts.db",
        },
        window_days: {
          type: "number",
          description: "Analysis window in days",
          default: 30,
        },
        threshold: {
          type: "number",
          description: "Failure rate threshold (0.0 to 1.0)",
          default: 0.15,
        },
        agent_id: {
          type: "string",
          description: "Filter by agent ID (optional)",
        },
        format: {
          type: "string",
          description: "Output format: text, json, or csv",
          enum: ["text", "json", "csv"],
          default: "text",
        },
      },
      required: [],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_get_constitution",
    description:
      "Load and return a parsed constitution from a YAML file. " +
      "Returns the full constitution structure including identity, boundaries, " +
      "invariants, and authority boundaries.",
    inputSchema: {
      type: "object" as const,
      properties: {
        constitution_path: {
          type: "string",
          description: "Path to the constitution YAML file",
        },
      },
      required: ["constitution_path"],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_verify_constitution",
    description:
      "Verify a constitution's Ed25519 signature and content hash. " +
      "Checks signature validity, key ID match, and file content hash.",
    inputSchema: {
      type: "object" as const,
      properties: {
        constitution_path: {
          type: "string",
          description: "Path to the constitution YAML file",
        },
        public_key_path: {
          type: "string",
          description: "Path to the Ed25519 public key file",
        },
      },
      required: ["constitution_path", "public_key_path"],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_list_checks",
    description:
      "List all Sanna coherence checks (C1-C5) with descriptions, " +
      "invariant mappings, default enforcement levels, and severities.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_check_constitution_approval",
    description:
      "Check the approval status of a constitution. Returns approval count, " +
      "status, expiry, and individual approver details.",
    inputSchema: {
      type: "object" as const,
      properties: {
        approval_path: {
          type: "string",
          description: "Path to approval JSON file",
        },
        public_key_path: {
          type: "string",
          description: "Ed25519 public key for verifying approval signatures (optional)",
        },
      },
      required: ["approval_path"],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
  {
    name: "sanna_verify_identity_claims",
    description:
      "Verify identity claims for an agent or entity. " +
      "Checks Ed25519 signatures and expiration.",
    inputSchema: {
      type: "object" as const,
      properties: {
        claims_json: {
          type: "string",
          description: "JSON string containing identity claims (single object or array)",
        },
        public_key_path: {
          type: "string",
          description: "Ed25519 public key for signature verification",
        },
      },
      required: ["claims_json", "public_key_path"],
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
    },
  },
];

// ── Tool type ───────────────────────────────────────────────────────

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

function textResult(text: string): ToolResult {
  return { content: [{ type: "text", text: truncateOutput(text) }] };
}

function errorResult(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

function jsonResult(data: unknown): ToolResult {
  return textResult(JSON.stringify(data, null, 2));
}

// ── Server configuration ────────────────────────────────────────────

export interface SannaMCPConfig {
  constitutionPath?: string;
  dbPath?: string;
  signingKeyPath?: string;
  publicKeyPath?: string;
}

// ── Tool handlers ───────────────────────────────────────────────────

function handleEvaluateAuthority(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const actionName = String(args.action_name ?? "");
  const actionParams = (args.action_params ?? {}) as Record<string, unknown>;
  const constitutionPath = String(
    args.constitution_path ?? config.constitutionPath ?? "",
  );

  if (!actionName) return errorResult("action_name is required");
  if (!constitutionPath) return errorResult("constitution_path is required");

  checkInputSize(actionName, "action_name");

  const constitution = loadConstitution(constitutionPath);
  const decision = evaluateAuthority(actionName, actionParams, constitution);

  return jsonResult({
    decision: decision.decision === "halt" ? "DENY" : decision.decision.toUpperCase(),
    reason: decision.reason,
    boundary_type: decision.boundary_type,
    action_name: actionName,
    constitution_path: constitutionPath,
  });
}

function handleGenerateReceipt(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const query = String(args.query ?? "");
  const context = String(args.context ?? "");
  const response = String(args.response ?? "");
  const constitutionPath = String(
    args.constitution_path ?? config.constitutionPath ?? "",
  );
  const signingKeyPath = String(
    args.signing_key_path ?? config.signingKeyPath ?? "",
  );
  const publicKeyPath = String(
    args.public_key_path ?? config.publicKeyPath ?? "",
  );

  if (!query) return errorResult("query is required");
  if (!response) return errorResult("response is required");

  checkInputSize(query, "query");
  checkInputSize(context, "context");
  checkInputSize(response, "response");

  // Load constitution if provided
  let constitution: Constitution | undefined;
  if (constitutionPath) {
    constitution = loadConstitution(constitutionPath);

    // Verify constitution signature if public key provided
    if (publicKeyPath) {
      const pubKey = loadPublicKey(publicKeyPath);
      const sigValid = verifyConstitutionSignature(constitution, pubKey);
      if (!sigValid) {
        return errorResult(
          `Constitution signature verification failed: ${constitutionPath}`,
        );
      }
    }
  }

  // Run coherence checks
  const checks: CheckResult[] = runCoherenceChecks({
    context,
    query,
    output: response,
    constitution,
  });

  // Run invariant checks from constitution
  if (constitution) {
    const invariantResults = runAllInvariantChecks(constitution, response, context);
    checks.push(...invariantResults);
  }

  // Build constitution reference
  const constitutionRef = constitution
    ? {
        document_id: `${constitution.identity.agent_name}/${constitution.schema_version}`,
        policy_hash: constitution.policy_hash ?? "",
      }
    : undefined;

  // Generate receipt
  const correlationId = `sanna-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const receipt = generateReceipt({
    correlation_id: correlationId,
    inputs: { query: query || null, context: context || null },
    outputs: { response: response || null },
    checks,
    constitution_ref: constitutionRef,
    enforcementSurface: "middleware",
    invariantsScope: "full",
  });

  // Sign receipt if key is available
  if (signingKeyPath) {
    const privateKey = loadPrivateKey(signingKeyPath);
    signReceipt(
      receipt as unknown as Record<string, unknown>,
      privateKey,
      "sanna-mcp-server",
    );
  }

  return jsonResult(receipt);
}

function handleVerifyReceipt(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const receiptJson = String(args.receipt_json ?? "");
  const publicKeyPath = String(
    args.public_key_path ?? config.publicKeyPath ?? "",
  );

  if (!receiptJson) return errorResult("receipt_json is required");
  checkInputSize(receiptJson, "receipt_json");

  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(receiptJson) as Record<string, unknown>;
  } catch {
    return errorResult("Invalid JSON in receipt_json");
  }

  const publicKey = publicKeyPath ? loadPublicKey(publicKeyPath) : undefined;
  const verification = verifyReceipt(receipt, publicKey);

  // Also recompute fingerprints for reporting
  const { receipt_fingerprint, full_fingerprint } = computeFingerprints(receipt);

  return jsonResult({
    valid: verification.valid,
    errors: verification.errors,
    warnings: verification.warnings,
    checks_performed: verification.checks_performed,
    computed_fingerprint: receipt_fingerprint,
    expected_fingerprint: receipt.receipt_fingerprint ?? "",
    computed_status: receipt.status ?? "",
  });
}

function handleQueryReceipts(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const dbPath = String(args.db_path ?? config.dbPath ?? ".sanna/receipts.db");
  const agentId = args.agent_id ? String(args.agent_id) : undefined;
  const status = args.status ? String(args.status) : undefined;
  const since = args.since ? String(args.since) : undefined;
  const until = args.until ? String(args.until) : undefined;
  const haltOnly = Boolean(args.halt_only ?? false);
  const analysis = args.analysis ? String(args.analysis) : undefined;
  let limit = Number(args.limit ?? 100);
  if (limit > MAX_QUERY_LIMIT) limit = MAX_QUERY_LIMIT;
  if (limit < 1) limit = 1;

  const store = new ReceiptStore(dbPath);
  try {
    // Drift analysis mode
    if (analysis === "drift") {
      const analyzer = new DriftAnalyzer(store);
      const report = analyzer.analyze(30, { agentId });
      return jsonResult({
        analysis: "drift",
        report,
        formatted: formatDriftReport(report),
      });
    }

    // Normal query mode
    const receipts = store.query({
      agent_id: agentId,
      status,
      since,
      until,
      enforcement: haltOnly || undefined,
      limit,
    });

    const total = store.count({
      agent_id: agentId,
      status,
      since,
      until,
      enforcement: haltOnly || undefined,
    });

    return jsonResult({
      count: receipts.length,
      total,
      truncated: receipts.length < total,
      receipts,
    });
  } finally {
    store.close();
  }
}

function handleDriftReport(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const dbPath = String(args.db_path ?? config.dbPath ?? ".sanna/receipts.db");
  const windowDays = Number(args.window_days ?? 30);
  const threshold = Number(args.threshold ?? 0.15);
  const agentId = args.agent_id ? String(args.agent_id) : undefined;
  const format = String(args.format ?? "text");

  const store = new ReceiptStore(dbPath);
  try {
    const analyzer = new DriftAnalyzer(store);
    const report = analyzer.analyze(windowDays, { agentId, threshold });

    if (format === "json") {
      return jsonResult(report);
    } else if (format === "csv") {
      return textResult(exportDriftReport(report, "csv"));
    } else {
      return textResult(formatDriftReport(report));
    }
  } finally {
    store.close();
  }
}

function handleGetConstitution(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const constitutionPath = String(
    args.constitution_path ?? config.constitutionPath ?? "",
  );
  if (!constitutionPath) return errorResult("constitution_path is required");

  const constitution = loadConstitution(constitutionPath);
  return jsonResult(constitution);
}

function handleVerifyConstitution(
  args: Record<string, unknown>,
  config: SannaMCPConfig,
): ToolResult {
  const constitutionPath = String(
    args.constitution_path ?? config.constitutionPath ?? "",
  );
  const publicKeyPath = String(
    args.public_key_path ?? config.publicKeyPath ?? "",
  );

  if (!constitutionPath) return errorResult("constitution_path is required");
  if (!publicKeyPath) return errorResult("public_key_path is required");

  const constitution = loadConstitution(constitutionPath);
  const publicKey = loadPublicKey(publicKeyPath);

  const signatureValid = verifyConstitutionSignature(constitution, publicKey);

  // Compute content hash
  const contentHash = computeFileContentHash(constitutionPath);

  const result: Record<string, unknown> = {
    constitution_path: constitutionPath,
    signature_present: constitution.provenance.signature?.value != null,
    signature_valid: signatureValid,
    content_hash: contentHash,
    policy_hash: constitution.policy_hash,
    agent_name: constitution.identity.agent_name,
    schema_version: constitution.schema_version,
  };

  if (constitution.provenance.signature) {
    result.signature_details = {
      key_id: constitution.provenance.signature.key_id,
      signed_by: constitution.provenance.signature.signed_by,
      signed_at: constitution.provenance.signature.signed_at,
      scheme: constitution.provenance.signature.scheme,
    };
  }

  return jsonResult(result);
}

function handleListChecks(): ToolResult {
  return jsonResult({
    checks_version: CHECKS_VERSION,
    spec_version: SPEC_VERSION,
    total: 5,
    checks: [
      {
        check_id: "C1",
        name: "Context Contradiction",
        invariant: "INV_NO_FABRICATION",
        check_impl: "sanna.context_contradiction",
        description: "Detects when output contradicts provided context",
        default_severity: "critical",
        default_enforcement: "halt",
      },
      {
        check_id: "C2",
        name: "Mark Inferences",
        invariant: "INV_MARK_INFERENCE",
        check_impl: "sanna.unmarked_inference",
        description: "Detects definitive claims without hedging language",
        default_severity: "warning",
        default_enforcement: "warn",
      },
      {
        check_id: "C3",
        name: "No False Certainty",
        invariant: "INV_NO_FALSE_CERTAINTY",
        check_impl: "sanna.false_certainty",
        description: "Detects confidence exceeding evidence strength",
        default_severity: "warning",
        default_enforcement: "warn",
      },
      {
        check_id: "C4",
        name: "Preserve Tension",
        invariant: "INV_PRESERVE_TENSION",
        check_impl: "sanna.conflict_collapse",
        description: "Detects conflicting information collapsed without justification",
        default_severity: "warning",
        default_enforcement: "warn",
      },
      {
        check_id: "C5",
        name: "No Premature Compression",
        invariant: "INV_NO_PREMATURE_COMPRESSION",
        check_impl: "sanna.premature_compression",
        description: "Detects complex input reduced to overly simple output",
        default_severity: "warning",
        default_enforcement: "warn",
      },
    ],
  });
}

function handleCheckConstitutionApproval(
  args: Record<string, unknown>,
): ToolResult {
  const approvalPath = String(args.approval_path ?? "");
  const publicKeyPath = args.public_key_path ? String(args.public_key_path) : undefined;

  if (!approvalPath) return errorResult("approval_path is required");

  let request: ApprovalRequest;
  try {
    request = JSON.parse(readFileSync(approvalPath, "utf-8")) as ApprovalRequest;
  } catch (e) {
    return errorResult(`Failed to read approval file: ${(e as Error).message}`);
  }

  const result: Record<string, unknown> = {
    id: request.id,
    status: request.status,
    constitution_hash: request.constitution_hash,
    requester: request.requester,
    requested_at: request.requested_at,
    expires_at: request.expires_at,
    required_approvals: request.required_approvals,
    current_approvals: request.approvals.length,
    expired: isApprovalExpired(request),
  };

  if (publicKeyPath && request.approvals.length > 0) {
    try {
      const pubKey = loadPublicKey(publicKeyPath);
      const keyId = getKeyId(pubKey);
      const keyMap = new Map<string, KeyObject>();
      keyMap.set(keyId, pubKey);
      const verification = verifyApproval(request, keyMap);
      result.signature_verification = {
        valid: verification.valid,
        verified_count: verification.verified_count,
        required_count: verification.required_count,
        details: verification.details,
      };
    } catch (e) {
      result.signature_verification = {
        valid: false,
        error: (e as Error).message,
      };
    }
  }

  return jsonResult(result);
}

function handleVerifyIdentityClaims(
  args: Record<string, unknown>,
): ToolResult {
  const claimsJson = String(args.claims_json ?? "");
  const publicKeyPath = String(args.public_key_path ?? "");

  if (!claimsJson) return errorResult("claims_json is required");
  if (!publicKeyPath) return errorResult("public_key_path is required");

  checkInputSize(claimsJson, "claims_json");

  let claims: IdentityClaim[];
  try {
    const parsed = JSON.parse(claimsJson);
    claims = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return errorResult("Invalid JSON in claims_json");
  }

  const pubKey = loadPublicKey(publicKeyPath);

  const results = claims.map((claim) => {
    try {
      const verification = verifyIdentityClaim(claim, pubKey);
      return {
        claim_id: claim.id,
        claim_type: claim.claim_type,
        subject_key_id: claim.subject_key_id,
        valid: verification.valid,
        expired: verification.expired,
        signature_valid: verification.signature_valid,
      };
    } catch (e) {
      return {
        claim_id: claim.id,
        valid: false,
        error: (e as Error).message,
      };
    }
  });

  const validCount = results.filter((r) => r.valid).length;

  return jsonResult({
    total: results.length,
    valid_count: validCount,
    results,
  });
}

// ── Dispatcher ──────────────────────────────────────────────────────

const HANDLER_MAP: Record<
  string,
  (args: Record<string, unknown>, config: SannaMCPConfig) => ToolResult
> = {
  sanna_evaluate_authority: handleEvaluateAuthority,
  sanna_generate_receipt: handleGenerateReceipt,
  sanna_verify_receipt: handleVerifyReceipt,
  sanna_query_receipts: handleQueryReceipts,
  sanna_drift_report: handleDriftReport,
  sanna_get_constitution: handleGetConstitution,
  sanna_verify_constitution: handleVerifyConstitution,
  sanna_list_checks: () => handleListChecks(),
  sanna_check_constitution_approval: (args) => handleCheckConstitutionApproval(args),
  sanna_verify_identity_claims: (args) => handleVerifyIdentityClaims(args),
};

// ── Server factory ──────────────────────────────────────────────────

export function createSannaServer(config: SannaMCPConfig = {}): Server {
  const server = new Server(
    { name: "sanna-mcp-server", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );

  // List tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // Call tools
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;

    const handler = HANDLER_MAP[toolName];
    if (!handler) {
      return errorResult(`Unknown tool: ${toolName}`);
    }

    try {
      return handler(args, config);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return errorResult(`Error in ${toolName}: ${message}`);
    }
  });

  return server;
}

export async function runServer(config: SannaMCPConfig = {}): Promise<void> {
  const server = createSannaServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
