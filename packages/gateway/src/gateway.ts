/**
 * Sanna Gateway — Core Enforcement Proxy
 *
 * MCP server that sits between a client and one or more downstream
 * MCP servers, enforcing constitutional governance with zero code
 * changes to existing agents.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import crypto, { type KeyObject } from "node:crypto";

import {
  loadConstitution,
  verifyConstitutionSignature,
  evaluateAuthority,
  generateReceipt,
  signReceipt,
  runCoherenceChecks,
  loadPrivateKey,
  loadPublicKey,
  ReceiptStore,
  LocalSQLiteSink,
} from "@sanna-ai/core";
import type {
  Constitution,
  Receipt,
  AuthorityDecision,
  CheckResult,
  ReceiptSink,
  ContentMode,
} from "@sanna-ai/core";

import type { GatewayConfig, DownstreamConfig } from "./config.js";
import { resolveToolPolicy } from "./config.js";
import { DownstreamConnection } from "./downstream.js";
import type { ToolInfo, ToolCallResult } from "./downstream.js";
import { EscalationStore } from "./escalation.js";
import {
  CircuitBreaker,
  CircuitBreakerOpenError,
} from "./circuit-breaker.js";
import {
  namespaceTool,
  parseNamespacedTool,
  namespaceToolList,
} from "./tool-namespace.js";
import { injectJustificationParam } from "./schema-mutation.js";
import { extractJustification } from "./schema-mutation.js";
import { redactPII, redactInObject } from "./pii.js";
import type { PiiPattern } from "./pii.js";
import { deliverTokenViaWebhook } from "./webhook.js";
import { deliverTokenToFile } from "./file-delivery.js";
import {
  computeInputHash,
  computeReasoningHash,
  computeActionHash,
  buildReceiptTriad,
} from "./receipt-v2.js";

// ── Meta-tool names ──────────────────────────────────────────────────

const META_TOOL_APPROVE = "sanna_approve_escalation";
const META_TOOL_DENY = "sanna_deny_escalation";
const META_TOOLS = new Set([META_TOOL_APPROVE, META_TOOL_DENY]);

// ── Types ────────────────────────────────────────────────────────────

interface DownstreamEntry {
  config: DownstreamConfig;
  connection: DownstreamConnection;
  tools: ToolInfo[];
  circuitBreaker: CircuitBreaker;
}

// ── SannaGateway ─────────────────────────────────────────────────────

export class SannaGateway {
  private _config: GatewayConfig;
  private _server: Server;
  private _downstreams = new Map<string, DownstreamEntry>();
  private _constitution!: Constitution;
  private _signingKey: KeyObject | null = null;
  private _publicKey: KeyObject | null = null;
  private _receiptStore: ReceiptStore | null = null;
  private _receiptSink: ReceiptSink | null = null;
  private _escalationStore: EscalationStore | null = null;
  private _piiEnabled = false;
  private _piiPatterns: PiiPattern[] | undefined;
  private _contentMode: ContentMode = null;
  private _workflowId: string | null = null;
  private _escalationReceiptFingerprints = new Map<string, string>();
  private _allTools: Array<{
    name: string;
    description?: string;
    inputSchema: Record<string, unknown>;
    downstream: string;
    originalName: string;
  }> = [];

  constructor(config: GatewayConfig, receiptSink?: ReceiptSink) {
    this._config = config;
    this._receiptSink = receiptSink ?? null;
    this._server = new Server(
      { name: "sanna-gateway", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
  }

  /**
   * Initialize all components and start the MCP server.
   */
  async start(): Promise<void> {
    // 1. Load constitution
    this._constitution = loadConstitution(this._config.constitution.path);

    // 2. Load keys
    if (this._config.constitution.signing_key_path) {
      this._signingKey = loadPrivateKey(
        this._config.constitution.signing_key_path,
      );
    }
    if (this._config.constitution.public_key_path) {
      this._publicKey = loadPublicKey(
        this._config.constitution.public_key_path,
      );
    }

    // 2b. Verify constitution signature
    if (this._publicKey) {
      const sigValid = verifyConstitutionSignature(
        this._constitution,
        this._publicKey,
      );
      if (!sigValid) {
        if (this._config.enforcement.mode === "enforced") {
          throw new Error(
            "Constitution signature verification failed (enforced mode requires valid signature)",
          );
        }
        process.stderr.write(
          "[sanna-gateway] WARNING: Constitution signature verification failed\n",
        );
      }
    }
    // If no public key configured, skip signature verification (opt-in feature)

    // 3. Receipt store / sink
    if (this._config.receipts?.store_path) {
      if (!this._receiptSink) {
        // Legacy config: wrap in LocalSQLiteSink
        process.stderr.write(
          "[sanna-gateway] DEPRECATED: receipts.store_path — use receiptSink constructor param instead\n",
        );
        this._receiptSink = new LocalSQLiteSink(this._config.receipts.store_path);
      }
      this._receiptStore = new ReceiptStore(
        this._config.receipts.store_path,
      );
    }

    // 3b. Content mode
    if (this._config.receipts?.content_mode) {
      this._contentMode = this._config.receipts.content_mode;
    }

    // 3c. Session workflow ID
    this._workflowId = `gw-${crypto.randomUUID()}`;

    // 4. Escalation store
    if (this._config.escalation) {
      this._escalationStore = new EscalationStore({
        storePath: this._config.escalation.store_path,
        ttlSeconds: this._config.escalation.ttl_seconds,
        hmacSecret: this._config.escalation.hmac_secret,
      });
    }

    // 5. PII config
    if (this._config.pii?.enabled) {
      this._piiEnabled = true;
    }

    // 6. Connect to downstreams
    for (const dsConfig of this._config.downstreams) {
      const connection = new DownstreamConnection(dsConfig);
      const cbOptions = this._config.circuit_breaker ?? {
        failure_threshold: 3,
        recovery_timeout_ms: 60_000,
        half_open_max: 1,
      };
      const circuitBreaker = new CircuitBreaker({
        failureThreshold: cbOptions.failure_threshold,
        recoveryTimeoutMs: cbOptions.recovery_timeout_ms,
        halfOpenMax: cbOptions.half_open_max,
      });

      circuitBreaker.onStateChange((from, to) => {
        process.stderr.write(
          `[sanna-gateway] circuit breaker '${dsConfig.name}': ${from} → ${to}\n`,
        );
      });

      connection.onDisconnect((name) => {
        process.stderr.write(
          `[sanna-gateway] downstream '${name}' disconnected unexpectedly\n`,
        );
      });

      try {
        await connection.connect();
        const tools = await connection.listTools();

        this._downstreams.set(dsConfig.name, {
          config: dsConfig,
          connection,
          tools,
          circuitBreaker,
        });

        // Namespace and aggregate tools
        const nsTools = namespaceToolList(dsConfig.name, tools);
        for (const tool of nsTools) {
          const parsed = parseNamespacedTool(tool.name);
          this._allTools.push({
            name: tool.name,
            description: tool.description,
            inputSchema: injectJustificationParam(
              (tool.inputSchema as Record<string, unknown>) ?? {
                type: "object",
                properties: {},
              },
            ),
            downstream: parsed?.downstream ?? dsConfig.name,
            originalName: parsed?.tool ?? tool.name,
          });
        }
      } catch (err) {
        process.stderr.write(
          `[sanna-gateway] failed to connect downstream '${dsConfig.name}': ${
            err instanceof Error ? err.message : err
          }\n`,
        );
      }
    }

    // 7. Add meta-tools for escalation
    if (this._escalationStore) {
      this._allTools.push({
        name: META_TOOL_APPROVE,
        description: "Approve a pending escalation by providing its ID and token",
        inputSchema: {
          type: "object",
          properties: {
            escalation_id: { type: "string", description: "The escalation ID to approve" },
            token: { type: "string", description: "The HMAC verification token" },
          },
          required: ["escalation_id", "token"],
        },
        downstream: "_sanna",
        originalName: META_TOOL_APPROVE,
      });
      this._allTools.push({
        name: META_TOOL_DENY,
        description: "Deny a pending escalation by providing its ID and token",
        inputSchema: {
          type: "object",
          properties: {
            escalation_id: { type: "string", description: "The escalation ID to deny" },
            token: { type: "string", description: "The HMAC verification token" },
          },
          required: ["escalation_id", "token"],
        },
        downstream: "_sanna",
        originalName: META_TOOL_DENY,
      });
    }

    // 8. Register MCP handlers
    this._registerHandlers();

    process.stderr.write(
      `[sanna-gateway] started: ${this._downstreams.size} downstreams, ` +
      `${this._allTools.length} tools, mode=${this._config.enforcement.mode}\n`,
    );
  }

  /**
   * Get the underlying MCP Server instance (for testing with transports).
   */
  getServer(): Server {
    return this._server;
  }

  /**
   * Get the list of all aggregated tools.
   */
  getTools(): typeof this._allTools {
    return this._allTools;
  }

  /**
   * Graceful shutdown.
   */
  async stop(): Promise<void> {
    for (const [, entry] of this._downstreams) {
      await entry.connection.disconnect();
    }
    this._downstreams.clear();
    this._receiptStore?.close();
    await this._receiptSink?.close?.();
  }

  // ── Handler registration ─────────────────────────────────────────

  private _registerHandlers(): void {
    // tools/list handler
    this._server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: this._allTools.map((t) => ({
          name: t.name,
          description: t.description,
          inputSchema: t.inputSchema,
        })),
      };
    });

    // tools/call handler
    this._server.setRequestHandler(
      CallToolRequestSchema,
      async (request) => {
        const toolName = request.params.name;
        const rawArgs = (request.params.arguments ?? {}) as Record<
          string,
          unknown
        >;

        // Handle meta-tools
        if (META_TOOLS.has(toolName)) {
          return this._handleMetaTool(toolName, rawArgs);
        }

        return this._handleToolCall(toolName, rawArgs);
      },
    );
  }

  // ── Meta-tool handling ───────────────────────────────────────────

  private async _handleMetaTool(
    toolName: string,
    args: Record<string, unknown>,
  ) {
    if (!this._escalationStore) {
      return {
        content: [{ type: "text", text: "Escalation store not configured" }],
        isError: true,
      };
    }

    const id = String(args.escalation_id ?? "");
    const token = String(args.token ?? "");

    if (toolName === META_TOOL_APPROVE) {
      const ok = this._escalationStore.verifyAndApprove(id, token);
      if (ok) {
        // Re-execute the original tool call with escalation receipt as parent
        const esc = this._escalationStore.get(id);
        if (esc) {
          const escalationReceiptFp = this._escalationReceiptFingerprints.get(id);
          return this._handleToolCall(
            esc.tool_name,
            esc.args,
            true, // wasEscalated
            escalationReceiptFp ? [escalationReceiptFp] : undefined,
          );
        }
        return {
          content: [{ type: "text", text: `Escalation ${id} approved` }],
        };
      }
      return {
        content: [
          { type: "text", text: `Failed to approve escalation ${id}: invalid token or expired` },
        ],
        isError: true,
      };
    }

    if (toolName === META_TOOL_DENY) {
      const ok = this._escalationStore.verifyAndDeny(id, token);
      return {
        content: [
          {
            type: "text",
            text: ok
              ? `Escalation ${id} denied`
              : `Failed to deny escalation ${id}: invalid token or expired`,
          },
        ],
        isError: !ok,
      };
    }

    return {
      content: [{ type: "text", text: `Unknown meta-tool: ${toolName}` }],
      isError: true,
    };
  }

  // ── Main tool call interception ──────────────────────────────────

  private async _handleToolCall(
    namespacedName: string,
    rawArgs: Record<string, unknown>,
    wasEscalated = false,
    parentReceipts?: string[] | null,
  ) {
    // a. Parse namespace
    const parsed = parseNamespacedTool(namespacedName);
    if (!parsed) {
      return {
        content: [{ type: "text", text: `Invalid tool name: ${namespacedName}` }],
        isError: true,
      };
    }

    const entry = this._downstreams.get(parsed.downstream);
    if (!entry) {
      return {
        content: [
          {
            type: "text",
            text: `Unknown downstream: ${parsed.downstream}`,
          },
        ],
        isError: true,
      };
    }

    // b. Extract justification
    const { justification, cleanArgs } = extractJustification(rawArgs);

    // c. PII redaction on input
    let processedArgs = cleanArgs;
    if (this._piiEnabled) {
      processedArgs = redactInObject(cleanArgs, this._piiPatterns) as Record<
        string,
        unknown
      >;
    }

    // d. Compute input hash for receipt triad
    const inputHash = computeInputHash(parsed.tool, processedArgs);

    // e. Evaluate authority
    const authorityDecision = evaluateAuthority(
      parsed.tool,
      processedArgs,
      this._constitution,
    );

    // f. Policy cascade
    const policyOverride = resolveToolPolicy(
      parsed.tool,
      entry.config,
      this._config.enforcement.default_policy,
    );

    // Map policy override to decision override
    let effectiveDecision = authorityDecision;
    if (policyOverride === "deny") {
      effectiveDecision = {
        decision: "halt",
        reason: `Policy override: tool '${parsed.tool}' is denied`,
        boundary_type: "cannot_execute",
      };
    } else if (policyOverride === "escalate" && !wasEscalated) {
      effectiveDecision = {
        decision: "escalate",
        reason: `Policy override: tool '${parsed.tool}' requires escalation`,
        boundary_type: "must_escalate",
      };
    }

    // In permissive mode, override all decisions to allow
    if (this._config.enforcement.mode === "permissive") {
      effectiveDecision = {
        decision: "allow",
        reason: "Permissive mode: all actions allowed",
        boundary_type: "uncategorized",
      };
    }

    // Run coherence checks
    const checkResults = runCoherenceChecks(
      processedArgs,
      "pending",
      this._constitution,
    );

    // Compute reasoning hash
    const reasoningHash = computeReasoningHash(
      effectiveDecision,
      checkResults,
      justification,
    );

    // g. Execute based on decision
    let toolResult: ToolCallResult | null = null;
    let wasAllowed = false;

    switch (effectiveDecision.decision) {
      case "halt": {
        // DENY — do not forward
        const actionHash = computeActionHash(null, false, wasEscalated);
        const triad = buildReceiptTriad(inputHash, reasoningHash, actionHash);
        const receipt = this._buildReceipt(
          parsed.tool,
          processedArgs,
          effectiveDecision,
          checkResults,
          null,
          false,
          wasEscalated,
          triad,
          parentReceipts,
        );
        this._storeReceipt(receipt);

        if (this._config.enforcement.mode === "advisory") {
          // In advisory mode, still forward but note the violation
          break; // fall through to allow
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                status: "denied",
                reason: effectiveDecision.reason,
                receipt_id: receipt.receipt_id,
                receipt_triad: triad,
              }),
            },
          ],
          isError: true,
        };
      }

      case "escalate": {
        if (!wasEscalated) {
          // Create escalation
          if (this._escalationStore) {
            const esc = this._escalationStore.createEscalation(
              namespacedName,
              processedArgs,
              effectiveDecision.reason,
              this._constitution.identity?.agent_name ?? "unknown",
            );

            const actionHash = computeActionHash(null, false, false);
            const triad = buildReceiptTriad(inputHash, reasoningHash, actionHash);
            const receipt = this._buildReceipt(
              parsed.tool,
              processedArgs,
              effectiveDecision,
              checkResults,
              null,
              false,
              false,
              triad,
              parentReceipts,
            );
            this._storeReceipt(receipt);

            // Track escalation receipt fingerprint for chaining
            const escFp = receipt.full_fingerprint as string;
            if (escFp) {
              this._escalationReceiptFingerprints.set(esc.escalation_id, escFp);
            }

            // Deliver token via configured methods (best-effort)
            const deliveryMethods = this._config.escalation?.delivery_methods ?? ["inline"];

            if (deliveryMethods.includes("webhook") && this._config.escalation?.webhook_url) {
              deliverTokenViaWebhook(
                {
                  escalation_id: esc.escalation_id,
                  tool_name: namespacedName,
                  reason: effectiveDecision.reason,
                  token: esc.token,
                  expires_at: esc.expires_at,
                },
                {
                  url: this._config.escalation.webhook_url,
                  headers: this._config.escalation.webhook_headers,
                },
              ).catch(() => {
                // Best-effort — webhook failure doesn't block inline response
              });
            }

            if (deliveryMethods.includes("file")) {
              try {
                deliverTokenToFile(
                  {
                    escalation_id: esc.escalation_id,
                    tool_name: namespacedName,
                    reason: effectiveDecision.reason,
                    token: esc.token,
                    expires_at: esc.expires_at,
                  },
                  {
                    tokenFilePath: this._config.escalation?.token_file_path ?? "~/.sanna/pending_tokens.json",
                    maxPendingTokens: this._config.escalation?.max_pending_tokens,
                  },
                );
              } catch {
                // Best-effort — file delivery failure doesn't block inline response
              }
            }

            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify({
                    status: "escalated",
                    reason: effectiveDecision.reason,
                    escalation_id: esc.escalation_id,
                    token: esc.token,
                    expires_at: esc.expires_at,
                    receipt_id: receipt.receipt_id,
                  }),
                },
              ],
            };
          }
          // No escalation store — treat as deny
          return {
            content: [
              {
                type: "text",
                text: `Escalation required but no escalation store configured: ${effectiveDecision.reason}`,
              },
            ],
            isError: true,
          };
        }
        // Was escalated and approved — fall through to forward
        break;
      }

      case "allow":
        break;
    }

    // Forward to downstream through circuit breaker
    try {
      toolResult = await entry.circuitBreaker.execute(() =>
        entry.connection.callTool(parsed!.tool, processedArgs),
      );
      wasAllowed = true;
    } catch (err) {
      if (err instanceof CircuitBreakerOpenError) {
        return {
          content: [
            {
              type: "text",
              text: `Downstream '${parsed.downstream}' circuit breaker is open`,
            },
          ],
          isError: true,
        };
      }
      return {
        content: [
          {
            type: "text",
            text: `Downstream error: ${err instanceof Error ? err.message : err}`,
          },
        ],
        isError: true,
      };
    }

    // h. PII redact output
    let processedResult = toolResult;
    if (this._piiEnabled && toolResult) {
      processedResult = {
        ...toolResult,
        content: toolResult.content.map((c) => {
          if (c.type === "text" && c.text) {
            return { ...c, text: redactPII(c.text, this._piiPatterns).redacted };
          }
          return c;
        }),
      };
    }

    // i. Generate receipt with triad
    const actionHash = computeActionHash(
      processedResult?.content,
      wasAllowed,
      wasEscalated,
    );
    const triad = buildReceiptTriad(inputHash, reasoningHash, actionHash);
    const receipt = this._buildReceipt(
      parsed.tool,
      processedArgs,
      effectiveDecision,
      checkResults,
      processedResult,
      wasAllowed,
      wasEscalated,
      triad,
      parentReceipts,
    );
    this._storeReceipt(receipt);

    // m. Return result with receipt metadata
    const resultContent = processedResult?.content ?? [];
    resultContent.push({
      type: "text",
      text: JSON.stringify({
        _sanna_receipt: {
          receipt_id: receipt.receipt_id,
          status: receipt.status,
          receipt_triad: triad,
        },
      }),
    });

    return {
      content: resultContent,
      isError: processedResult?.isError ?? false,
    };
  }

  // ── Receipt building ─────────────────────────────────────────────

  private _buildReceipt(
    toolName: string,
    args: Record<string, unknown>,
    decision: AuthorityDecision,
    checks: CheckResult[],
    result: ToolCallResult | null,
    wasAllowed: boolean,
    wasEscalated: boolean,
    triad: { input_hash: string; reasoning_hash: string; action_hash: string },
    parentReceipts?: string[] | null,
  ): Record<string, unknown> {
    const correlationId = `gw-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;

    const ENFORCEMENT_ACTION_MAP: Record<string, string> = {
      halt: "halted",
      escalate: "escalated",
      allow: "allowed",
    };
    const normalizedAction = ENFORCEMENT_ACTION_MAP[decision.decision] ?? decision.decision;

    const receipt = generateReceipt({
      correlation_id: correlationId,
      inputs: { tool: toolName, args },
      outputs: result ? { content: result.content } : { content: null },
      checks,
      enforcement: wasAllowed
        ? undefined
        : {
            action: normalizedAction,
            reason: decision.reason,
            failed_checks: checks
              .filter((c) => !c.passed)
              .map((c) => c.check_id),
            enforcement_mode: this._config.enforcement.mode,
            timestamp: new Date().toISOString(),
          },
      parent_receipts: parentReceipts,
      workflow_id: this._workflowId,
      content_mode: this._contentMode,
      content_mode_source: this._contentMode ? "local_config" : null,
      enforcementSurface: "gateway",
      invariantsScope: "full",
    });

    // Add triad
    (receipt as Record<string, unknown>).receipt_triad = triad;

    // Sign if configured
    if (this._signingKey && this._config.receipts?.sign !== false) {
      const signed = signReceipt(
        receipt as Record<string, unknown>,
        this._signingKey,
        this._constitution.identity?.agent_name ?? "sanna-gateway",
      );
      return signed;
    }

    return receipt as Record<string, unknown>;
  }

  private _storeReceipt(receipt: Record<string, unknown>): void {
    if (this._receiptSink) {
      this._receiptSink.store(receipt as unknown as Receipt).catch(() => {
        // Best-effort persistence
      });
    } else if (this._receiptStore) {
      try {
        this._receiptStore.save(receipt as unknown as Receipt);
      } catch {
        // Best-effort persistence
      }
    }
  }
}
