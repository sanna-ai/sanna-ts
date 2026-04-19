/**
 * Sanna Protocol — Middleware module
 *
 * TypeScript equivalent of Python's @sanna_observe decorator.
 * Wraps functions with governance: authority evaluation, coherence checks,
 * invariant enforcement, receipt generation, and halt enforcement.
 *
 * Usage:
 *   const governed = sannaObserve(myFunction, { constitution, enforcementMode: "enforced" });
 *   const result = governed({ query: "...", context: "..." });
 *   // result.output — the original return value
 *   // result.receipt — the signed reasoning receipt
 *   // result.halted — whether execution was halted
 */

import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { runCoherenceChecks } from "./checks.js";
import { runAllInvariantChecks } from "./invariants.js";
import { evaluateAuthority } from "./evaluator.js";
import { generateReceipt, signReceipt } from "./receipt.js";
import { loadConstitution, verifyConstitutionSignature } from "./constitution.js";
import { loadPrivateKey, loadPublicKey } from "./crypto.js";
import type {
  Constitution,
  CheckResult,
  Receipt,
  SannaObserveOptions,
  SannaResult,
  EnforcementMode,
  TraceData,
  AuthorityDecision,
  ReceiptSink,
} from "./types.js";

// ── SannaHaltError ───────────────────────────────────────────────────

/**
 * Thrown when an enforced-mode check failure triggers a halt.
 * Carries the receipt documenting why the halt occurred.
 */
export class SannaHaltError extends Error {
  public readonly receipt: Receipt;
  public readonly failedChecks: CheckResult[];

  constructor(message: string, receipt: Receipt, failedChecks: CheckResult[]) {
    super(message);
    this.name = "SannaHaltError";
    this.receipt = receipt;
    this.failedChecks = failedChecks;
  }
}

// ── Trace data builder ───────────────────────────────────────────────

/**
 * Build trace data dict used for receipt generation.
 *
 * Assembles the inputs/outputs structure that `generateReceipt` expects,
 * matching the Python `build_trace_data()` shape.
 */
export function buildTraceData(
  query: string,
  context: string,
  output: string,
  constitution?: Constitution,
  checkResults?: CheckResult[],
): TraceData {
  return {
    correlationId: `sanna-${randomUUID().replace(/-/g, "").slice(0, 12)}`,
    query,
    context,
    output,
    constitution,
    checkResults,
  };
}

// ── Constitution cache ───────────────────────────────────────────────

const constitutionCache = new Map<string, Constitution>();

function resolveConstitution(opts: SannaObserveOptions): Constitution | undefined {
  if (opts.constitution) return opts.constitution;

  if (opts.constitutionPath) {
    const cached = constitutionCache.get(opts.constitutionPath);
    if (cached) return cached;

    const loaded = loadConstitution(opts.constitutionPath);

    // Verify signature if public key is provided
    if (opts.constitutionPublicKeyPath) {
      const pubKey = loadPublicKey(opts.constitutionPublicKeyPath);
      if (!verifyConstitutionSignature(loaded, pubKey)) {
        throw new Error(
          `Constitution signature verification failed: ${opts.constitutionPath}`,
        );
      }
    }

    constitutionCache.set(opts.constitutionPath, loaded);
    return loaded;
  }

  return undefined;
}

function resolveSigningKey(opts: SannaObserveOptions): KeyObject | undefined {
  if (opts.signingKeyPath) {
    return loadPrivateKey(opts.signingKeyPath);
  }
  return undefined;
}

// ── Input resolution ─────────────────────────────────────────────────

const CONTEXT_KEYS = ["context", "retrieved_context", "documents", "retrieved_docs"];
const QUERY_KEYS = ["query", "prompt", "input", "user_input", "question"];

interface ResolvedInputs {
  query: string;
  context: string;
}

function resolveInputs(
  args: unknown[],
  opts: SannaObserveOptions,
): ResolvedInputs {
  let query = "";
  let context = "";

  // If first arg is an object, search for context/query keys
  const firstArg = args[0];
  if (firstArg && typeof firstArg === "object" && !Array.isArray(firstArg)) {
    const dict = firstArg as Record<string, unknown>;

    // Explicit param mapping takes precedence
    if (opts.contextParam && opts.contextParam in dict) {
      context = String(dict[opts.contextParam] ?? "");
    } else {
      for (const key of CONTEXT_KEYS) {
        if (key in dict && dict[key]) {
          context = toStr(dict[key]);
          break;
        }
      }
    }

    if (opts.queryParam && opts.queryParam in dict) {
      query = String(dict[opts.queryParam] ?? "");
    } else {
      for (const key of QUERY_KEYS) {
        if (key in dict && dict[key]) {
          query = toStr(dict[key]);
          break;
        }
      }
    }
  }

  // If positional: first string is query, second is context
  if (!query && typeof args[0] === "string") {
    query = args[0];
  }
  if (!context && typeof args[1] === "string") {
    context = args[1];
  }

  return { query, context };
}

function toStr(val: unknown): string {
  if (val == null) return "";
  if (typeof val === "string") return val;
  if (Array.isArray(val)) {
    return val.map((item) => {
      if (typeof item === "object" && item !== null && "text" in item) {
        return String((item as Record<string, unknown>).text);
      }
      return String(item);
    }).join("\n");
  }
  return String(val);
}

// ── Core governance logic ────────────────────────────────────────────

function runGovernance(
  output: unknown,
  inputs: ResolvedInputs,
  constitution: Constitution | undefined,
  enforcementMode: EnforcementMode,
  signingKey: KeyObject | undefined,
  toolName: string | undefined,
  parentReceipts?: string[] | null,
  workflowId?: string | null,
  sink?: ReceiptSink,
): SannaResult<unknown> {
  const outputStr = toStr(output);
  const correlationId = `sanna-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  const allChecks: CheckResult[] = [];
  let authorityDecisions: Record<string, unknown>[] | undefined;
  let enforcement: Record<string, unknown> | undefined;

  // 1. Authority evaluation
  if (constitution && toolName) {
    const decision: AuthorityDecision = evaluateAuthority(toolName, {}, constitution);
    authorityDecisions = [{
      tool_name: toolName,
      decision: decision.decision,
      reason: decision.reason,
      boundary_type: decision.boundary_type,
    }];

    if (decision.decision === "halt" && enforcementMode === "enforced") {
      // Generate receipt and halt
      const receipt = generateGovernanceReceipt({
        correlationId,
        inputs,
        outputStr,
        checks: [],
        constitution,
        enforcement: {
          action: "halted",
          reason: decision.reason,
          failed_checks: [],
          enforcement_mode: "halt",
          timestamp: new Date().toISOString(),
        },
        authorityDecisions,
        signingKey,
        parentReceipts,
        workflowId,
      });

      throw new SannaHaltError(
        `Authority boundary violation: ${decision.reason}`,
        receipt,
        [],
      );
    }
  }

  // 2. Run coherence checks (skip in permissive mode)
  if (enforcementMode !== "permissive") {
    const coherenceChecks = runCoherenceChecks({
      context: inputs.context,
      query: inputs.query,
      output: outputStr,
      constitution,
    });
    allChecks.push(...coherenceChecks);

    // 3. Run invariant checks from constitution
    if (constitution) {
      const invariantResults = runAllInvariantChecks(constitution, outputStr, inputs.context);
      allChecks.push(...invariantResults);
    }
  }

  // 4. Determine enforcement action
  const HALT_SEVERITIES = new Set(["critical", "high"]);
  const failedChecks = allChecks.filter((c) => !c.passed);
  const haltChecks = failedChecks.filter((c) => HALT_SEVERITIES.has(c.severity));

  let halted = false;

  if (haltChecks.length > 0 && enforcementMode === "enforced") {
    halted = true;
    enforcement = {
      action: "halted",
      reason: `Coherence check failed: ${haltChecks.map((c) => c.check_id).join(", ")}`,
      failed_checks: haltChecks.map((c) => c.check_id),
      enforcement_mode: "halt",
      timestamp: new Date().toISOString(),
    };
  }

  // 5. Generate receipt
  const receipt = generateGovernanceReceipt({
    correlationId,
    inputs,
    outputStr,
    checks: allChecks,
    constitution,
    enforcement,
    authorityDecisions,
    signingKey,
    parentReceipts,
    workflowId,
  });

  // 6. Store receipt in sink (best-effort)
  if (sink) {
    sink.store(receipt).catch((err) => {
      process.stderr.write(
        `[sanna] sink.store failed: ${err instanceof Error ? err.message : err}\n`,
      );
    });
  }

  // 7. Halt if enforced mode
  if (halted) {
    throw new SannaHaltError(
      `Sanna coherence check failed: ${haltChecks.map((c) => `${c.check_id} (${c.name})`).join(", ")}`,
      receipt,
      haltChecks,
    );
  }

  return { output: output as unknown, receipt, halted: false };
}

// ── Receipt generation helper ────────────────────────────────────────

interface GovernanceReceiptParams {
  correlationId: string;
  inputs: ResolvedInputs;
  outputStr: string;
  checks: CheckResult[];
  constitution?: Constitution;
  enforcement?: Record<string, unknown>;
  authorityDecisions?: Record<string, unknown>[];
  signingKey?: KeyObject;
  parentReceipts?: string[] | null;
  workflowId?: string | null;
}

function generateGovernanceReceipt(params: GovernanceReceiptParams): Receipt {
  const constitutionRef = params.constitution
    ? {
        document_id: `${params.constitution.identity.agent_name}/${params.constitution.schema_version}`,
        policy_hash: params.constitution.policy_hash ?? "",
      }
    : undefined;

  const receipt = generateReceipt({
    correlation_id: params.correlationId,
    inputs: {
      query: params.inputs.query || null,
      context: params.inputs.context || null,
    },
    outputs: {
      response: params.outputStr || null,
    },
    checks: params.checks,
    constitution_ref: constitutionRef,
    enforcement: params.enforcement,
    authority_decisions: params.authorityDecisions,
    parent_receipts: params.parentReceipts,
    workflow_id: params.workflowId,
    enforcementSurface: "middleware",
    invariantsScope: "full",
  });

  // Sign receipt if key is available
  if (params.signingKey) {
    signReceipt(
      receipt as unknown as Record<string, unknown>,
      params.signingKey,
      "sanna-middleware",
    );
  }

  return receipt;
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Wrap a function with Sanna governance.
 *
 * Returns a new function that:
 * 1. Loads/caches the constitution
 * 2. Evaluates authority if toolName is provided
 * 3. Executes the wrapped function
 * 4. Runs C1-C5 coherence checks
 * 5. Runs custom invariant checks from the constitution
 * 6. Generates a signed receipt
 * 7. Returns SannaResult with .output, .receipt, .halted
 *
 * In enforced mode, throws SannaHaltError on critical check failure.
 * In advisory mode, returns failures in the receipt but never halts.
 * In permissive mode, skips checks entirely and returns a minimal receipt.
 *
 * @param fn The function to wrap
 * @param options Governance configuration
 * @returns Wrapped function returning SannaResult<T>
 */
export function sannaObserve<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn,
  options: SannaObserveOptions = {},
): (...args: TArgs) => SannaResult<TReturn> {
  const enforcementMode = options.enforcementMode ?? "advisory";
  let constitution: Constitution | undefined;
  let signingKey: KeyObject | undefined;
  let initialized = false;

  function ensureInit(): void {
    if (initialized) return;
    constitution = resolveConstitution(options);
    signingKey = resolveSigningKey(options);
    initialized = true;
  }

  return function wrappedFn(...args: TArgs): SannaResult<TReturn> {
    ensureInit();

    // Resolve inputs from function arguments
    const inputs = resolveInputs(args, options);

    // Execute the wrapped function
    const output = fn(...args);

    // Run governance
    const result = runGovernance(
      output,
      inputs,
      constitution,
      enforcementMode,
      signingKey,
      options.toolName,
      options.parentReceipts,
      options.workflowId,
      options.sink,
    );

    return result as SannaResult<TReturn>;
  };
}

/**
 * Decorator-style API for class methods.
 *
 * Returns a function wrapper that applies Sanna governance to a function.
 * Useful when you want to configure options once and wrap multiple functions.
 *
 * Usage:
 *   const govern = withSannaGovernance({ constitution, enforcementMode: "enforced" });
 *   const safeFn = govern(myFunction);
 *   const result = safeFn({ query: "..." });
 */
export function withSannaGovernance(
  options: SannaObserveOptions = {},
): <TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn,
) => (...args: TArgs) => SannaResult<TReturn> {
  return function wrap<TArgs extends unknown[], TReturn>(
    fn: (...args: TArgs) => TReturn,
  ): (...args: TArgs) => SannaResult<TReturn> {
    return sannaObserve(fn, options);
  };
}
