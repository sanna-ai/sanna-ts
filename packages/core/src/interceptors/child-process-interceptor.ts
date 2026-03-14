/**
 * Child process interceptor — patches Node.js child_process module to enforce
 * CLI governance via constitution-based authority evaluation.
 *
 * Mirrors Python Deliverable 2 (patch_subprocess). Same enforcement logic,
 * same hash computation, same receipt fields, same anti-enumeration.
 */

import { createRequire } from "node:module";
import * as path from "node:path";
import type { ChildProcess, SpawnSyncReturns } from "node:child_process";
import { randomUUID } from "node:crypto";

import type { ReceiptSink, Constitution } from "../types.js";
import { hashObj, hashContent, EMPTY_HASH } from "../hashing.js";
import { generateReceipt } from "../receipt.js";
import { evaluateCliAuthority, checkCliInvariants } from "./cli-authority.js";

// ── Types ────────────────────────────────────────────────────────────

export interface PatchOptions {
  constitutionPath: string;
  sink: ReceiptSink;
  agentId: string;
  mode?: "enforce" | "audit" | "passthrough";
  signingKey?: Buffer;
  contentMode?: "full" | "redacted" | "hashes_only";
  workflowId?: string;
  parentFingerprint?: string;
}

interface InterceptorState {
  active: boolean;
  originals: Record<string, Function>;
  constitution: Constitution | null;
  sink: ReceiptSink | null;
  options: PatchOptions | null;
  inIntercept: boolean;
}

// ── State ────────────────────────────────────────────────────────────

const _state: InterceptorState = {
  active: false,
  originals: {},
  constitution: null,
  sink: null,
  options: null,
  inIntercept: false,
};

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — import.meta.url is ESM-only; CJS build uses __filename fallback
const _require = createRequire(typeof import.meta?.url === "string" ? import.meta.url : __filename);

// ── Helpers ──────────────────────────────────────────────────────────

function parseBinary(command: string): { binary: string; argv: string[] } {
  const parts = command.split(/\s+/).filter(Boolean);
  const binary = path.basename(parts[0] ?? "");
  const argv = parts.slice(1);
  return { binary, argv };
}

function makeEnoentError(binary: string): NodeJS.ErrnoException {
  const err = new Error(`spawn ${binary} ENOENT`) as NodeJS.ErrnoException;
  err.code = "ENOENT";
  err.errno = -2;
  (err as unknown as Record<string, unknown>).syscall = "spawn";
  (err as unknown as Record<string, unknown>).path = binary;
  return err;
}

function computeInputHash(binary: string, argv: string[], cwd: string, envKeys: string[]): string {
  return hashObj({ args: argv, command: binary, cwd, env_keys: envKeys });
}

function computeActionHash(exitCode: number | null, stdout: string, stderr: string): string {
  return hashObj({ exit_code: exitCode, stderr, stdout });
}

function getEnvKeys(opts: Record<string, unknown>): string[] {
  const env = (opts.env as Record<string, string> | undefined) ?? process.env;
  return Object.keys(env).sort();
}

function getCwd(opts: Record<string, unknown>): string {
  return opts.cwd ? String(opts.cwd) : process.cwd();
}

function extractJustification(opts: Record<string, unknown> | undefined): {
  justification: string | undefined;
  cleanOpts: Record<string, unknown>;
} {
  if (!opts) return { justification: undefined, cleanOpts: {} };
  const justification = opts.justification as string | undefined;
  const cleanOpts = { ...opts };
  delete cleanOpts.justification;
  return { justification, cleanOpts };
}

function determineEventType(decision: string): string {
  switch (decision) {
    case "halt": return "cli_invocation_halted";
    case "escalate": return "cli_invocation_escalated";
    default: return "cli_invocation_allowed";
  }
}

function emitReceipt(params: {
  binary: string; argv: string[];
  inputHash: string; reasoningHash: string; actionHash: string;
  decision: string; reason: string; ruleId?: string;
  eventType: string; contextLimitation: string;
  exitCode: number | null; halted: boolean;
}): void {
  const opts = _state.options!;
  const receipt = generateReceipt({
    correlation_id: randomUUID(),
    inputs: { binary: params.binary, argv: params.argv, agent_id: opts.agentId },
    outputs: {
      decision: params.decision, reason: params.reason,
      rule_id: params.ruleId ?? null, exit_code: params.exitCode,
    },
    checks: [],
    status: params.halted ? "HALT" : "PASS",
    event_type: params.eventType,
    context_limitation: params.contextLimitation,
    input_hash: params.inputHash,
    reasoning_hash: params.reasoningHash,
    action_hash: params.actionHash,
    assurance: params.halted ? "partial" : "full",
    content_mode: opts.contentMode ?? null,
    workflow_id: opts.workflowId ?? null,
    parent_receipts: opts.parentFingerprint ? [opts.parentFingerprint] : null,
  });

  _state.sink!.store(receipt).catch(() => {});
}

function shouldExecute(decision: string): boolean {
  const mode = _state.options?.mode ?? "enforce";
  if (mode === "passthrough" || mode === "audit") return true;
  if (decision === "halt") return false;
  return true;
}

function effectiveDecision(decision: string): string {
  return decision;
}

/**
 * Evaluate authority and invariants for a command.
 * Returns the resolved decision info.
 */
function evaluate(binary: string, argv: string[], justification: string | undefined, cwd: string, envKeys: string[]) {
  const inputHash = computeInputHash(binary, argv, cwd, envKeys);
  const reasoningHash = justification ? hashContent(justification) : EMPTY_HASH;

  const authDecision = evaluateCliAuthority(binary, argv, _state.constitution!);
  const invariant = checkCliInvariants(binary, argv, _state.constitution!);

  let decision = authDecision.decision;
  let reason = authDecision.reason;
  if (invariant && invariant.verdict === "halt") {
    decision = "halt";
    reason = `Invariant ${invariant.id}: ${invariant.description}`;
  }

  const contextLimitation = justification ? "cli_execution" : "cli_no_justification";
  const eventType = determineEventType(decision);

  return { inputHash, reasoningHash, decision, reason, ruleId: authDecision.rule_id, contextLimitation, eventType };
}

// ── Patched functions ────────────────────────────────────────────────

function patchedExecSync(command: string | Buffer, options?: Record<string, unknown>): Buffer | string {
  // Re-entrancy guard: exec internally calls execFile; avoid double interception
  if (_state.inIntercept) {
    return (_state.originals["execSync"] as Function)(command, options);
  }
  _state.inIntercept = true;
  try {
    const cmdStr = typeof command === "string" ? command : command.toString();
    const { binary, argv } = parseBinary(cmdStr);
    const { justification, cleanOpts } = extractJustification(options);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, argv, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv, ...ev, actionHash, exitCode: null, halted: true });
      throw makeEnoentError(binary);
    }

    try {
      const result = (_state.originals["execSync"] as Function)(command, cleanOpts);
      const stdout = typeof result === "string" ? result : result.toString("utf-8");
      const actionHash = computeActionHash(0, stdout, "");
      emitReceipt({ binary, argv, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode: 0, halted: false });
      return result;
    } catch (err: unknown) {
      const e = err as Record<string, unknown>;
      const exitCode = (e.status as number) ?? 1;
      const stderr = e.stderr ? String(e.stderr) : "";
      const stdout = e.stdout ? String(e.stdout) : "";
      const actionHash = computeActionHash(exitCode, stdout, stderr);
      emitReceipt({ binary, argv, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode, halted: false });
      throw err;
    }
  } finally {
    _state.inIntercept = false;
  }
}

function patchedSpawnSync(
  command: string,
  args?: readonly string[] | Record<string, unknown>,
  options?: Record<string, unknown>,
): SpawnSyncReturns<Buffer | string> {
  if (_state.inIntercept) {
    return (_state.originals["spawnSync"] as Function)(command, args, options);
  }
  _state.inIntercept = true;
  try {
    let actualArgs: string[];
    let opts: Record<string, unknown>;
    if (Array.isArray(args)) {
      actualArgs = args as string[];
      opts = (options as Record<string, unknown>) ?? {};
    } else if (args && typeof args === "object") {
      actualArgs = [];
      opts = args as Record<string, unknown>;
    } else {
      actualArgs = [];
      opts = (options as Record<string, unknown>) ?? {};
    }

    const binary = path.basename(command);
    const { justification, cleanOpts } = extractJustification(opts);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, actualArgs, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv: actualArgs, ...ev, actionHash, exitCode: null, halted: true });
      throw makeEnoentError(binary);
    }

    const result = (_state.originals["spawnSync"] as Function)(command, actualArgs, cleanOpts);
    const stdout = result.stdout ? String(result.stdout) : "";
    const stderr = result.stderr ? String(result.stderr) : "";
    const exitCode = result.status ?? 0;
    const actionHash = computeActionHash(exitCode, stdout, stderr);
    emitReceipt({ binary, argv: actualArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode, halted: false });
    return result;
  } finally {
    _state.inIntercept = false;
  }
}

function patchedExec(
  command: string,
  optionsOrCallback?: Record<string, unknown> | Function,
  maybeCallback?: Function,
): ChildProcess {
  if (_state.inIntercept) {
    return (_state.originals["exec"] as Function)(command, optionsOrCallback, maybeCallback);
  }
  _state.inIntercept = true;
  try {
    let opts: Record<string, unknown>;
    let callback: Function | undefined;
    if (typeof optionsOrCallback === "function") {
      callback = optionsOrCallback;
      opts = {};
    } else {
      opts = (optionsOrCallback as Record<string, unknown>) ?? {};
      callback = maybeCallback as Function | undefined;
    }

    const { binary, argv } = parseBinary(command);
    const { justification, cleanOpts } = extractJustification(opts);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, argv, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv, ...ev, actionHash, exitCode: null, halted: true });
      if (callback) {
        process.nextTick(() => callback!(makeEnoentError(binary), "", ""));
      }
      // Return a ChildProcess from a harmless no-op command
      return (_state.originals["spawn"] as Function)("true", [], { stdio: "ignore" });
    }

    const wrappedCallback = callback
      ? (err: Error | null, stdout: string | Buffer, stderr: string | Buffer) => {
          const stdoutStr = stdout ? String(stdout) : "";
          const stderrStr = stderr ? String(stderr) : "";
          const exitCode = err ? ((err as unknown as Record<string, unknown>).code as number ?? 1) : 0;
          const actionHash = computeActionHash(exitCode, stdoutStr, stderrStr);
          emitReceipt({ binary, argv, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode, halted: false });
          callback!(err, stdout, stderr);
        }
      : undefined;

    if (wrappedCallback) {
      return (_state.originals["exec"] as Function)(command, cleanOpts, wrappedCallback);
    }

    const child = (_state.originals["exec"] as Function)(command, cleanOpts) as ChildProcess;
    let stdoutBuf = "";
    let stderrBuf = "";
    child.stdout?.on("data", (chunk: Buffer | string) => { stdoutBuf += String(chunk); });
    child.stderr?.on("data", (chunk: Buffer | string) => { stderrBuf += String(chunk); });
    child.on("close", (code: number | null) => {
      const actionHash = computeActionHash(code ?? 0, stdoutBuf, stderrBuf);
      emitReceipt({ binary, argv, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode: code ?? 0, halted: false });
    });
    return child;
  } finally {
    _state.inIntercept = false;
  }
}

function patchedExecFileSync(
  file: string,
  args?: readonly string[] | Record<string, unknown>,
  options?: Record<string, unknown>,
): Buffer | string {
  if (_state.inIntercept) {
    return (_state.originals["execFileSync"] as Function)(file, args, options);
  }
  _state.inIntercept = true;
  try {
    let actualArgs: string[];
    let opts: Record<string, unknown>;
    if (Array.isArray(args)) {
      actualArgs = args as string[];
      opts = (options as Record<string, unknown>) ?? {};
    } else if (args && typeof args === "object") {
      actualArgs = [];
      opts = args as Record<string, unknown>;
    } else {
      actualArgs = [];
      opts = (options as Record<string, unknown>) ?? {};
    }

    const binary = path.basename(file);
    const { justification, cleanOpts } = extractJustification(opts);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, actualArgs, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv: actualArgs, ...ev, actionHash, exitCode: null, halted: true });
      throw makeEnoentError(binary);
    }

    try {
      const result = (_state.originals["execFileSync"] as Function)(file, actualArgs, cleanOpts);
      const stdout = typeof result === "string" ? result : result.toString("utf-8");
      const actionHash = computeActionHash(0, stdout, "");
      emitReceipt({ binary, argv: actualArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode: 0, halted: false });
      return result;
    } catch (err: unknown) {
      const e = err as Record<string, unknown>;
      const exitCode = (e.status as number) ?? 1;
      const stderr = e.stderr ? String(e.stderr) : "";
      const stdout = e.stdout ? String(e.stdout) : "";
      const actionHash = computeActionHash(exitCode, stdout, stderr);
      emitReceipt({ binary, argv: actualArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode, halted: false });
      throw err;
    }
  } finally {
    _state.inIntercept = false;
  }
}

function patchedExecFile(
  file: string,
  argsOrOptsOrCb?: readonly string[] | Record<string, unknown> | Function,
  optsOrCb?: Record<string, unknown> | Function,
  maybeCb?: Function,
): ChildProcess {
  if (_state.inIntercept) {
    return (_state.originals["execFile"] as Function)(file, argsOrOptsOrCb, optsOrCb, maybeCb);
  }
  _state.inIntercept = true;
  try {
    let actualArgs: string[];
    let opts: Record<string, unknown>;
    let callback: Function | undefined;

    if (typeof argsOrOptsOrCb === "function") {
      actualArgs = []; opts = {}; callback = argsOrOptsOrCb;
    } else if (Array.isArray(argsOrOptsOrCb)) {
      actualArgs = argsOrOptsOrCb as string[];
      if (typeof optsOrCb === "function") { opts = {}; callback = optsOrCb; }
      else { opts = (optsOrCb as Record<string, unknown>) ?? {}; callback = maybeCb; }
    } else if (argsOrOptsOrCb && typeof argsOrOptsOrCb === "object") {
      actualArgs = [];
      opts = argsOrOptsOrCb as Record<string, unknown>;
      callback = typeof optsOrCb === "function" ? optsOrCb : maybeCb;
    } else {
      actualArgs = []; opts = {};
      callback = typeof optsOrCb === "function" ? optsOrCb : maybeCb;
    }

    const binary = path.basename(file);
    const { justification, cleanOpts } = extractJustification(opts);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, actualArgs, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv: actualArgs, ...ev, actionHash, exitCode: null, halted: true });
      if (callback) {
        process.nextTick(() => callback!(makeEnoentError(binary), "", ""));
      }
      return (_state.originals["spawn"] as Function)("true", [], { stdio: "ignore" });
    }

    const wrappedCallback = callback
      ? (err: Error | null, stdout: string | Buffer, stderr: string | Buffer) => {
          const stdoutStr = stdout ? String(stdout) : "";
          const stderrStr = stderr ? String(stderr) : "";
          const exitCode = err ? ((err as unknown as Record<string, unknown>).code as number ?? 1) : 0;
          const actionHash = computeActionHash(exitCode, stdoutStr, stderrStr);
          emitReceipt({ binary, argv: actualArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode, halted: false });
          callback!(err, stdout, stderr);
        }
      : undefined;

    if (wrappedCallback) {
      return (_state.originals["execFile"] as Function)(file, actualArgs, cleanOpts, wrappedCallback);
    }

    const child = (_state.originals["execFile"] as Function)(file, actualArgs, cleanOpts) as ChildProcess;
    let stdoutBuf = "";
    let stderrBuf = "";
    child.stdout?.on("data", (chunk: Buffer | string) => { stdoutBuf += String(chunk); });
    child.stderr?.on("data", (chunk: Buffer | string) => { stderrBuf += String(chunk); });
    child.on("close", (code: number | null) => {
      const actionHash = computeActionHash(code ?? 0, stdoutBuf, stderrBuf);
      emitReceipt({ binary, argv: actualArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode: code ?? 0, halted: false });
    });
    return child;
  } finally {
    _state.inIntercept = false;
  }
}

function patchedSpawn(
  command: string,
  argsOrOpts?: readonly string[] | Record<string, unknown>,
  options?: Record<string, unknown>,
): ChildProcess {
  if (_state.inIntercept) {
    return (_state.originals["spawn"] as Function)(command, argsOrOpts, options);
  }
  _state.inIntercept = true;
  try {
    let actualArgs: string[];
    let opts: Record<string, unknown>;
    if (Array.isArray(argsOrOpts)) {
      actualArgs = argsOrOpts as string[];
      opts = (options as Record<string, unknown>) ?? {};
    } else if (argsOrOpts && typeof argsOrOpts === "object") {
      actualArgs = [];
      opts = argsOrOpts as Record<string, unknown>;
    } else {
      actualArgs = [];
      opts = (options as Record<string, unknown>) ?? {};
    }

    const binary = path.basename(command);
    const { justification, cleanOpts } = extractJustification(opts);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, actualArgs, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv: actualArgs, ...ev, actionHash, exitCode: null, halted: true });
      throw makeEnoentError(binary);
    }

    const child = (_state.originals["spawn"] as Function)(command, actualArgs, cleanOpts) as ChildProcess;
    let stdoutBuf = "";
    let stderrBuf = "";
    child.stdout?.on("data", (chunk: Buffer | string) => { stdoutBuf += String(chunk); });
    child.stderr?.on("data", (chunk: Buffer | string) => { stderrBuf += String(chunk); });
    child.on("close", (code: number | null) => {
      const actionHash = computeActionHash(code ?? 0, stdoutBuf, stderrBuf);
      emitReceipt({ binary, argv: actualArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode: code ?? 0, halted: false });
    });
    return child;
  } finally {
    _state.inIntercept = false;
  }
}

function patchedFork(
  modulePath: string,
  argsOrOpts?: readonly string[] | Record<string, unknown>,
  options?: Record<string, unknown>,
): ChildProcess {
  if (_state.inIntercept) {
    return (_state.originals["fork"] as Function)(modulePath, argsOrOpts, options);
  }
  _state.inIntercept = true;
  try {
    let actualArgs: string[];
    let opts: Record<string, unknown>;
    if (Array.isArray(argsOrOpts)) {
      actualArgs = argsOrOpts as string[];
      opts = (options as Record<string, unknown>) ?? {};
    } else if (argsOrOpts && typeof argsOrOpts === "object") {
      actualArgs = [];
      opts = argsOrOpts as Record<string, unknown>;
    } else {
      actualArgs = [];
      opts = (options as Record<string, unknown>) ?? {};
    }

    const binary = "node";
    const forkArgs = [modulePath, ...actualArgs];
    const { justification, cleanOpts } = extractJustification(opts);
    const envKeys = getEnvKeys(cleanOpts);
    const cwd = getCwd(cleanOpts);
    const ev = evaluate(binary, forkArgs, justification, cwd, envKeys);

    if (!shouldExecute(ev.decision)) {
      const actionHash = computeActionHash(null, "", "");
      emitReceipt({ binary, argv: forkArgs, ...ev, actionHash, exitCode: null, halted: true });
      throw makeEnoentError(binary);
    }

    const child = (_state.originals["fork"] as Function)(modulePath, actualArgs, cleanOpts) as ChildProcess;
    child.on("close", (code: number | null) => {
      const actionHash = computeActionHash(code ?? 0, "", "");
      emitReceipt({ binary, argv: forkArgs, ...ev, decision: effectiveDecision(ev.decision), actionHash, exitCode: code ?? 0, halted: false });
    });
    return child;
  } finally {
    _state.inIntercept = false;
  }
}

// ── Public API ───────────────────────────────────────────────────────

export async function patchChildProcess(options: PatchOptions): Promise<void> {
  if (_state.active) return;

  const { loadConstitution } = await import("../constitution.js");
  _state.constitution = loadConstitution(options.constitutionPath);
  _state.sink = options.sink;
  _state.options = options;

  const cp = _require("node:child_process");

  _state.originals["spawn"] = cp.spawn;
  _state.originals["spawnSync"] = cp.spawnSync;
  _state.originals["exec"] = cp.exec;
  _state.originals["execSync"] = cp.execSync;
  _state.originals["execFile"] = cp.execFile;
  _state.originals["execFileSync"] = cp.execFileSync;
  _state.originals["fork"] = cp.fork;

  cp.spawn = patchedSpawn;
  cp.spawnSync = patchedSpawnSync;
  cp.exec = patchedExec;
  cp.execSync = patchedExecSync;
  cp.execFile = patchedExecFile;
  cp.execFileSync = patchedExecFileSync;
  cp.fork = patchedFork;

  _state.active = true;
}

export function unpatchChildProcess(): void {
  if (!_state.active) return;

  const cp = _require("node:child_process");

  cp.spawn = _state.originals["spawn"];
  cp.spawnSync = _state.originals["spawnSync"];
  cp.exec = _state.originals["exec"];
  cp.execSync = _state.originals["execSync"];
  cp.execFile = _state.originals["execFile"];
  cp.execFileSync = _state.originals["execFileSync"];
  cp.fork = _state.originals["fork"];

  _state.originals = {};
  _state.constitution = null;
  _state.sink = null;
  _state.options = null;
  _state.inIntercept = false;
  _state.active = false;
}
