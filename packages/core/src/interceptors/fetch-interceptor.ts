/**
 * Fetch/HTTP interceptor — patches globalThis.fetch and http/https.request
 * to enforce API governance via constitution-based authority evaluation.
 *
 * Mirrors Python Deliverable 3 (patch_http). Same enforcement logic,
 * same hash computation, same receipt fields, same anti-enumeration.
 */

import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";

import type { ReceiptSink, Constitution } from "../types.js";
import { hashObj, hashContent, hashBytes, EMPTY_HASH } from "../hashing.js";
import { generateReceipt } from "../receipt.js";
import { evaluateApiAuthority, checkApiInvariants } from "./api-authority.js";

// ── Types ────────────────────────────────────────────────────────────

export interface HttpPatchOptions {
  constitutionPath: string;
  sink: ReceiptSink;
  agentId: string;
  mode?: "enforce" | "audit" | "passthrough";
  signingKey?: Buffer;
  contentMode?: "full" | "redacted" | "hashes_only";
  workflowId?: string;
  parentFingerprint?: string;
  excludeUrls?: string[];
}

interface HttpInterceptorState {
  active: boolean;
  originals: Record<string, Function>;
  constitution: Constitution | null;
  sink: ReceiptSink | null;
  options: HttpPatchOptions | null;
  excludePatterns: string[];
  inIntercept: boolean;
}

// ── State ────────────────────────────────────────────────────────────

const _state: HttpInterceptorState = {
  active: false,
  originals: {},
  constitution: null,
  sink: null,
  options: null,
  excludePatterns: [],
  inIntercept: false,
};

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore — import.meta.url is ESM-only; CJS build uses __filename fallback
const _require = createRequire(typeof import.meta?.url === "string" ? import.meta.url : __filename);

// Default exclusions — always added, cannot be removed
const DEFAULT_EXCLUDES = [
  "https://api.sanna.cloud/*",
  "https://*.sanna.cloud/*",
];

// ── Helpers ──────────────────────────────────────────────────────────

function globMatch(str: string, pattern: string): boolean {
  const regex = new RegExp(
    "^" +
      pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".") +
      "$",
  );
  return regex.test(str);
}

function isExcluded(url: string): boolean {
  return _state.excludePatterns.some((pattern) => globMatch(url, pattern));
}

function extractUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.toString();
  return (input as Request).url;
}

function extractMethod(input: string | URL | Request, init?: RequestInit): string {
  if (init?.method) return init.method.toUpperCase();
  if (typeof input !== "string" && !(input instanceof URL) && (input as Request).method) {
    return (input as Request).method.toUpperCase();
  }
  return "GET";
}

function extractHeaderKeys(headers?: RequestInit["headers"]): string[] {
  if (!headers) return [];
  if (headers instanceof Headers) {
    return [...headers.keys()].sort();
  }
  if (Array.isArray(headers)) {
    return headers.map(([k]) => k).sort();
  }
  return Object.keys(headers).sort();
}

function extractJustification(init?: RequestInit): { justification: string | null; cleanInit: RequestInit | undefined } {
  if (!init?.headers) return { justification: null, cleanInit: init };

  const headers = new Headers(init.headers);
  const justification = headers.get("X-Sanna-Justification");
  if (justification) {
    headers.delete("X-Sanna-Justification");
    return {
      justification,
      cleanInit: { ...init, headers },
    };
  }
  return { justification: null, cleanInit: init };
}

async function computeBodyHash(body: RequestInit["body"] | null | undefined): Promise<string> {
  if (!body) return EMPTY_HASH;

  let bytes: Buffer;
  if (typeof body === "string") {
    bytes = Buffer.from(body, "utf-8");
  } else if (body instanceof ArrayBuffer) {
    bytes = Buffer.from(body);
  } else if (ArrayBuffer.isView(body)) {
    bytes = Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  } else if (body instanceof Blob) {
    const ab = await body.arrayBuffer();
    bytes = Buffer.from(ab);
  } else if (body instanceof URLSearchParams) {
    bytes = Buffer.from(body.toString(), "utf-8");
  } else if (body instanceof ReadableStream) {
    // Can't read a stream without consuming it; use EMPTY_HASH
    return EMPTY_HASH;
  } else {
    return EMPTY_HASH;
  }

  return bytes.length > 0 ? hashBytes(bytes) : EMPTY_HASH;
}

function determineEventType(decision: string, mode: string): string {
  if (decision === "halt") return "api_invocation_halted";
  if (decision === "escalate") return "api_invocation_escalated";
  return "api_invocation_allowed";
}

async function emitHttpReceipt(params: {
  method: string; url: string;
  inputHash: string; reasoningHash: string; actionHash: string;
  decision: string; reason: string; ruleId?: string;
  eventType: string; contextLimitation: string;
  statusCode: number | null; halted: boolean;
}): Promise<void> {
  const opts = _state.options!;
  const receipt = generateReceipt({
    correlation_id: randomUUID(),
    inputs: { method: params.method, url: params.url, agent_id: opts.agentId },
    outputs: {
      decision: params.decision, reason: params.reason,
      rule_id: params.ruleId ?? null, status_code: params.statusCode,
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

  await _state.sink!.store(receipt).catch(() => {});
}

function shouldExecute(decision: string): boolean {
  const mode = _state.options?.mode ?? "enforce";
  if (mode === "passthrough" || mode === "audit") return true;
  return decision !== "halt";
}

// ── Patched fetch ────────────────────────────────────────────────────

async function patchedFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  // Re-entrancy guard
  if (_state.inIntercept) {
    return (_state.originals["fetch"] as typeof globalThis.fetch)(input, init);
  }

  const url = extractUrl(input);
  if (isExcluded(url)) {
    return (_state.originals["fetch"] as typeof globalThis.fetch)(input, init);
  }

  _state.inIntercept = true;
  try {
    const method = extractMethod(input, init);
    const { justification, cleanInit } = extractJustification(init);

    // Compute header keys from cleaned init (after justification stripped)
    const headersKeys = extractHeaderKeys(cleanInit?.headers);
    const bodyHash = await computeBodyHash(cleanInit?.body);

    // input_hash: canonical key order (alphabetical: body_hash, headers_keys, method, url)
    const inputHash = hashObj({ body_hash: bodyHash, headers_keys: headersKeys, method, url });
    const reasoningHash = justification ? hashContent(justification) : EMPTY_HASH;

    // Evaluate authority
    const authDecision = evaluateApiAuthority(method, url, _state.constitution!);
    const invariant = checkApiInvariants(url, _state.constitution!);

    let decision = authDecision.decision;
    let reason = authDecision.reason;
    if (invariant && invariant.verdict === "halt") {
      decision = "halt";
      reason = `Invariant ${invariant.id}: ${invariant.description}`;
    }

    const mode = _state.options!.mode ?? "enforce";
    const contextLimitation = justification ? "api_execution" : "api_no_justification";
    const eventType = determineEventType(decision, mode);

    if (!shouldExecute(decision)) {
      // Halted action hash
      const actionHash = hashObj({
        body_hash: EMPTY_HASH,
        response_headers_keys: [] as string[],
        status_code: null,
      });
      await emitHttpReceipt({
        method, url, inputHash, reasoningHash, actionHash,
        decision, reason, ruleId: authDecision.rule_id,
        eventType, contextLimitation, statusCode: null, halted: true,
      });

      const err = new TypeError("fetch failed");
      err.cause = new Error(`connect ECONNREFUSED ${url}`);
      throw err;
    }

    // Execute the real fetch
    const response = await (_state.originals["fetch"] as typeof globalThis.fetch)(input, cleanInit);

    // Compute action_hash from response
    const respHeadersKeys = [...response.headers.keys()].sort();
    const cloned = response.clone();
    let respBodyHash: string;
    try {
      const respBodyBytes = await cloned.arrayBuffer();
      respBodyHash = respBodyBytes.byteLength > 0
        ? hashBytes(Buffer.from(respBodyBytes))
        : EMPTY_HASH;
    } catch {
      respBodyHash = EMPTY_HASH;
    }

    const actionHash = hashObj({
      body_hash: respBodyHash,
      response_headers_keys: respHeadersKeys,
      status_code: response.status,
    });

    await emitHttpReceipt({
      method, url, inputHash, reasoningHash, actionHash,
      decision, reason, ruleId: authDecision.rule_id,
      eventType, contextLimitation, statusCode: response.status, halted: false,
    });

    return response;
  } finally {
    _state.inIntercept = false;
  }
}

// ── Patched http/https.request ───────────────────────────────────────

function buildUrlFromHttpArgs(args: unknown[], protocol: string): string {
  const first = args[0];
  if (typeof first === "string") return first;
  if (first instanceof URL) return first.toString();
  if (first && typeof first === "object") {
    const opts = first as Record<string, unknown>;
    const host = (opts.hostname ?? opts.host ?? "localhost") as string;
    const port = opts.port ? `:${opts.port}` : "";
    const path = (opts.path ?? "/") as string;
    return `${protocol}//${host}${port}${path}`;
  }
  return `${protocol}//localhost/`;
}

function buildMethodFromHttpArgs(args: unknown[]): string {
  const first = args[0];
  if (first && typeof first === "object" && !Array.isArray(first) && !(first instanceof URL)) {
    const opts = first as Record<string, unknown>;
    return ((opts.method as string) ?? "GET").toUpperCase();
  }
  if (args.length > 1 && args[1] && typeof args[1] === "object") {
    const opts = args[1] as Record<string, unknown>;
    return ((opts.method as string) ?? "GET").toUpperCase();
  }
  return "GET";
}

function extractHttpHeaderKeys(args: unknown[]): string[] {
  for (const arg of args) {
    if (arg && typeof arg === "object" && !Array.isArray(arg) && !(arg instanceof URL)) {
      const opts = arg as Record<string, unknown>;
      if (opts.headers && typeof opts.headers === "object") {
        return Object.keys(opts.headers as Record<string, unknown>).sort();
      }
    }
  }
  return [];
}

function createPatchedHttpRequest(protocol: string, originalKey: string): Function {
  return function patchedRequest(this: unknown, ...args: unknown[]) {
    if (_state.inIntercept) {
      return (_state.originals[originalKey] as Function).apply(this, args);
    }

    const url = buildUrlFromHttpArgs(args, protocol);
    if (isExcluded(url)) {
      return (_state.originals[originalKey] as Function).apply(this, args);
    }

    _state.inIntercept = true;
    const self = this;
    try {
      const method = buildMethodFromHttpArgs(args);
      const headersKeys = extractHttpHeaderKeys(args);
      const inputHash = hashObj({ body_hash: EMPTY_HASH, headers_keys: headersKeys, method, url });
      const reasoningHash = EMPTY_HASH;

      const authDecision = evaluateApiAuthority(method, url, _state.constitution!);
      const invariant = checkApiInvariants(url, _state.constitution!);

      let decision = authDecision.decision;
      let reason = authDecision.reason;
      if (invariant && invariant.verdict === "halt") {
        decision = "halt";
        reason = `Invariant ${invariant.id}: ${invariant.description}`;
      }

      const mode = _state.options!.mode ?? "enforce";
      const eventType = determineEventType(decision, mode);

      if (!shouldExecute(decision)) {
        const actionHash = hashObj({
          body_hash: EMPTY_HASH,
          response_headers_keys: [] as string[],
          status_code: null,
        });
        emitHttpReceipt({
          method, url, inputHash, reasoningHash, actionHash,
          decision, reason, ruleId: authDecision.rule_id,
          eventType, contextLimitation: "api_no_justification",
          statusCode: null, halted: true,
        });
        const err = new Error(`connect ECONNREFUSED ${url}`) as NodeJS.ErrnoException;
        err.code = "ECONNREFUSED";
        throw err;
      }

      const req = (_state.originals[originalKey] as Function).apply(self, args);

      const origOn = req.on.bind(req);
      req.on = function (this: unknown, event: string, listener: Function) {
        if (event === "response") {
          const wrappedListener = (res: { statusCode?: number; headers?: Record<string, string> }) => {
            const statusCode = res.statusCode ?? 0;
            const respHeadersKeys = res.headers ? Object.keys(res.headers).sort() : [];
            const actionHash = hashObj({
              body_hash: EMPTY_HASH,
              response_headers_keys: respHeadersKeys,
              status_code: statusCode,
            });
            emitHttpReceipt({
              method, url, inputHash, reasoningHash, actionHash,
              decision, reason, ruleId: authDecision.rule_id,
              eventType, contextLimitation: "api_no_justification",
              statusCode, halted: false,
            });
            listener(res);
          };
          return origOn(event, wrappedListener);
        }
        return origOn(event, listener);
      };

      return req;
    } finally {
      _state.inIntercept = false;
    }
  };
}

// ── Public API ───────────────────────────────────────────────────────

export async function patchFetch(options: HttpPatchOptions): Promise<void> {
  if (_state.active) return;

  const { loadConstitution } = await import("../constitution.js");
  _state.constitution = loadConstitution(options.constitutionPath);
  _state.sink = options.sink;
  _state.options = options;

  // Build exclusion patterns
  _state.excludePatterns = [...DEFAULT_EXCLUDES, ...(options.excludeUrls ?? [])];

  // Patch globalThis.fetch
  _state.originals["fetch"] = globalThis.fetch;
  globalThis.fetch = patchedFetch as typeof globalThis.fetch;

  // Patch http.request and https.request
  const http = _require("node:http");
  const https = _require("node:https");

  _state.originals["http.request"] = http.request;
  _state.originals["https.request"] = https.request;

  http.request = createPatchedHttpRequest("http:", "http.request");
  https.request = createPatchedHttpRequest("https:", "https.request");

  _state.active = true;
}

export function unpatchFetch(): void {
  if (!_state.active) return;

  // Restore fetch
  if (_state.originals["fetch"]) {
    globalThis.fetch = _state.originals["fetch"] as typeof globalThis.fetch;
  }

  // Restore http/https
  const http = _require("node:http");
  const https = _require("node:https");

  if (_state.originals["http.request"]) {
    http.request = _state.originals["http.request"];
  }
  if (_state.originals["https.request"]) {
    https.request = _state.originals["https.request"];
  }

  _state.originals = {};
  _state.constitution = null;
  _state.sink = null;
  _state.options = null;
  _state.excludePatterns = [];
  _state.inIntercept = false;
  _state.active = false;
}
