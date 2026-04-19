/**
 * Fetch/HTTP interceptor — patches globalThis.fetch and http/https.request
 * to enforce API governance via constitution-based authority evaluation.
 *
 * Mirrors Python Deliverable 3 (patch_http). Same enforcement logic,
 * same hash computation, same receipt fields, same anti-enumeration.
 */

import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { resolve4, resolve6 } from "node:dns/promises";

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

// ── SSRF Protection ─────────────────────────────────────────────────

const PRIVATE_IPV4_RANGES: Array<{ addr: number; mask: number }> = [
  { addr: 0x7f000000, mask: 0xff000000 }, // 127.0.0.0/8
  { addr: 0x0a000000, mask: 0xff000000 }, // 10.0.0.0/8
  { addr: 0xac100000, mask: 0xfff00000 }, // 172.16.0.0/12
  { addr: 0xc0a80000, mask: 0xffff0000 }, // 192.168.0.0/16
  { addr: 0xa9fe0000, mask: 0xffff0000 }, // 169.254.0.0/16
  { addr: 0x00000000, mask: 0xff000000 }, // 0.0.0.0/8
];

function parseIpv4(ip: string): number | null {
  if (!ip) return null;
  // Handle octal (0177.0.0.1) and decimal (2130706433) notation
  const parts = ip.split(".");
  if (parts.length === 1) {
    // Decimal notation: e.g. "2130706433" → 127.0.0.1
    if (!/^\d+$/.test(parts[0])) return null;
    const n = Number(parts[0]);
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null;
    return n >>> 0;
  }
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (part === "") return null;
    // Parse octal (leading 0) or decimal
    const n = part.startsWith("0") && part.length > 1 ? parseInt(part, 8) : parseInt(part, 10);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

function isPrivateIpv4(ip: string): boolean {
  const num = parseIpv4(ip);
  if (num === null) return false;
  // >>> 0 ensures unsigned comparison (JS bitwise ops return signed 32-bit)
  return PRIVATE_IPV4_RANGES.some(({ addr, mask }) => ((num & mask) >>> 0) === addr);
}

function isPrivateIpv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  // fc00::/7 (unique local)
  if (/^f[cd]/i.test(normalized)) return true;
  // fe80::/10 (link-local)
  if (/^fe[89ab]/i.test(normalized)) return true;
  // IPv4-mapped IPv6: ::ffff:x.x.x.x (dotted notation)
  const mapped = normalized.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return isPrivateIpv4(mapped[1]);
  // IPv4-mapped IPv6: ::ffff:HHHH:HHHH (hex notation, as URL constructor normalizes)
  const mappedHex = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isPrivateIpv4(ipv4);
  }
  // IPv4-compatible IPv6: ::x.x.x.x
  const compat = normalized.match(/^::(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (compat) return isPrivateIpv4(compat[1]);
  return false;
}

export function isPrivateIp(ip: string): boolean {
  return isPrivateIpv4(ip) || isPrivateIpv6(ip);
}

function normalizeUrlForMatching(url: string): string {
  try {
    const parsed = new URL(url);
    // Decode + lowercase hostname handles punycode/unicode normalization
    // URL constructor already converts unicode hostnames to punycode
    parsed.hostname = parsed.hostname.toLowerCase();
    // Decode percent-encoding in path for consistent matching
    parsed.pathname = decodeURIComponent(parsed.pathname);
    return parsed.toString();
  } catch {
    // If URL parsing fails, lowercase the whole thing as fallback
    return url.toLowerCase();
  }
}

async function resolveHostIps(hostname: string): Promise<string[]> {
  const ips: string[] = [];
  try {
    ips.push(...(await resolve4(hostname)));
  } catch { /* no A records */ }
  try {
    ips.push(...(await resolve6(hostname)));
  } catch { /* no AAAA records */ }
  return ips;
}

async function validateNotPrivateHost(url: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return; // Not a valid URL — let the actual request fail
  }

  const hostname = parsed.hostname;

  // Check if hostname is an IP literal
  // Strip brackets for IPv6 literals like [::1]
  const bare = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;

  if (isPrivateIp(bare)) {
    throw new TypeError(`fetch failed: request to private IP ${bare} blocked (SSRF protection)`);
  }

  // DNS resolution check — resolve hostname and verify no private IPs
  if (!bare.match(/^[\d.]+$/) && !bare.includes(":")) {
    // It's a hostname, not an IP literal — resolve it
    const ips = await resolveHostIps(bare);
    for (const ip of ips) {
      if (isPrivateIp(ip)) {
        throw new TypeError(`fetch failed: hostname ${hostname} resolves to private IP ${ip} (SSRF protection)`);
      }
    }
  }
}

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
  const normalized = normalizeUrlForMatching(url);
  return _state.excludePatterns.some(
    (pattern) => globMatch(normalized, pattern) || globMatch(url, pattern),
  );
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
  const ENFORCEMENT_ACTION_MAP: Record<string, string> = {
    halt: "halted",
    escalate: "escalated",
    allow: "allowed",
  };
  const enforcementAction = ENFORCEMENT_ACTION_MAP[params.decision] ?? "allowed";

  const opts = _state.options!;
  const receipt = generateReceipt({
    correlation_id: randomUUID(),
    inputs: { method: params.method, url: params.url, agent_id: opts.agentId },
    outputs: { status_code: params.statusCode },
    checks: [],
    enforcement: {
      action: enforcementAction,
      reason: params.reason,
      failed_checks: [],
      enforcement_mode: opts.mode ?? "enforce",
      timestamp: new Date().toISOString(),
    },
    enforcementSurface: "http_interceptor",
    invariantsScope: "authority_only",
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

  // SSRF validation — must happen before any request is made
  await validateNotPrivateHost(url);

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

    // SSRF validation — synchronous check for IP literals
    {
      let parsed: URL | null = null;
      try { parsed = new URL(url); } catch { /* let it fail later */ }
      if (parsed) {
        const hostname = parsed.hostname;
        const bare = hostname.startsWith("[") && hostname.endsWith("]")
          ? hostname.slice(1, -1)
          : hostname;
        if (isPrivateIp(bare)) {
          const err = new Error(`connect ECONNREFUSED ${url}: request to private IP ${bare} blocked (SSRF protection)`) as NodeJS.ErrnoException;
          err.code = "ECONNREFUSED";
          throw err;
        }
      }
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
