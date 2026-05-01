/**
 * Manifest Phase 1: governed capability surface receipt builder.
 *
 * Reads a constitution and (optionally) an MCP tool catalog and produces a
 * com.sanna.manifest extension dict per v1.5 spec Section 2.20. The dict
 * flows into a session_manifest receipt emitted at session initialization.
 *
 * This module is shared composition logic. The gateway calls it for the
 * MCP surface; CLI + HTTP interceptors call it for their respective surfaces
 * in SAN-209.
 *
 * Mirrors src/sanna/manifest.py from sanna-repo SAN-202 PR #37.
 */

import { evaluateAuthority } from "./evaluator.js";
import { hashContent } from "./hashing.js";
import type { Constitution } from "./types.js";

// Stable suppression_reason enum per v1.5 spec Section 2.21
export const SUPPRESSION_REASON_CANNOT_EXECUTE = "cannot_execute";
export const SUPPRESSION_REASON_POLICY_DENIED = "policy_denied";
export const SUPPRESSION_REASON_ESCALATION_SUPPRESSED = "escalation_suppressed";
export const SUPPRESSION_REASON_SERVER_DEFAULT_DENIED = "server_default_denied";
export const SUPPRESSION_REASON_CONSTITUTION_INVALID = "constitution_invalid";
export const SUPPRESSION_REASON_CONTENT_MODE_REDACTED = "content_mode_redacted";
export const SUPPRESSION_REASON_UNKNOWN = "unknown";

export const VALID_SUPPRESSION_REASONS = new Set<string>([
  SUPPRESSION_REASON_CANNOT_EXECUTE,
  SUPPRESSION_REASON_POLICY_DENIED,
  SUPPRESSION_REASON_ESCALATION_SUPPRESSED,
  SUPPRESSION_REASON_SERVER_DEFAULT_DENIED,
  SUPPRESSION_REASON_CONSTITUTION_INVALID,
  SUPPRESSION_REASON_CONTENT_MODE_REDACTED,
  SUPPRESSION_REASON_UNKNOWN,
]);

export const MANIFEST_VERSION = "0.1";

export interface McpSurface {
  tools_delivered: string[];
  tools_suppressed: string[];
  suppression_reasons: Record<string, string>;
}

export interface CliSurface {
  patterns_delivered: string[];
  patterns_suppressed: string[];
  suppression_reasons: Record<string, string>;
  mode: string;
}

export interface HttpSurface {
  patterns_delivered: string[];
  patterns_suppressed: string[];
  suppression_reasons: Record<string, string>;
  mode: string;
}

export interface Surfaces {
  mcp?: McpSurface;
  cli?: CliSurface;
  http?: HttpSurface;
}

export interface Manifest {
  version: string;
  composition_basis: string;
  surfaces: Surfaces;
}

export function generateManifest(
  constitution: Constitution | null,
  mcpTools?: string[],
  surfaces?: Array<"mcp" | "cli" | "http">,
  contentMode?: "full" | "redacted" | "hashes_only",
): Manifest {
  const surfacesDict: Partial<Record<"mcp" | "cli" | "http", Record<string, unknown>>> = {};

  if (mcpTools !== undefined) {
    surfacesDict.mcp = _generateMcpSurface(constitution, mcpTools) as unknown as Record<string, unknown>;
  }

  if (constitution !== null && constitution.cli_permissions !== null) {
    surfacesDict.cli = _generateCliSurface(constitution) as unknown as Record<string, unknown>;
  }

  if (constitution !== null && constitution.api_permissions !== null) {
    surfacesDict.http = _generateHttpSurface(constitution) as unknown as Record<string, unknown>;
  }

  if (surfaces !== undefined) {
    const allowedSet = new Set<string>(surfaces);
    for (const k of Object.keys(surfacesDict) as Array<"mcp" | "cli" | "http">) {
      if (!allowedSet.has(k)) delete surfacesDict[k];
    }
  }

  if (contentMode === "redacted") {
    for (const surface of Object.values(surfacesDict)) {
      _redactForRedactedMode(surface);
    }
  } else if (contentMode === "hashes_only") {
    for (const surface of Object.values(surfacesDict)) {
      _redactForHashesOnlyMode(surface);
    }
  }

  return {
    version: MANIFEST_VERSION,
    composition_basis: "static",
    surfaces: surfacesDict as unknown as Surfaces,
  };
}

function _redactForRedactedMode(surface: Record<string, unknown>): void {
  const suppressedList = (
    (surface.tools_suppressed as string[] | undefined) ??
    (surface.patterns_suppressed as string[] | undefined) ??
    []
  );
  const supReasonsDict = (surface.suppression_reasons as Record<string, string> | undefined) ?? {};
  const aggregate = suppressedList.map((name) => supReasonsDict[name] ?? "unknown");

  for (const listField of ["tools_delivered", "tools_suppressed", "patterns_delivered", "patterns_suppressed"]) {
    if (Array.isArray(surface[listField])) {
      const count = (surface[listField] as unknown[]).length;
      surface[listField] = Array(count).fill("<redacted>");
    }
  }

  delete surface.suppression_reasons;
  if (aggregate.length > 0) {
    surface.aggregate_suppression_reasons = aggregate;
  }
}

function _redactForHashesOnlyMode(surface: Record<string, unknown>): void {
  for (const listField of ["tools_delivered", "tools_suppressed", "patterns_delivered", "patterns_suppressed"]) {
    if (Array.isArray(surface[listField])) {
      const items = surface[listField] as string[];
      const hashed = items.map((name) => hashContent(name));
      hashed.sort();
      surface[listField] = hashed;
    }
  }

  const supReasons = surface.suppression_reasons as Record<string, string> | undefined;
  if (supReasons !== undefined && Object.keys(supReasons).length > 0) {
    const newReasons: Record<string, string> = {};
    for (const [k, v] of Object.entries(supReasons)) {
      newReasons[hashContent(k)] = v;
    }
    surface.suppression_reasons = newReasons;
  }
}

function _generateMcpSurface(
  constitution: Constitution | null,
  mcpTools: string[],
): McpSurface {
  const delivered: string[] = [];
  const suppressed: string[] = [];
  const suppressionReasons: Record<string, string> = {};

  // Fail-closed: invalid or missing constitution suppresses all tools
  if (constitution === null || constitution.authority_boundaries === null) {
    for (const name of [...mcpTools].sort()) {
      suppressed.push(name);
      suppressionReasons[name] = SUPPRESSION_REASON_CONSTITUTION_INVALID;
    }
    return {
      tools_delivered: [],
      tools_suppressed: suppressed,
      suppression_reasons: suppressionReasons,
    };
  }

  const ab = constitution.authority_boundaries;
  const escalationVisibility = ab.escalation_visibility ?? "visible";

  for (const name of [...mcpTools].sort()) {
    const decision = evaluateAuthority(name, {}, constitution);
    if (decision.decision === "halt") {
      suppressed.push(name);
      suppressionReasons[name] = SUPPRESSION_REASON_CANNOT_EXECUTE;
    } else if (decision.decision === "escalate") {
      if (escalationVisibility === "suppressed") {
        suppressed.push(name);
        suppressionReasons[name] = SUPPRESSION_REASON_ESCALATION_SUPPRESSED;
      } else {
        delivered.push(name);
      }
    } else {
      delivered.push(name);
    }
  }

  return {
    tools_delivered: delivered,
    tools_suppressed: suppressed,
    suppression_reasons: suppressionReasons,
  };
}

function _generateCliSurface(constitution: Constitution): CliSurface {
  const cp = constitution.cli_permissions;
  if (cp === null) {
    return { patterns_delivered: [], patterns_suppressed: [], suppression_reasons: {}, mode: "strict" };
  }

  const escalationVisibility =
    constitution.authority_boundaries?.escalation_visibility ?? "visible";

  const delivered: string[] = [];
  const suppressed: string[] = [];
  const suppressionReasons: Record<string, string> = {};

  for (const cmd of cp.commands) {
    const pattern = cmd.binary;
    if (cmd.authority === "cannot_execute") {
      suppressed.push(pattern);
      suppressionReasons[pattern] = SUPPRESSION_REASON_CANNOT_EXECUTE;
    } else if (cmd.authority === "must_escalate") {
      if (escalationVisibility === "suppressed") {
        suppressed.push(pattern);
        suppressionReasons[pattern] = SUPPRESSION_REASON_ESCALATION_SUPPRESSED;
      } else {
        delivered.push(pattern);
      }
    } else {
      delivered.push(pattern);
    }
  }

  return {
    patterns_delivered: [...delivered].sort(),
    patterns_suppressed: [...suppressed].sort(),
    suppression_reasons: suppressionReasons,
    mode: cp.mode,
  };
}

function _generateHttpSurface(constitution: Constitution): HttpSurface {
  const ap = constitution.api_permissions;
  if (ap === null) {
    return { patterns_delivered: [], patterns_suppressed: [], suppression_reasons: {}, mode: "strict" };
  }

  const escalationVisibility =
    constitution.authority_boundaries?.escalation_visibility ?? "visible";

  const delivered: string[] = [];
  const suppressed: string[] = [];
  const suppressionReasons: Record<string, string> = {};

  for (const ep of ap.endpoints) {
    const pattern = ep.url_pattern;
    if (ep.authority === "cannot_execute") {
      suppressed.push(pattern);
      suppressionReasons[pattern] = SUPPRESSION_REASON_CANNOT_EXECUTE;
    } else if (ep.authority === "must_escalate") {
      if (escalationVisibility === "suppressed") {
        suppressed.push(pattern);
        suppressionReasons[pattern] = SUPPRESSION_REASON_ESCALATION_SUPPRESSED;
      } else {
        delivered.push(pattern);
      }
    } else {
      delivered.push(pattern);
    }
  }

  return {
    patterns_delivered: [...delivered].sort(),
    patterns_suppressed: [...suppressed].sort(),
    suppression_reasons: suppressionReasons,
    mode: ap.mode,
  };
}
