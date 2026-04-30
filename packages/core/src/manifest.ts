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
  mode: string;
}

export interface HttpSurface {
  patterns_delivered: string[];
  patterns_suppressed: string[];
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
): Manifest {
  const surfaces: Surfaces = {};

  if (mcpTools !== undefined) {
    surfaces.mcp = _generateMcpSurface(constitution, mcpTools);
  }

  if (constitution !== null && constitution.cli_permissions !== null) {
    surfaces.cli = _generateCliSurface(constitution);
  }

  if (constitution !== null && constitution.api_permissions !== null) {
    surfaces.http = _generateHttpSurface(constitution);
  }

  return {
    version: MANIFEST_VERSION,
    composition_basis: "static",
    surfaces,
  };
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
    return { patterns_delivered: [], patterns_suppressed: [], mode: "strict" };
  }

  const escalationVisibility =
    constitution.authority_boundaries?.escalation_visibility ?? "visible";

  const delivered: string[] = [];
  const suppressed: string[] = [];

  for (const cmd of cp.commands) {
    if (cmd.authority === "cannot_execute") {
      suppressed.push(cmd.binary);
    } else if (cmd.authority === "must_escalate") {
      if (escalationVisibility === "suppressed") {
        suppressed.push(cmd.binary);
      } else {
        delivered.push(cmd.binary);
      }
    } else {
      delivered.push(cmd.binary);
    }
  }

  return {
    patterns_delivered: [...delivered].sort(),
    patterns_suppressed: [...suppressed].sort(),
    mode: cp.mode,
  };
}

function _generateHttpSurface(constitution: Constitution): HttpSurface {
  const ap = constitution.api_permissions;
  if (ap === null) {
    return { patterns_delivered: [], patterns_suppressed: [], mode: "strict" };
  }

  const escalationVisibility =
    constitution.authority_boundaries?.escalation_visibility ?? "visible";

  const delivered: string[] = [];
  const suppressed: string[] = [];

  for (const ep of ap.endpoints) {
    if (ep.authority === "cannot_execute") {
      suppressed.push(ep.url_pattern);
    } else if (ep.authority === "must_escalate") {
      if (escalationVisibility === "suppressed") {
        suppressed.push(ep.url_pattern);
      } else {
        delivered.push(ep.url_pattern);
      }
    } else {
      delivered.push(ep.url_pattern);
    }
  }

  return {
    patterns_delivered: [...delivered].sort(),
    patterns_suppressed: [...suppressed].sort(),
    mode: ap.mode,
  };
}
