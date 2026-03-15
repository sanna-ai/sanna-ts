/**
 * API authority evaluation for fetch/HTTP interception.
 *
 * Evaluates URL + method against api_permissions in a constitution.
 * Same logic as Python's api_authority.py for cross-language determinism.
 */

import type { Constitution, ApiAuthorityDecision, ApiInvariant } from "../types.js";

/**
 * Evaluate whether an API request is authorized by the constitution's api_permissions.
 *
 * Matching: URL glob pattern, then method list match.
 * If no rule matches: strict mode halts, permissive mode allows.
 */
export function evaluateApiAuthority(
  method: string,
  url: string,
  constitution: Constitution,
): ApiAuthorityDecision {
  const apiPerms = constitution.api_permissions;
  if (!apiPerms) {
    return { decision: "allow", reason: "No api_permissions in constitution" };
  }

  for (const endpoint of apiPerms.endpoints) {
    if (!globMatch(url, endpoint.url_pattern)) continue;

    const methods = endpoint.methods ?? ["*"];
    if (!methods.includes("*") && !methods.map((m) => m.toUpperCase()).includes(method.toUpperCase())) {
      continue;
    }

    if (endpoint.authority === "cannot_execute") {
      return {
        decision: "halt",
        reason: `URL '${url}' method '${method}' matches cannot_execute rule: ${endpoint.id}`,
        rule_id: endpoint.id,
      };
    } else if (endpoint.authority === "must_escalate") {
      return {
        decision: "escalate",
        reason: `URL '${url}' method '${method}' matches must_escalate rule: ${endpoint.id}`,
        rule_id: endpoint.id,
        escalation_target: endpoint.escalation_target,
      };
    } else {
      return {
        decision: "allow",
        reason: `URL '${url}' method '${method}' matches can_execute rule: ${endpoint.id}`,
        rule_id: endpoint.id,
      };
    }
  }

  if (apiPerms.mode === "strict") {
    return {
      decision: "halt",
      reason: `URL '${url}' not matched in strict mode api_permissions`,
    };
  }
  return {
    decision: "allow",
    reason: `URL '${url}' not matched (permissive mode, audit receipt emitted)`,
  };
}

/**
 * Check API invariants against the URL.
 * Returns the first matching invariant, or null if none match.
 */
export function checkApiInvariants(
  url: string,
  constitution: Constitution,
): ApiInvariant | null {
  const apiPerms = constitution.api_permissions;
  if (!apiPerms?.invariants?.length) return null;

  for (const inv of apiPerms.invariants) {
    if (inv.pattern && new RegExp(inv.pattern).test(url)) {
      return inv;
    }
  }
  return null;
}

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
