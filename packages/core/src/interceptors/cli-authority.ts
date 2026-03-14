/**
 * CLI authority evaluation for child process interception.
 *
 * Evaluates binary + argv against cli_permissions in a constitution.
 * Same logic as Python's cli_authority.py for cross-language determinism.
 */

import type { Constitution, CliAuthorityDecision, CliInvariant } from "../types.js";

/**
 * Evaluate whether a CLI command is authorized by the constitution's cli_permissions.
 *
 * Matching: binary exact match (case-sensitive), then argv glob match.
 * If no rule matches: strict mode halts, permissive mode allows.
 */
export function evaluateCliAuthority(
  binary: string,
  argv: string[],
  constitution: Constitution,
): CliAuthorityDecision {
  const cliPerms = constitution.cli_permissions;
  if (!cliPerms) {
    return { decision: "allow", reason: "No cli_permissions in constitution" };
  }

  const argvStr = argv.join(" ");

  for (const cmd of cliPerms.commands) {
    // Binary match: exact, case-sensitive
    if (cmd.binary !== binary) continue;

    // Argv pattern: glob match
    const pattern = cmd.argv_pattern ?? "*";
    if (pattern === "*" || globMatch(argvStr, pattern)) {
      if (cmd.authority === "cannot_execute") {
        return {
          decision: "halt",
          reason: `Binary '${binary}' matches cannot_execute rule: ${cmd.id}`,
          rule_id: cmd.id,
        };
      } else if (cmd.authority === "must_escalate") {
        return {
          decision: "escalate",
          reason: `Binary '${binary}' matches must_escalate rule: ${cmd.id}`,
          rule_id: cmd.id,
          escalation_target: cmd.escalation_target,
        };
      } else {
        return {
          decision: "allow",
          reason: `Binary '${binary}' matches can_execute rule: ${cmd.id}`,
          rule_id: cmd.id,
        };
      }
    }
  }

  // No rule matched
  if (cliPerms.mode === "strict") {
    return {
      decision: "halt",
      reason: `Binary '${binary}' not listed in strict mode cli_permissions`,
    };
  }
  return {
    decision: "allow",
    reason: `Binary '${binary}' not listed (permissive mode, audit receipt emitted)`,
  };
}

/**
 * Check CLI invariants against the full command string.
 * Returns the first matching invariant, or null if none match.
 */
export function checkCliInvariants(
  binary: string,
  argv: string[],
  constitution: Constitution,
): CliInvariant | null {
  const cliPerms = constitution.cli_permissions;
  if (!cliPerms?.invariants?.length) return null;

  const fullCommand = `${binary} ${argv.join(" ")}`;
  for (const inv of cliPerms.invariants) {
    if (inv.pattern && new RegExp(inv.pattern).test(fullCommand)) {
      return inv;
    }
  }
  return null;
}

/**
 * Simple glob matcher (fnmatch equivalent).
 * Supports * (match any) and ? (match single char).
 */
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
