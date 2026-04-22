/**
 * Sanna Protocol — Authority evaluator
 *
 * Evaluates whether an action is permitted under a constitution's
 * authority boundaries. Checks three tiers in strict priority order:
 *
 * 1. cannot_execute — forbidden actions → halt
 * 2. must_escalate — actions requiring review → escalate
 * 3. can_execute — explicitly allowed actions → allow
 * 4. default — unmatched actions → allow (uncategorized)
 *
 * See Sanna specification v1.0, Section 2.7 and Appendix D.
 */

import type { Constitution, AuthorityDecision } from "./types.js";

// ── Stop words for condition matching ────────────────────────────────

const STOP_WORDS = new Set([
  "a", "an", "the", "and", "or", "but", "for", "nor", "so", "yet",
  "in", "on", "at", "to", "of", "by", "is", "it", "as", "if",
  "be", "do", "no", "not", "are", "was", "were", "has", "had",
  "with", "from", "into", "that", "this", "than",
]);

// ── Name normalization (Appendix D) ──────────────────────────────────

/**
 * Split camelCase/PascalCase into space-separated words.
 */
function splitCamelCase(s: string): string {
  // lowercase→Uppercase: deleteFile → delete File
  s = s.replace(/([a-z])([A-Z])/g, "$1 $2");
  // Uppercase run→Uppercase+Lowercase: XMLParser → XML Parser
  s = s.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2");
  // Letter→digit: file2delete → file 2delete
  s = s.replace(/([a-zA-Z])(\d)/g, "$1 $2");
  // Digit→letter: 2ndFile → 2nd File
  s = s.replace(/(\d)([a-zA-Z])/g, "$1 $2");
  return s;
}

/**
 * Normalize separators (_, -, ., /, :, @) and camelCase to spaces.
 */
function normalizeSeparators(s: string): string {
  s = splitCamelCase(s);
  s = s.replace(/[_\-./:@\\]+/g, " ");
  return s;
}

/**
 * Normalize a tool/action name for authority boundary matching.
 * NFKC → camelCase split → separator normalization → casefold → dot-join.
 */
export function normalizeAuthorityName(name: string): string {
  name = name.normalize("NFKC");
  name = normalizeSeparators(name);
  name = name.toLowerCase();  // casefold approximation for ASCII
  name = name.trim().replace(/\s+/g, ".");
  return name;
}

// ── Matching helpers ─────────────────────────────────────────────────

/**
 * Exact match with opt-in glob patterns.
 *
 * If pattern contains "*", treat as a glob (shell-style wildcard):
 *   "read_*" matches "read_file" but not "write_file"
 *   "*_delete" matches "user_delete" but not "delete_user"
 *   "*" matches everything
 *
 * Otherwise, exact match after normalization.
 * Separatorless fallback uses exact match too:
 *   readFile === read_file === read.file
 *   but readFile !== readFileSystem
 */
export function matchesAction(pattern: string, action: string): boolean {
  if (!action || !action.trim()) return false;
  if (!pattern || !pattern.trim()) return false;

  const p = normalizeAuthorityName(pattern);
  const a = normalizeAuthorityName(action);

  if (p.includes("*")) {
    // Glob matching: escape regex special chars except *, then * → .*
    const escaped = p.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    const regexStr = "^" + escaped.replace(/\*/g, ".*") + "$";
    return new RegExp(regexStr).test(a);
  }

  // Exact match
  if (p === a) return true;

  // Separatorless fallback: exact comparison
  const pStripped = p.replace(/[^a-z0-9]/g, "");
  const aStripped = a.replace(/[^a-z0-9]/g, "");
  if (pStripped && aStripped) {
    return pStripped === aStripped;
  }

  return false;
}

/**
 * Build a searchable context string from action name and params.
 */
function buildActionContext(action: string, params: Record<string, unknown>): string {
  const parts = [action];
  for (const [k, v] of Object.entries(params)) {
    parts.push(String(k));
    parts.push(String(v));
  }
  return parts.join(" ");
}

/**
 * Keyword-based condition matching.
 * Extracts significant words (3+ chars, not stop words) from condition
 * and checks if ALL appear as word-boundary matches in the action context.
 */
function matchesCondition(condition: string, actionContext: string): boolean {
  const contextLower = normalizeSeparators(actionContext.normalize("NFKC")).toLowerCase();
  const words = condition.normalize("NFKC").toLowerCase().split(/\s+/);
  const significant = words.filter((w) => w.length >= 3 && !STOP_WORDS.has(w));

  if (significant.length === 0) return false;

  return significant.every((word) => {
    const re = new RegExp("\\b" + word.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    return re.test(contextLower);
  });
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Evaluate whether an action is permitted under a constitution's
 * authority boundaries.
 *
 * Priority: cannot_execute > must_escalate > can_execute > default allow.
 */
export function evaluateAuthority(
  action: string,
  params: Record<string, unknown>,
  constitution: Constitution,
): AuthorityDecision {
  const ab = constitution.authority_boundaries;

  if (!ab) {
    return {
      decision: "allow",
      reason: "No authority boundaries defined in constitution",
      boundary_type: "uncategorized",
    };
  }

  if (!ab.cannot_execute.length && !ab.must_escalate.length && !ab.can_execute.length) {
    return {
      decision: "allow",
      reason: "Authority boundaries section is empty",
      boundary_type: "uncategorized",
    };
  }

  // 1. Check cannot_execute (highest priority)
  for (const forbidden of ab.cannot_execute) {
    if (matchesAction(forbidden, action)) {
      return {
        decision: "halt",
        reason: `Action matches cannot_execute rule: '${forbidden}'`,
        boundary_type: "cannot_execute",
      };
    }
  }

  // 2. Check must_escalate
  const actionContext = buildActionContext(action, params);
  for (const rule of ab.must_escalate) {
    if (matchesCondition(rule.condition, actionContext)) {
      return {
        decision: "escalate",
        reason: `Action matches escalation condition: '${rule.condition}'`,
        boundary_type: "must_escalate",
      };
    }
  }

  // 3. Check can_execute
  for (const allowed of ab.can_execute) {
    if (matchesAction(allowed, action)) {
      return {
        decision: "allow",
        reason: `Action matches can_execute rule: '${allowed}'`,
        boundary_type: "can_execute",
      };
    }
  }

  // 4. Default — allow with uncategorized
  return {
    decision: "allow",
    reason: "Action not matched by any authority boundary rule",
    boundary_type: "uncategorized",
  };
}
