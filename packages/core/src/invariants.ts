/**
 * Sanna Protocol — Custom Invariant Checks
 *
 * Extracts invariant definitions from constitutions and evaluates them
 * against output. Supports built-in invariant types:
 *   - regex_match: output must match a regex pattern
 *   - regex_deny: output must NOT match a regex pattern
 *   - max_length: output must not exceed a character/word limit
 *   - required_keywords: output must contain specified keywords
 *   - pii_detection: output must not contain PII patterns (email, phone)
 *
 * Modeled after the Python enforcement/constitution_engine.py module.
 */

import isSafeRegex from "safe-regex2";
import { getEvaluator } from "./evaluator-registry.js";
import type { CheckResult, Constitution, InvariantDefinition } from "./types.js";

// ── PII patterns ─────────────────────────────────────────────────────

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
const PHONE_RE = /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/;

// ── Invariant type detection ─────────────────────────────────────────

/**
 * Detect the invariant type from its rule text when no explicit type is set.
 *
 * Heuristics:
 * - "regex" or "pattern" → regex_match/regex_deny
 * - "max" + "length"/"characters"/"words" → max_length
 * - "must contain" / "required keyword" → required_keywords
 * - "pii" / "personal" / "email" / "phone" → pii_detection
 */
function detectInvariantType(rule: string): string | null {
  const lower = rule.toLowerCase();

  if (/\bpii\b|personal.*information|email.*address|phone.*number|social.*security/.test(lower)) {
    return "pii_detection";
  }
  if (/\bmax(?:imum)?\s+\d+\s+(?:char|word|token|length)/.test(lower)) {
    return "max_length";
  }
  if (/\bmust contain\b|\brequired keyword/.test(lower)) {
    return "required_keywords";
  }
  if (/\bmust not match\b|\bforbidden pattern\b|\bdeny pattern\b/.test(lower)) {
    return "regex_deny";
  }
  if (/\bmust match\b|\brequired pattern\b/.test(lower)) {
    return "regex_match";
  }

  return null;
}

/**
 * Extract a regex pattern from a rule string.
 * Looks for patterns in /.../ or after "pattern:" or "regex:".
 */
function extractPattern(rule: string): string | null {
  // /pattern/ syntax
  const slashMatch = rule.match(/\/(.+?)\//);
  if (slashMatch) return slashMatch[1];

  // "pattern: xyz" or "regex: xyz" syntax
  const colonMatch = rule.match(/(?:pattern|regex):\s*(.+?)(?:\s*$|\s*,)/i);
  if (colonMatch) return colonMatch[1].trim();

  return null;
}

/**
 * Extract a numeric limit from a rule string.
 */
function extractMaxLength(rule: string): { limit: number; unit: "characters" | "words" } | null {
  const match = rule.match(/max(?:imum)?\s+(\d+)\s+(char(?:acter)?s?|words?|tokens?)/i);
  if (!match) return null;
  const limit = parseInt(match[1], 10);
  const unit = match[2].toLowerCase().startsWith("word") ? "words" : "characters";
  return { limit, unit };
}

/**
 * Extract keywords from a rule string.
 * Looks for comma-separated or quoted terms after "contain" or "keywords:".
 */
function extractKeywords(rule: string): string[] {
  // "keywords: a, b, c" syntax
  const colonMatch = rule.match(/keywords?:\s*(.+?)$/im);
  if (colonMatch) {
    return colonMatch[1].split(",").map((k) => k.trim().replace(/^["']|["']$/g, "")).filter(Boolean);
  }

  // "must contain 'x', 'y'" syntax
  const quotedMatches = rule.match(/['"]([^'"]+)['"]/g);
  if (quotedMatches && quotedMatches.length > 0) {
    return quotedMatches.map((m) => m.replace(/^['"]|['"]$/g, ""));
  }

  return [];
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Extract invariant definitions from a constitution, enriching each
 * with detected type and parsed parameters.
 */
export function loadInvariantChecks(constitution: Constitution): InvariantDefinition[] {
  return constitution.invariants.map((inv) => {
    const detected = inv.check ? null : detectInvariantType(inv.rule);
    const type = detected ?? undefined;

    const def: InvariantDefinition = {
      id: inv.id,
      rule: inv.rule,
      enforcement: inv.enforcement,
      type,
    };

    if (type === "regex_match" || type === "regex_deny") {
      const pattern = extractPattern(inv.rule);
      if (pattern) def.pattern = pattern;
    } else if (type === "max_length") {
      const parsed = extractMaxLength(inv.rule);
      if (parsed) def.maxLength = parsed.limit;
    } else if (type === "required_keywords") {
      def.keywords = extractKeywords(inv.rule);
    }

    return def;
  });
}

/**
 * Run a single invariant check against output.
 *
 * Returns a CheckResult. If the invariant type is unknown or undetectable,
 * returns a NOT_CHECKED result.
 */
export function runInvariantCheck(
  invariant: InvariantDefinition,
  output: string,
  _context?: string,
): CheckResult {
  const base = {
    check_id: invariant.id,
    name: `Invariant: ${invariant.id}`,
    triggered_by: invariant.id,
    enforcement_level: invariant.enforcement,
  };

  if (!invariant.type) {
    // Try custom evaluator registry before giving up
    const evaluator = getEvaluator(invariant.id);
    if (evaluator) {
      try {
        const result = evaluator(_context ?? "", output, {} as Constitution, {
          id: invariant.id,
          rule: invariant.rule,
          enforcement: invariant.enforcement,
        });
        return { ...result, check_impl: "custom_evaluator", replayable: false };
      } catch (err) {
        return {
          ...base,
          passed: true,
          severity: "info",
          evidence: `Custom evaluator error: ${err instanceof Error ? err.message : String(err)}`,
          status: "ERRORED",
          check_impl: "custom_evaluator",
        };
      }
    }

    return {
      ...base,
      passed: false,
      severity: mapEnforcementToSeverity(invariant.enforcement),
      evidence: "Unrecognized invariant type: cannot evaluate rule",
      details: invariant.rule,
      status: "UNKNOWN_TYPE",
    };
  }

  switch (invariant.type) {
    case "regex_match":
      return runRegexMatch(invariant, output, base);
    case "regex_deny":
      return runRegexDeny(invariant, output, base);
    case "max_length":
      return runMaxLength(invariant, output, base);
    case "required_keywords":
      return runRequiredKeywords(invariant, output, base);
    case "pii_detection":
      return runPiiDetection(output, base);
    default: {
      // Try custom evaluator registry before returning UNKNOWN_TYPE
      const evaluator = getEvaluator(invariant.id);
      if (evaluator) {
        try {
          const result = evaluator(_context ?? "", output, {} as Constitution, {
            id: invariant.id,
            rule: invariant.rule,
            enforcement: invariant.enforcement,
            type: invariant.type,
          });
          return { ...result, check_impl: "custom_evaluator", replayable: false };
        } catch (err) {
          return {
            ...base,
            passed: true,
            severity: "info",
            evidence: `Custom evaluator error: ${err instanceof Error ? err.message : String(err)}`,
            status: "ERRORED",
            check_impl: "custom_evaluator",
          };
        }
      }

      return {
        ...base,
        passed: false,
        severity: mapEnforcementToSeverity(invariant.enforcement),
        evidence: "Unrecognized invariant type: cannot evaluate rule",
        details: `Unknown invariant type: ${invariant.type}`,
        status: "UNKNOWN_TYPE",
      };
    }
  }
}

/**
 * Run all invariant checks from a constitution against an output string.
 */
export function runAllInvariantChecks(
  constitution: Constitution,
  output: string,
  context?: string,
): CheckResult[] {
  const definitions = loadInvariantChecks(constitution);
  return definitions.map((def) => runInvariantCheck(def, output, context));
}

// ── Individual invariant runners ─────────────────────────────────────

function runRegexMatch(
  inv: InvariantDefinition,
  output: string,
  base: Record<string, unknown>,
): CheckResult {
  if (!inv.pattern) {
    return { ...base, passed: true, severity: "info", evidence: null, details: "No pattern specified", status: "NOT_CHECKED" } as CheckResult;
  }

  // Reject known-catastrophic patterns (fail-closed)
  if (!isSafeRegex(inv.pattern)) {
    return { ...base, passed: false, severity: mapEnforcementToSeverity(inv.enforcement), evidence: `Unsafe regex pattern rejected (potential ReDoS): /${inv.pattern}/`, details: "Invariant failed due to unsafe regex pattern", status: "UNSAFE_PATTERN" } as CheckResult;
  }

  try {
    const re = new RegExp(inv.pattern);
    const matches = re.test(output);
    return {
      ...base,
      passed: matches,
      severity: matches ? "info" : mapEnforcementToSeverity(inv.enforcement),
      evidence: matches ? null : `Output does not match required pattern: /${inv.pattern}/`,
      details: matches ? "Output matches required pattern" : `Pattern /${inv.pattern}/ not found in output`,
    } as CheckResult;
  } catch {
    return { ...base, passed: false, severity: mapEnforcementToSeverity(inv.enforcement), evidence: `Invalid regex pattern rejected: /${inv.pattern}/`, details: `Invalid regex pattern: ${inv.pattern}`, status: "ERRORED" } as CheckResult;
  }
}

function runRegexDeny(
  inv: InvariantDefinition,
  output: string,
  base: Record<string, unknown>,
): CheckResult {
  if (!inv.pattern) {
    return { ...base, passed: true, severity: "info", evidence: null, details: "No pattern specified", status: "NOT_CHECKED" } as CheckResult;
  }

  // Reject known-catastrophic patterns (fail-closed)
  if (!isSafeRegex(inv.pattern)) {
    return { ...base, passed: false, severity: mapEnforcementToSeverity(inv.enforcement), evidence: `Unsafe regex pattern rejected (potential ReDoS): /${inv.pattern}/`, details: "Invariant failed due to unsafe regex pattern", status: "UNSAFE_PATTERN" } as CheckResult;
  }

  try {
    const re = new RegExp(inv.pattern);
    const matches = re.test(output);
    return {
      ...base,
      passed: !matches,
      severity: !matches ? "info" : mapEnforcementToSeverity(inv.enforcement),
      evidence: matches ? `Output matches forbidden pattern: /${inv.pattern}/` : null,
      details: matches ? `Forbidden pattern /${inv.pattern}/ found in output` : "Output does not contain forbidden pattern",
    } as CheckResult;
  } catch {
    return { ...base, passed: false, severity: mapEnforcementToSeverity(inv.enforcement), evidence: `Invalid regex pattern rejected: /${inv.pattern}/`, details: `Invalid regex pattern: ${inv.pattern}`, status: "ERRORED" } as CheckResult;
  }
}

function runMaxLength(
  inv: InvariantDefinition,
  output: string,
  base: Record<string, unknown>,
): CheckResult {
  if (!inv.maxLength) {
    return { ...base, passed: true, severity: "info", evidence: null, details: "No length limit specified", status: "NOT_CHECKED" } as CheckResult;
  }

  const ruleLower = inv.rule.toLowerCase();
  const isWords = ruleLower.includes("word");
  const actual = isWords ? output.split(/\s+/).length : output.length;
  const unit = isWords ? "words" : "characters";
  const withinLimit = actual <= inv.maxLength;

  return {
    ...base,
    passed: withinLimit,
    severity: withinLimit ? "info" : mapEnforcementToSeverity(inv.enforcement),
    evidence: withinLimit ? null : `Output has ${actual} ${unit}, exceeds limit of ${inv.maxLength}`,
    details: withinLimit ? `Output length (${actual} ${unit}) within limit` : `Output exceeds maximum ${inv.maxLength} ${unit}`,
  } as CheckResult;
}

function runRequiredKeywords(
  inv: InvariantDefinition,
  output: string,
  base: Record<string, unknown>,
): CheckResult {
  if (!inv.keywords || inv.keywords.length === 0) {
    return { ...base, passed: true, severity: "info", evidence: null, details: "No keywords specified", status: "NOT_CHECKED" } as CheckResult;
  }

  const outputLower = output.toLowerCase();
  const missing = inv.keywords.filter((kw) => !outputLower.includes(kw.toLowerCase()));

  if (missing.length > 0) {
    return {
      ...base,
      passed: false,
      severity: mapEnforcementToSeverity(inv.enforcement),
      evidence: `Missing required keywords: ${missing.join(", ")}`,
      details: `${missing.length}/${inv.keywords.length} required keywords not found`,
    } as CheckResult;
  }

  return {
    ...base,
    passed: true,
    severity: "info",
    evidence: null,
    details: `All ${inv.keywords.length} required keywords found`,
  } as CheckResult;
}

function runPiiDetection(
  output: string,
  base: Record<string, unknown>,
): CheckResult {
  const findings: string[] = [];

  if (EMAIL_RE.test(output)) {
    findings.push("email address");
  }
  if (PHONE_RE.test(output)) {
    findings.push("phone number");
  }
  if (SSN_RE.test(output)) {
    findings.push("SSN");
  }

  if (findings.length > 0) {
    return {
      ...base,
      passed: false,
      severity: "critical",
      evidence: `PII detected: ${findings.join(", ")}`,
      details: `Output contains potential PII: ${findings.join(", ")}`,
    } as CheckResult;
  }

  return {
    ...base,
    passed: true,
    severity: "info",
    evidence: null,
    details: "No PII patterns detected",
  } as CheckResult;
}

// ── Helpers ──────────────────────────────────────────────────────────

function mapEnforcementToSeverity(enforcement: string): string {
  switch (enforcement) {
    case "halt": return "critical";
    case "warn": return "medium";
    case "log": return "low";
    default: return "info";
  }
}
