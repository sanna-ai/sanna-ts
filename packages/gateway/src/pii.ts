/**
 * Sanna Gateway — PII Redaction
 *
 * Pattern-based detection and redaction of personally identifiable
 * information in tool inputs and outputs.
 */

// ── Built-in patterns ────────────────────────────────────────────────

export interface PiiPattern {
  name: string;
  regex: RegExp;
  replacement: string;
}

const BUILTIN_PATTERNS: PiiPattern[] = [
  {
    name: "email",
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replacement: "[EMAIL_REDACTED]",
  },
  {
    name: "ssn",
    // SSN: XXX-XX-XXXX (with separators)
    regex: /\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b/g,
    replacement: "[SSN_REDACTED]",
  },
  // Credit card is handled separately via two-pass in redactPII() to avoid ReDoS.
  {
    name: "phone",
    // US/international phone formats
    regex: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    replacement: "[PHONE_REDACTED]",
  },
  {
    name: "ip_address",
    // IPv4 address
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    replacement: "[IP_REDACTED]",
  },
];

// Credit card: two-pass approach to avoid ReDoS from lazy quantifier
// inside bounded repetition. Strip spaces/dashes first, then match
// 13-19 contiguous digits.
const CC_DIGIT_RE = /\b\d{13,19}\b/g;

function redactCreditCards(text: string): { result: string; count: number } {
  // Build a map of digit-only positions to original positions
  // Strategy: find runs of [digit, space, dash] that are 13-19 digits long
  const segments: Array<{ start: number; end: number }> = [];
  let i = 0;
  while (i < text.length) {
    if (/\d/.test(text[i])) {
      // Found start of a potential CC run
      const runStart = i;
      let digitCount = 0;
      let j = i;
      while (j < text.length && /[\d \-]/.test(text[j])) {
        if (/\d/.test(text[j])) digitCount++;
        j++;
      }
      if (digitCount >= 13 && digitCount <= 19) {
        segments.push({ start: runStart, end: j });
      }
      i = j;
    } else {
      i++;
    }
  }

  if (segments.length === 0) return { result: text, count: 0 };

  // Replace from end to preserve indices
  let result = text;
  for (let k = segments.length - 1; k >= 0; k--) {
    result =
      result.slice(0, segments[k].start) +
      "[CC_REDACTED]" +
      result.slice(segments[k].end);
  }
  return { result, count: segments.length };
}

// ── Redaction results ────────────────────────────────────────────────

export interface RedactionResult {
  redacted: string;
  redaction_count: number;
  redacted_types: string[];
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Redact PII from a text string.
 *
 * Applies built-in patterns plus any custom patterns provided.
 * Returns the redacted text along with counts and types of redactions.
 */
export function redactPII(
  text: string,
  customPatterns?: PiiPattern[],
): RedactionResult {
  let result = text;
  let totalCount = 0;
  const typesFound = new Set<string>();

  // Credit card: two-pass (strip separators, match digit runs)
  const ccResult = redactCreditCards(result);
  if (ccResult.count > 0) {
    result = ccResult.result;
    totalCount += ccResult.count;
    typesFound.add("credit_card");
  }

  // Other built-in patterns + custom
  const patterns = [...BUILTIN_PATTERNS, ...(customPatterns ?? [])];
  for (const pattern of patterns) {
    // Reset regex state for global patterns
    pattern.regex.lastIndex = 0;
    const matches = result.match(pattern.regex);
    if (matches && matches.length > 0) {
      totalCount += matches.length;
      typesFound.add(pattern.name);
      result = result.replace(pattern.regex, pattern.replacement);
    }
  }

  return {
    redacted: result,
    redaction_count: totalCount,
    redacted_types: [...typesFound],
  };
}

/**
 * Recursively redact all string values in an object.
 *
 * Returns a deep copy with all string values redacted.
 * Stops recursing at maxDepth (default 20) to prevent stack overflow.
 */
export function redactInObject(
  obj: unknown,
  customPatterns?: PiiPattern[],
  maxDepth = 20,
): unknown {
  return _redactRecursive(obj, customPatterns, maxDepth, 0);
}

function _redactRecursive(
  obj: unknown,
  customPatterns: PiiPattern[] | undefined,
  maxDepth: number,
  currentDepth: number,
): unknown {
  if (typeof obj === "string") {
    return redactPII(obj, customPatterns).redacted;
  }
  if (currentDepth >= maxDepth) {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) =>
      _redactRecursive(item, customPatterns, maxDepth, currentDepth + 1),
    );
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = _redactRecursive(
        value,
        customPatterns,
        maxDepth,
        currentDepth + 1,
      );
    }
    return result;
  }
  return obj;
}
