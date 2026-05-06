/**
 * SAN-406: com.sanna.anomaly extension field-level redaction (spec Section 2.22.5).
 *
 * Mirrors the Section 2.14 manifest redaction pattern in manifest.ts but with
 * single-value (not list) semantics. The redacted value substitutes for the
 * attempted_tool / attempted_command / attempted_endpoint field in
 * com.sanna.anomaly extension emissions, per the operator-configured contentMode.
 *
 * contentMode semantics (spec Section 2.22.5 + 2.14):
 * - "full" or undefined/null/empty: emit raw value (current behavior preserved)
 * - "redacted": substitute literal "<redacted>"
 * - "hashes_only": substitute SHA-256 hex (lowercase) of original value via
 *   the canonical hashContent helper (NFC + UTF-8 + SHA-256 + lowercase per
 *   Sanna canonical hashing).
 *
 * Note on "hashes_only" privacy: SHA-256 of short capability names (e.g., "ls",
 * "/api/users") is rainbow-table reversible. The mode is for audit-time
 * deterministic comparison, not privacy. Operators relying on strong privacy
 * MUST use "redacted".
 *
 * Cross-SDK parity with sanna-repo's src/sanna/anomaly.py (SAN-406 PR 1).
 */
import { hashContent } from "./hashing.js";
import type { ContentMode } from "./types.js";

export function redactAttemptedField(value: string, contentMode: ContentMode | string | undefined): string {
  // Treat empty/falsy as raw mode (matches Python helper's defensive permissive
  // behavior). Production paths produce undefined/null or one of the 3 enums;
  // the empty-string sentinel appears in some test stubs.
  if (!contentMode || contentMode === "full") {
    return value;
  }
  if (contentMode === "redacted") {
    return "<redacted>";
  }
  if (contentMode === "hashes_only") {
    return hashContent(value);
  }
  throw new Error(
    `unknown contentMode ${JSON.stringify(contentMode)}; expected one of ` +
    `"full", "redacted", "hashes_only", null, or undefined`
  );
}
