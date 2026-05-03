/**
 * SAN-358: Verifier assertions for session_manifest + invocation_anomaly receipts.
 *
 * Mirror of Python src/sanna/verify_manifest.py (sanna-repo PR #46).
 * Every Check.message string matches Python character-for-character.
 */

import { VALID_SUPPRESSION_REASONS, SUPPRESSION_REASON_UNKNOWN } from "./manifest.js";
import type { Check } from "./types.js";

const ANOMALY_CAPABILITY_FIELD: Record<string, string> = {
  invocation_anomaly: "attempted_tool",
  cli_invocation_anomaly: "attempted_command",
  api_invocation_anomaly: "attempted_endpoint",
};

const ANOMALY_SURFACE_NAME: Record<string, string> = {
  invocation_anomaly: "mcp",
  cli_invocation_anomaly: "cli",
  api_invocation_anomaly: "http",
};

const VALID_MANIFEST_ENFORCEMENT_SURFACES = new Set([
  "gateway", "cli_interceptor", "http_interceptor", "mixed",
]);

export const VALID_ANOMALY_EVENT_TYPES = new Set([
  "invocation_anomaly", "cli_invocation_anomaly", "api_invocation_anomaly",
]);

const CROSS_RECEIPT_SKIP_MSG =
  "Cross-receipt parent resolution requires receipt set; use verify_receipt_set";

// -- Helper: Check 8 --

function checkConstitutionRef(receipt: Record<string, unknown>): Check[] {
  const constitutionRef = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (constitutionRef && typeof constitutionRef === "object") {
    const policyHash = constitutionRef.policy_hash;
    if (policyHash && typeof policyHash === "string") {
      return [{
        name: "manifest_constitution_ref_present",
        status: "PASS",
        message: "constitution_ref.policy_hash present",
      }];
    }
  }
  return [{
    name: "manifest_constitution_ref_present",
    status: "FAIL",
    message: (
      "session_manifest receipt requires constitution_ref.policy_hash " +
      "(manifest is meaningless without constitution binding)"
    ),
  }];
}

// -- Helper: Check 9 --

function checkEnforcementSurface(
  receipt: Record<string, unknown>,
  surfaces: Record<string, unknown>,
): Check[] {
  const enforcementSurface = receipt.enforcement_surface as string | undefined;
  if (enforcementSurface === undefined || enforcementSurface === null) {
    return [];
  }

  if (!VALID_MANIFEST_ENFORCEMENT_SURFACES.has(enforcementSurface)) {
    return [{
      name: "manifest_enforcement_surface_consistent",
      status: "FAIL",
      message: (
        `session_manifest enforcement_surface '${enforcementSurface}' ` +
        "not in valid set {gateway, cli_interceptor, http_interceptor, mixed}"
      ),
    }];
  }

  const surfaceCount = typeof surfaces === "object" && surfaces !== null
    ? Object.keys(surfaces).length
    : 0;

  if (enforcementSurface === "mixed") {
    if (surfaceCount < 2) {
      return [{
        name: "manifest_enforcement_surface_consistent",
        status: "FAIL",
        message: (
          `session_manifest with enforcement_surface='mixed' requires ` +
          `surfaces dict with at least 2 entries; got ${surfaceCount}`
        ),
      }];
    }
  } else if (enforcementSurface === "gateway") {
    if (typeof surfaces === "object" && surfaces !== null && !("mcp" in surfaces)) {
      return [{
        name: "manifest_enforcement_surface_consistent",
        status: "FAIL",
        message: "session_manifest with enforcement_surface='gateway' missing 'mcp' surface",
      }];
    }
  } else if (enforcementSurface === "cli_interceptor") {
    if (typeof surfaces === "object" && surfaces !== null && !("cli" in surfaces)) {
      return [{
        name: "manifest_enforcement_surface_consistent",
        status: "FAIL",
        message: "session_manifest with enforcement_surface='cli_interceptor' missing 'cli' surface",
      }];
    }
  } else if (enforcementSurface === "http_interceptor") {
    if (typeof surfaces === "object" && surfaces !== null && !("http" in surfaces)) {
      return [{
        name: "manifest_enforcement_surface_consistent",
        status: "FAIL",
        message: "session_manifest with enforcement_surface='http_interceptor' missing 'http' surface",
      }];
    }
  }

  return [{
    name: "manifest_enforcement_surface_consistent",
    status: "PASS",
    message: `enforcement_surface='${enforcementSurface}' is consistent with surfaces`,
  }];
}

// -- Public: 9 checks for session_manifest receipts --

export function verifySessionManifestReceipt(receipt: Record<string, unknown>): Check[] {
  const checks: Check[] = [];
  const ext = (receipt.extensions ?? {}) as Record<string, unknown>;
  const manifest = ext["com.sanna.manifest"] as Record<string, unknown> | undefined;
  const contentMode = receipt.content_mode as string | undefined;

  // Check 1: manifest_extension_present
  if (!manifest || typeof manifest !== "object") {
    checks.push({
      name: "manifest_extension_present",
      status: "FAIL",
      message: "session_manifest receipt missing required extension 'com.sanna.manifest'",
    });
    checks.push(...checkConstitutionRef(receipt));
    checks.push(...checkEnforcementSurface(receipt, {}));
    return checks;
  }

  checks.push({
    name: "manifest_extension_present",
    status: "PASS",
    message: "extension 'com.sanna.manifest' present",
  });

  // Check 2: manifest_version_supported
  // undefined -> "None" to match Python's None string representation byte-for-byte.
  const actualVersion = manifest.version;
  const versionStr = actualVersion === undefined ? "None" : String(actualVersion);
  if (actualVersion !== "0.1") {
    checks.push({
      name: "manifest_version_supported",
      status: "FAIL",
      message: `manifest version '${versionStr}' not in supported set {'0.1'}`,
    });
  } else {
    checks.push({
      name: "manifest_version_supported",
      status: "PASS",
      message: `manifest version '${versionStr}' is supported`,
    });
  }

  // Check 3: manifest_has_at_least_one_surface
  const surfaces = manifest.surfaces as Record<string, unknown> | undefined;
  if (!surfaces || typeof surfaces !== "object" || Object.keys(surfaces).length < 1) {
    checks.push({
      name: "manifest_has_at_least_one_surface",
      status: "FAIL",
      message: "manifest 'surfaces' must contain at least one of {'mcp', 'cli', 'http'}",
    });
    checks.push(...checkConstitutionRef(receipt));
    checks.push(...checkEnforcementSurface(receipt, {}));
    return checks;
  }

  const sortedSurfaceKeys = [...Object.keys(surfaces)].sort();
  checks.push({
    name: "manifest_has_at_least_one_surface",
    status: "PASS",
    message: `manifest surfaces present: [${sortedSurfaceKeys.map((k) => `'${k}'`).join(", ")}]`,
  });

  // Checks 4, 5, 6, 7: per-surface
  const sortFails: Check[] = [];
  const reasonIssues: Check[] = [];
  const overlapFails: Check[] = [];
  const keyMismatchFails: Check[] = [];

  for (const [surfaceName, surfaceData] of Object.entries(surfaces)) {
    if (!surfaceData || typeof surfaceData !== "object") continue;
    const sd = surfaceData as Record<string, unknown>;

    const isMcp = surfaceName === "mcp";
    const deliveredField = isMcp ? "tools_delivered" : "patterns_delivered";
    const suppressedField = isMcp ? "tools_suppressed" : "patterns_suppressed";

    const delivered = (sd[deliveredField] as string[] | undefined) ?? [];
    const suppressed = (sd[suppressedField] as string[] | undefined) ?? [];
    const suppressionReasons = sd.suppression_reasons as Record<string, string> | undefined;

    // Check 4: manifest_lists_sorted
    for (const [fieldName, lst] of [[deliveredField, delivered], [suppressedField, suppressed]] as [string, string[]][]) {
      if (Array.isArray(lst) && JSON.stringify(lst) !== JSON.stringify([...lst].sort())) {
        sortFails.push({
          name: "manifest_lists_sorted",
          status: "FAIL",
          message: (
            `manifest surface '${surfaceName}' field '${fieldName}' ` +
            "is not sorted alphabetically (determinism violated)"
          ),
        });
      }
    }

    // Check 5: manifest_suppression_reasons_in_enum
    if (suppressionReasons && typeof suppressionReasons === "object") {
      for (const [, value] of Object.entries(suppressionReasons)) {
        if (!VALID_SUPPRESSION_REASONS.has(value)) {
          reasonIssues.push({
            name: "manifest_suppression_reasons_in_enum",
            status: "FAIL",
            message: (
              `manifest surface '${surfaceName}' suppression_reason ` +
              `'${value}' not in stable enum (Section 2.21)`
            ),
          });
        } else if (value === SUPPRESSION_REASON_UNKNOWN) {
          reasonIssues.push({
            name: "manifest_suppression_reasons_in_enum",
            status: "WARN",
            message: (
              `manifest surface '${surfaceName}' uses 'unknown' ` +
              "suppression_reason (documented fallback per Section 2.21)"
            ),
          });
        }
      }
    }

    // Check 6: manifest_no_overlap_delivered_suppressed
    if (contentMode !== "redacted" && Array.isArray(delivered) && Array.isArray(suppressed)) {
      const deliveredSet = new Set(delivered);
      const suppressedSet = new Set(suppressed);
      const overlap = [...deliveredSet].filter((n) => suppressedSet.has(n)).sort();
      for (const name of overlap) {
        overlapFails.push({
          name: "manifest_no_overlap_delivered_suppressed",
          status: "FAIL",
          message: (
            `manifest surface '${surfaceName}' has '${name}' in BOTH ` +
            "delivered and suppressed (anti-enumeration integrity violated)"
          ),
        });
      }
    }

    // Check 7: manifest_suppression_reasons_keys_match
    if (suppressionReasons && typeof suppressionReasons === "object" && Array.isArray(suppressed)) {
      const reasonKeys = new Set(Object.keys(suppressionReasons));
      const suppressedNames = new Set(suppressed);
      if (
        reasonKeys.size !== suppressedNames.size ||
        ![...reasonKeys].every((k) => suppressedNames.has(k))
      ) {
        const sortedReasonKeys = [...reasonKeys].sort();
        const sortedSuppressedNames = [...suppressedNames].sort();
        keyMismatchFails.push({
          name: "manifest_suppression_reasons_keys_match",
          status: "FAIL",
          message: (
            `manifest surface '${surfaceName}' suppression_reasons keys ` +
            `[${sortedReasonKeys.map((k) => `'${k}'`).join(", ")}] do not match suppressed names ` +
            `[${sortedSuppressedNames.map((k) => `'${k}'`).join(", ")}]`
          ),
        });
      }
    }
  }

  checks.push(...(sortFails.length > 0 ? sortFails : [{
    name: "manifest_lists_sorted",
    status: "PASS" as const,
    message: "all surface lists are sorted alphabetically",
  }]));

  checks.push(...(reasonIssues.length > 0 ? reasonIssues : [{
    name: "manifest_suppression_reasons_in_enum",
    status: "PASS" as const,
    message: "all suppression_reasons are in the stable enum",
  }]));

  checks.push(...(overlapFails.length > 0 ? overlapFails : [{
    name: "manifest_no_overlap_delivered_suppressed",
    status: "PASS" as const,
    message: "no overlap between delivered and suppressed",
  }]));

  checks.push(...(keyMismatchFails.length > 0 ? keyMismatchFails : [{
    name: "manifest_suppression_reasons_keys_match",
    status: "PASS" as const,
    message: "suppression_reasons keys match suppressed names",
  }]));

  // Check 8: manifest_constitution_ref_present
  checks.push(...checkConstitutionRef(receipt));

  // Check 9: manifest_enforcement_surface_consistent
  checks.push(...checkEnforcementSurface(receipt, surfaces));

  return checks;
}

// -- Public: 3 checks for invocation_anomaly receipts --

export function verifyInvocationAnomalyReceipt(
  receipt: Record<string, unknown>,
  receiptSet: Record<string, unknown>[] | null,
): Check[] {
  const checks: Check[] = [];
  const eventType = (receipt.event_type as string | undefined) ?? "";

  // Check 10: anomaly_event_type_in_valid_set
  if (!VALID_ANOMALY_EVENT_TYPES.has(eventType)) {
    checks.push({
      name: "anomaly_event_type_in_valid_set",
      status: "FAIL",
      message: `anomaly receipt event_type '${eventType}' not in valid set`,
    });
    return checks;
  }

  checks.push({
    name: "anomaly_event_type_in_valid_set",
    status: "PASS",
    message: `event_type '${eventType}' is in valid set`,
  });

  // Checks 11 and 12 require a receipt set
  if (receiptSet === null) {
    checks.push({
      name: "anomaly_parent_receipts_resolves_to_session_manifest",
      status: "WARN",
      message: CROSS_RECEIPT_SKIP_MSG,
    });
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "WARN",
      message: CROSS_RECEIPT_SKIP_MSG,
    });
    return checks;
  }

  // Check 11: anomaly_parent_receipts_resolves_to_session_manifest
  const parentReceipts = (receipt.parent_receipts as string[] | undefined) ?? [];

  if (!parentReceipts.length) {
    checks.push({
      name: "anomaly_parent_receipts_resolves_to_session_manifest",
      status: "FAIL",
      message: (
        "anomaly receipt requires non-empty parent_receipts containing " +
        "the active session_manifest's full_fingerprint (spec Section 2.12)"
      ),
    });
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "WARN",
      message: CROSS_RECEIPT_SKIP_MSG,
    });
    return checks;
  }

  const fpIndex: Record<string, Record<string, unknown>> = {};
  for (const r of receiptSet) {
    const fp = r.full_fingerprint as string | undefined;
    if (fp) fpIndex[fp] = r;
  }

  let parentManifest: Record<string, unknown> | null = null;
  for (const fp of parentReceipts) {
    const candidate = fpIndex[fp];
    if (candidate && candidate.event_type === "session_manifest") {
      parentManifest = candidate;
      break;
    }
  }

  if (parentManifest === null) {
    const parentReceiptsPyRepr = `[${parentReceipts.map((p) => `'${p}'`).join(", ")}]`;
    checks.push({
      name: "anomaly_parent_receipts_resolves_to_session_manifest",
      status: "FAIL",
      message: (
        `anomaly receipt parent_receipts ${parentReceiptsPyRepr} do not resolve ` +
        "to a session_manifest in the provided receipt set"
      ),
    });
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "WARN",
      message: CROSS_RECEIPT_SKIP_MSG,
    });
    return checks;
  }

  checks.push({
    name: "anomaly_parent_receipts_resolves_to_session_manifest",
    status: "PASS",
    message: "anomaly receipt parent_receipts resolves to a session_manifest in the receipt set",
  });

  // Check 12: anomaly_attempted_capability_in_parent_suppressed_or_absent
  const capabilityField = ANOMALY_CAPABILITY_FIELD[eventType];
  const surfaceName = ANOMALY_SURFACE_NAME[eventType];

  const anomalyExt = ((receipt.extensions ?? {}) as Record<string, unknown>)["com.sanna.anomaly"] as Record<string, unknown> | undefined ?? {};
  const capabilityName = anomalyExt[capabilityField] as string | undefined;

  if (capabilityName === undefined || capabilityName === null) {
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "WARN",
      message: (
        `anomaly receipt missing '${capabilityField}' in ` +
        "extensions['com.sanna.anomaly']; cannot verify capability " +
        "against parent manifest"
      ),
    });
    return checks;
  }

  const parentManifestExt = ((parentManifest.extensions ?? {}) as Record<string, unknown>)["com.sanna.manifest"] as Record<string, unknown> | undefined ?? {};
  const parentSurfaces = (parentManifestExt.surfaces ?? {}) as Record<string, unknown>;
  const parentSurface = (parentSurfaces[surfaceName] ?? {}) as Record<string, unknown>;

  const isMcp = surfaceName === "mcp";
  const suppressedField = isMcp ? "tools_suppressed" : "patterns_suppressed";
  const deliveredField = isMcp ? "tools_delivered" : "patterns_delivered";

  const suppressed = new Set((parentSurface[suppressedField] as string[] | undefined) ?? []);
  const delivered = new Set((parentSurface[deliveredField] as string[] | undefined) ?? []);

  if (suppressed.has(capabilityName)) {
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "PASS",
      message: (
        `anomaly capability '${capabilityName}' was suppressed in parent ` +
        "session_manifest (spec-conformant anti-enumeration signal)"
      ),
    });
  } else if (delivered.has(capabilityName)) {
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "FAIL",
      message: (
        `anomaly receipt for capability '${capabilityName}' that parent ` +
        "session_manifest declares as DELIVERED -- inconsistent receipt set"
      ),
    });
  } else {
    checks.push({
      name: "anomaly_attempted_capability_in_parent_suppressed_or_absent",
      status: "PASS",
      message: (
        `anomaly capability '${capabilityName}' was not declared in ` +
        "constitution at all (verifier cannot disambiguate from " +
        "policy-suppression on the wire; this is an informational note, " +
        "not a violation)"
      ),
    });
  }

  return checks;
}
