import { Command } from "commander";
import { readFileSync } from "node:fs";
import { verifyBundle } from "@sanna-ai/core";

const KEY_ID_RE = /^[0-9a-f]{64}$/;

function loadTrustedKeyIds(path: string): Set<string> {
  const text = readFileSync(path, "utf-8");
  const keys = new Set<string>();
  const lines = text.split("\n");
  lines.forEach((raw, idx) => {
    const lineno = idx + 1;
    const line = raw.split("#", 1)[0].trim().toLowerCase();
    if (!line) return;
    if (!KEY_ID_RE.test(line)) {
      const preview = line.slice(0, 32);
      throw new Error(`${path}:${lineno}: not a 64-hex key_id: '${preview}'`);
    }
    keys.add(line);
  });
  if (keys.size === 0) {
    throw new Error(`${path}: trust anchor file is empty after stripping comments/blanks`);
  }
  return keys;
}

export async function runBundleVerify(
  bundlePath: string,
  options: { json?: boolean; lenient?: boolean; trustedKeyIds?: string },
): Promise<void> {
  const strict = !options.lenient;

  // Resolve trust anchor source: --trusted-key-ids flag first, then env var.
  // Note: do NOT log the resolved path. CodeQL clear-text-logging heuristic
  // matches values flowing from options.trustedKeyIds / SANNA_TRUSTED_KEY_IDS
  // due to variable-name pattern; count-only log avoids the finding.
  let trustedKeyIds: Set<string> | null = null;
  const anchorPath = options.trustedKeyIds ?? process.env.SANNA_TRUSTED_KEY_IDS;
  if (anchorPath) {
    try {
      trustedKeyIds = loadTrustedKeyIds(anchorPath);
    } catch (e) {
      console.error(`Error: ${(e as Error).message}`);
      process.exitCode = 1;
      return;
    }
    // Count-only log; no path (CodeQL hygiene -- see comment above).
    console.error(`Loaded trust anchor: ${trustedKeyIds.size} key_id(s)`);
  }

  let result;
  try {
    result = verifyBundle(bundlePath, strict, trustedKeyIds);
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exitCode = 1;
    return;
  }

  // Stderr warning banner when no anchor + non-JSON output (parity with Python SDK).
  if (!result.trust_anchored && !options.json) {
    console.error(
      "\n" +
      "============================================================\n" +
      "WARNING: BUNDLE VERIFIED SELF-CONSISTENTLY ONLY\n" +
      "------------------------------------------------------------\n" +
      "No trust anchor was supplied. The bundle internally agrees\n" +
      "but no external authority confirms the key_id belongs to who\n" +
      "the receipt claims it does. An attacker who re-signs a forged\n" +
      "bundle with their own key would still pass this check.\n" +
      "Supply --trusted-key-ids <FILE> or SANNA_TRUSTED_KEY_IDS env\n" +
      "var for an authoritative verdict.\n" +
      "============================================================\n",
    );
  }

  if (options.json) {
    const output = {
      valid: result.valid,
      trust_anchored: result.trust_anchored,
      checks: result.checks,
      receipt_summary: result.receipt_summary,
      errors: result.errors,
    };
    console.log(JSON.stringify(output, null, 2));
    if (!result.valid) process.exitCode = 1;
    return;
  }

  // Formatted output
  const verdict = result.valid ? "VALID" : "INVALID";
  const mode = strict ? "strict" : "lenient";

  console.log("=== EVIDENCE BUNDLE VERIFICATION ===");
  console.log();
  console.log(`  Bundle:   ${bundlePath}`);
  console.log(`  Mode:     ${mode}`);
  console.log(`  Verdict:  ${verdict}`);

  if (result.receipt_summary) {
    const rs = result.receipt_summary;
    console.log();
    console.log("  Receipt:");
    if (rs.agent_name) console.log(`    Agent:          ${rs.agent_name}`);
    if (rs.status) console.log(`    Status:         ${rs.status}`);
    if (rs.correlation_id) console.log(`    Correlation ID: ${rs.correlation_id}`);
  }

  console.log();
  console.log("  VERIFICATION STEPS (8-step):");
  for (const check of result.checks) {
    const prefix = check.passed ? "[PASS]" : "[FAIL]";
    console.log(`    ${prefix} ${check.name}: ${check.detail}`);
  }

  if (result.errors.length > 0) {
    console.log();
    console.log("  Errors:");
    for (const err of result.errors) {
      console.log(`    - ${err}`);
    }
  }

  if (!result.valid) process.exitCode = 1;
}

export const bundleVerifyCommand = new Command("bundle-verify")
  .description("Verify a self-contained evidence bundle (8-step)")
  .argument("<bundle>", "Path to evidence bundle zip")
  .option("--json", "Output as JSON")
  .option("--lenient", "Lenient mode (structure + fingerprint checks only)")
  .option(
    "--trusted-key-ids <FILE>",
    "Path to file of trusted Ed25519 key_ids (64-hex per line, '#' comments). " +
    "Without this flag (or SANNA_TRUSTED_KEY_IDS env var), verification is self-consistent only.",
  )
  .action(async (bundle, opts) => {
    await runBundleVerify(bundle, opts);
  });
