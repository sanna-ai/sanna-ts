import { Command } from "commander";
import { verifyBundle } from "@sanna-ai/core";

export async function runBundleVerify(
  bundlePath: string,
  options: { json?: boolean; lenient?: boolean },
): Promise<void> {
  const strict = !options.lenient;

  let result;
  try {
    result = verifyBundle(bundlePath, strict);
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exitCode = 1;
    return;
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
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
  console.log("  VERIFICATION STEPS (7-step):");
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
  .description("Verify a self-contained evidence bundle (7-step)")
  .argument("<bundle>", "Path to evidence bundle zip")
  .option("--json", "Output as JSON")
  .option("--lenient", "Lenient mode (structure + fingerprint checks only)")
  .action(async (bundle, opts) => {
    await runBundleVerify(bundle, opts);
  });
