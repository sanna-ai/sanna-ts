import { Command } from "commander";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  generateReceipt,
  signReceipt,
  loadPrivateKey,
} from "@sanna-ai/core";
import type { CheckResult } from "@sanna-ai/core";

export async function runGenerate(
  traceFile: string,
  options: { signingKey?: string; signedBy?: string; output?: string },
): Promise<void> {
  let trace: Record<string, unknown>;
  try {
    trace = JSON.parse(readFileSync(traceFile, "utf-8")) as Record<string, unknown>;
  } catch (e) {
    console.error(`Error reading trace file: ${(e as Error).message}`);
    process.exitCode = 1;
    return;
  }

  if (!trace.inputs || typeof trace.inputs !== "object") {
    console.error("Error: Trace file must contain an 'inputs' object.");
    process.exitCode = 1;
    return;
  }
  if (!trace.outputs || typeof trace.outputs !== "object") {
    console.error("Error: Trace file must contain an 'outputs' object.");
    process.exitCode = 1;
    return;
  }

  const checks = (trace.checks ?? []) as Record<string, unknown>[];
  const correlationId = (trace.correlation_id as string) ?? `sanna-cli-${Date.now()}`;

  const receipt = generateReceipt({
    correlation_id: correlationId,
    inputs: trace.inputs as Record<string, unknown>,
    outputs: trace.outputs as Record<string, unknown>,
    checks: checks as CheckResult[],
    status: trace.status as string | undefined,
    constitution_ref: trace.constitution_ref as Record<string, unknown> | undefined,
    enforcement: trace.enforcement as Record<string, unknown> | undefined,
    extensions: trace.extensions as Record<string, unknown> | undefined,
    enforcementSurface: "middleware",
    invariantsScope: "full",
  });

  if (options.signingKey) {
    const privateKey = loadPrivateKey(options.signingKey);
    const signedBy = options.signedBy ?? "sanna-cli";
    signReceipt(receipt as unknown as Record<string, unknown>, privateKey, signedBy);
  }

  if (options.output) {
    const dir = dirname(options.output);
    if (dir) mkdirSync(dir, { recursive: true });
    writeFileSync(options.output, JSON.stringify(receipt, null, 2) + "\n");
    console.log(`Receipt written to ${options.output}`);
    console.log();
    console.log(`  Receipt ID:    ${receipt.receipt_id}`);
    console.log(`  Fingerprint:   ${receipt.receipt_fingerprint}`);
    console.log(`  Status:        ${receipt.status}`);
    if (options.signingKey) {
      console.log(`  Signed:        yes`);
    }
  } else {
    console.log(JSON.stringify(receipt, null, 2));
  }
}

export const generateCommand = new Command("generate")
  .description("Generate a receipt from trace data")
  .argument("<trace-file>", "Path to trace data JSON file")
  .option("--signing-key <path>", "Ed25519 private key for signing")
  .option("--signed-by <id>", "Signer identity", "sanna-cli")
  .option("-o, --output <path>", "Output file (default: stdout)")
  .action(async (traceFile, opts) => {
    await runGenerate(traceFile, opts);
  });
