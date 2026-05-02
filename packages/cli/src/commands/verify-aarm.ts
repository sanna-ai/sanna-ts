import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { glob } from "node:fs/promises";
import { loadPublicKey } from "@sanna-ai/core";
import { aggregateAarmReport, formatAarmReport } from "@sanna-ai/core/aarm";

async function expandFiles(pattern: string): Promise<string[]> {
  if (pattern.includes("*") || pattern.includes("?") || pattern.includes("{")) {
    const files: string[] = [];
    for await (const f of glob(pattern)) {
      files.push(f);
    }
    return files.sort();
  }
  return [pattern];
}

export async function runVerifyAarm(
  filesGlob: string,
  options: {
    format?: string;
    publicKey?: string;
    output?: string;
  },
): Promise<void> {
  const fmt = options.format ?? "human";

  let files: string[];
  try {
    files = await expandFiles(filesGlob);
  } catch (e) {
    console.error(`Error: Failed to expand file pattern: ${(e as Error).message}`);
    process.exitCode = 2;
    return;
  }

  if (!files.length) {
    console.error(`Error: No files matched: ${filesGlob}`);
    process.exitCode = 2;
    return;
  }

  const receipts: Record<string, unknown>[] = [];
  const loadErrors: string[] = [];

  for (const file of files) {
    try {
      const raw = readFileSync(file, "utf-8");
      receipts.push(JSON.parse(raw) as Record<string, unknown>);
    } catch (e) {
      loadErrors.push(`${file}: ${(e as Error).message}`);
    }
  }

  if (loadErrors.length) {
    for (const err of loadErrors) {
      console.error(`Error loading receipt: ${err}`);
    }
    process.exitCode = 2;
    return;
  }

  let publicKey;
  if (options.publicKey) {
    try {
      publicKey = loadPublicKey(options.publicKey);
    } catch (e) {
      console.error(`Error: Failed to load public key: ${(e as Error).message}`);
      process.exitCode = 3;
      return;
    }
  }

  let report;
  try {
    report = aggregateAarmReport(receipts, publicKey);
  } catch (e) {
    console.error(`Error: Internal error during AARM aggregation: ${(e as Error).message}`);
    process.exitCode = 3;
    return;
  }

  let output: string;
  try {
    output = formatAarmReport(report, fmt);
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exitCode = 3;
    return;
  }

  if (options.output) {
    try {
      writeFileSync(options.output, output, "utf-8");
    } catch (e) {
      console.error(`Error: Failed to write output file: ${(e as Error).message}`);
      process.exitCode = 2;
      return;
    }
  } else {
    console.log(output);
  }

  if (report.aggregate_status === "FAIL") {
    process.exitCode = 1;
  }
}

export const verifyAarmCommand = new Command("verify-aarm")
  .description("Verify AARM Core (R1-R6) conformance across a set of receipts")
  .argument("<files-glob>", "Receipt JSON file or glob pattern")
  .option("--format <format>", "Output format: human (default) or json", "human")
  .option("--public-key <path>", "Ed25519 public key for receipt signature verification")
  .option("--output <file>", "Write report to file instead of stdout")
  .action(async (filesGlob: string, opts) => {
    await runVerifyAarm(filesGlob, opts);
  });
