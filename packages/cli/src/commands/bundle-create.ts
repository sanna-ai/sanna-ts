import { Command } from "commander";
import { createBundle } from "@sanna-ai/core";

export async function runBundleCreate(options: {
  receipt: string;
  constitution: string;
  publicKey: string;
  output: string;
  description?: string;
}): Promise<void> {
  try {
    const outputPath = createBundle({
      receiptPath: options.receipt,
      constitutionPath: options.constitution,
      publicKeyPath: options.publicKey,
      outputPath: options.output,
      description: options.description,
    });

    console.log(`Evidence bundle created: ${outputPath}`);
    console.log();
    console.log("  Contents:");
    console.log("    receipt.json");
    console.log("    constitution.yaml");
    console.log("    public_keys/{key_id}.pub");
    console.log("    metadata.json");
    console.log();
    console.log(`Verify with: sanna bundle-verify ${options.output}`);
  } catch (e) {
    console.error(`Error: ${(e as Error).message}`);
    process.exitCode = 1;
  }
}

export const bundleCreateCommand = new Command("bundle-create")
  .description("Create a self-contained evidence bundle (zip)")
  .requiredOption("--receipt <path>", "Path to signed receipt JSON")
  .requiredOption("--constitution <path>", "Path to signed constitution YAML")
  .requiredOption("--public-key <path>", "Path to Ed25519 public key")
  .requiredOption("-o, --output <path>", "Output zip path")
  .option("--description <text>", "Bundle description")
  .action(async (opts) => {
    await runBundleCreate(opts);
  });
