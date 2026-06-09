import { Command } from "commander";
import {
  loadConstitution,
  signConstitution,
  saveConstitution,
  loadPrivateKey,
} from "@sanna-ai/core";

export async function runSign(
  file: string,
  options: { privateKey: string; signedBy?: string; output?: string },
): Promise<void> {
  const constitution = loadConstitution(file);
  const privateKey = loadPrivateKey(options.privateKey);
  const signedBy = options.signedBy ?? `signer@sanna.dev`;

  const signed = signConstitution(constitution, privateKey, signedBy);

  const outputPath = options.output ?? file;
  saveConstitution(signed, outputPath);

  const sig = signed.provenance.signature!;
  console.log(`Signed constitution written to ${outputPath}`);
  console.log();
  console.log(`  Agent:     ${signed.identity.agent_name}`);
  console.log(`  Hash:      ${signed.policy_hash}`);
  console.log(`  Key ID:    ${sig.key_id}`);
  console.log(`  Signed by: ${sig.signed_by}`);
  console.log(`  Scheme:    ${sig.scheme}`);
}

export const signCommand = new Command("sign")
  .description("Sign a constitution with Ed25519")
  .argument("<file>", "Path to constitution YAML file")
  .requiredOption("--private-key <path>", "Path to Ed25519 private key")
  .option("--signed-by <identity>", "Identity of the signer")
  .option("-o, --output <path>", "Output file (default: overwrites input)")
  .action(async (file, opts) => {
    await runSign(file, opts);
  });
