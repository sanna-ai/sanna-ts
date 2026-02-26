import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  loadConstitution,
  createApprovalRequest,
  signApproval,
  loadPrivateKey,
  getKeyId,
} from "@sanna-ai/core";
import type { ApprovalRequest } from "@sanna-ai/core";

export async function runApprove(
  constitutionFile: string,
  options: {
    privateKey: string;
    requester?: string;
    requiredApprovals?: string;
    expiresInHours?: string;
    approvalFile?: string;
  },
): Promise<void> {
  const constitution = loadConstitution(constitutionFile);
  const policyHash = constitution.policy_hash;

  // Verify constitution is Ed25519-signed
  if (!constitution.provenance.signature?.value) {
    console.error("Error: Constitution is not Ed25519-signed. Sign it first with `sanna sign`.");
    process.exitCode = 1;
    return;
  }

  const privateKey = loadPrivateKey(options.privateKey);
  const requester = options.requester ?? "approver@sanna.dev";
  const requiredApprovals = options.requiredApprovals ? parseInt(options.requiredApprovals, 10) : 1;
  const expiresInHours = options.expiresInHours ? parseInt(options.expiresInHours, 10) : 72;

  // Derive approval file path
  const approvalFile = options.approvalFile ?? constitutionFile.replace(/\.(yaml|yml)$/, ".approval.json");

  // Load or create approval request
  let request: ApprovalRequest;
  if (existsSync(approvalFile)) {
    request = JSON.parse(readFileSync(approvalFile, "utf-8")) as ApprovalRequest;
  } else {
    request = createApprovalRequest(policyHash!, requester, {
      required_approvals: requiredApprovals,
      expires_in_hours: expiresInHours,
    });
  }

  // Sign approval
  signApproval(request, privateKey);

  // Persist
  const dir = dirname(approvalFile);
  if (dir) mkdirSync(dir, { recursive: true });
  writeFileSync(approvalFile, JSON.stringify(request, null, 2) + "\n");

  const keyId = getKeyId(privateKey);
  console.log(`Approval signed and saved to ${approvalFile}`);
  console.log();
  console.log(`  Constitution: ${constitutionFile}`);
  console.log(`  Policy hash:  ${(policyHash ?? "").slice(0, 16)}...`);
  console.log(`  Approver:     ${keyId.slice(0, 16)}...`);
  console.log(`  Status:       ${request.status}`);
  console.log(`  Approvals:    ${request.approvals.length}/${request.required_approvals}`);
  console.log(`  Expires:      ${request.expires_at}`);
}

export const approveCommand = new Command("approve")
  .description("Sign a constitution approval")
  .argument("<constitution>", "Path to constitution YAML file")
  .requiredOption("--private-key <path>", "Path to Ed25519 private key")
  .option("--requester <identity>", "Requester identity string", "approver@sanna.dev")
  .option("--required-approvals <n>", "Number of approvals required", "1")
  .option("--expires-in-hours <n>", "Expiry window in hours", "72")
  .option("--approval-file <path>", "Approval JSON output path")
  .action(async (constitution, opts) => {
    await runApprove(constitution, opts);
  });
