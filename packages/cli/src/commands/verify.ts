import { Command } from "commander";
import { readFileSync } from "node:fs";
import {
  verifyReceipt,
  loadPublicKey,
  loadConstitution,
  verifyConstitutionSignature,
  verifyApproval,
  getKeyId,
} from "@sanna-ai/core";
import type { ApprovalRequest } from "@sanna-ai/core";
import type { KeyObject } from "node:crypto";

interface VerifyResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  checks_performed: string[];
  constitution_valid: boolean | null;
  approval_valid: boolean | null;
}

export async function runVerify(
  file: string,
  options: {
    publicKey?: string;
    constitution?: string;
    constitutionPublicKey?: string;
    approverPublicKey?: string;
    strict?: boolean;
    format?: string;
  },
): Promise<void> {
  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(readFileSync(file, "utf-8")) as Record<string, unknown>;
  } catch (e) {
    console.error(`Error: Invalid JSON in receipt: ${e}`);
    process.exitCode = 1;
    return;
  }

  const result: VerifyResult = {
    valid: true,
    errors: [],
    warnings: [],
    checks_performed: [],
    constitution_valid: null,
    approval_valid: null,
  };

  // ── Stage 1: Receipt verification ──────────────────────────────────
  const publicKey = options.publicKey ? loadPublicKey(options.publicKey) : undefined;
  const receiptResult = verifyReceipt(receipt, publicKey);

  result.checks_performed.push(...receiptResult.checks_performed);
  result.errors.push(...receiptResult.errors);
  result.warnings.push(...receiptResult.warnings);
  if (!receiptResult.valid) result.valid = false;

  // ── Stage 2: Strict mode enforcement ───────────────────────────────
  if (options.strict) {
    if (!options.publicKey) {
      result.errors.push("Strict mode: --public-key is required");
      result.valid = false;
    }
    if (!receipt.receipt_signature) {
      result.errors.push("Strict mode: receipt is not signed");
      result.valid = false;
    }
  }

  // ── Stage 3: Constitution chain verification ───────────────────────
  if (options.constitution) {
    result.checks_performed.push("constitution_chain");

    try {
      const constitution = loadConstitution(options.constitution);

      // Verify constitution signature if key provided
      if (options.constitutionPublicKey) {
        const constPubKey = loadPublicKey(options.constitutionPublicKey);
        const sigValid = verifyConstitutionSignature(constitution, constPubKey);
        if (sigValid) {
          result.constitution_valid = true;
        } else {
          result.errors.push("Constitution signature verification failed");
          result.constitution_valid = false;
          result.valid = false;
        }
      } else if (constitution.provenance.signature?.value) {
        result.warnings.push("Constitution is signed but no --constitution-public-key provided for verification");
        result.constitution_valid = null;
      }

      // Verify policy_hash binding
      const constRef = receipt.constitution_ref as Record<string, unknown> | undefined;
      if (constRef?.policy_hash && constitution.policy_hash) {
        if (constRef.policy_hash !== constitution.policy_hash) {
          result.errors.push(
            `Policy hash mismatch: receipt has ${String(constRef.policy_hash).slice(0, 16)}..., ` +
            `constitution has ${constitution.policy_hash.slice(0, 16)}...`,
          );
          result.valid = false;
        }
      } else if (!constRef?.policy_hash) {
        result.warnings.push("Receipt has no constitution_ref.policy_hash to verify against");
      }
    } catch (e) {
      result.errors.push(`Failed to load constitution: ${(e as Error).message}`);
      result.constitution_valid = false;
      result.valid = false;
    }
  }

  // ── Stage 4: Approval chain verification ───────────────────────────
  if (options.approverPublicKey) {
    result.checks_performed.push("approval_chain");

    const constRef = receipt.constitution_ref as Record<string, unknown> | undefined;
    const approvalBlock = constRef?.constitution_approval as Record<string, unknown> | undefined;

    if (approvalBlock && approvalBlock.approvals) {
      try {
        const approverPubKey = loadPublicKey(options.approverPublicKey);
        const approverKeyId = getKeyId(approverPubKey);
        const keyMap = new Map<string, KeyObject>();
        keyMap.set(approverKeyId, approverPubKey);

        const approvalResult = verifyApproval(approvalBlock as ApprovalRequest, keyMap);
        if (approvalResult.valid) {
          result.approval_valid = true;
        } else {
          result.errors.push("Approval signature verification failed");
          result.approval_valid = false;
          result.valid = false;
        }
      } catch (e) {
        result.errors.push(`Approval verification error: ${(e as Error).message}`);
        result.approval_valid = false;
        result.valid = false;
      }
    } else {
      result.warnings.push("Receipt has no constitution_approval block to verify");
      result.approval_valid = null;
    }
  }

  // ── Output ─────────────────────────────────────────────────────────
  if (options.format === "json") {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printSummary(receipt, result);
  }

  if (!result.valid) {
    process.exitCode = 1;
  }
}

function printSummary(receipt: Record<string, unknown>, result: VerifyResult): void {
  console.log("=".repeat(50));
  console.log("SANNA RECEIPT VERIFICATION");
  console.log("=".repeat(50));
  console.log();
  console.log(`  Status:      ${result.valid ? "VALID" : "INVALID"}`);
  console.log(`  Checks run:  ${result.checks_performed.join(", ")}`);

  // Chain status
  if (result.constitution_valid !== null) {
    console.log(`  Constitution: ${result.constitution_valid ? "VALID" : "INVALID"}`);
  }
  if (result.approval_valid !== null) {
    console.log(`  Approval:     ${result.approval_valid ? "VALID" : "INVALID"}`);
  }
  console.log();

  if (result.errors.length > 0) {
    console.log("Errors:");
    for (const err of result.errors) {
      console.log(`  [FAIL] ${err}`);
    }
    console.log();
  }

  if (result.warnings.length > 0) {
    console.log("Warnings:");
    for (const warn of result.warnings) {
      console.log(`  [WARN] ${warn}`);
    }
    console.log();
  }

  // SAN-214 Change C: Legacy receipt walkthrough.
  const cvStrForWalkthrough = String(receipt.checks_version ?? "");
  const cvIntForWalkthrough = parseInt(cvStrForWalkthrough, 10);
  const enforcementForWalkthrough = receipt.enforcement as
    Record<string, unknown> | undefined;
  const enforcementActionForWalkthrough = enforcementForWalkthrough?.action as
    string | undefined;

  const hasStatusMismatch = result.errors.some(
    (e) => e.startsWith("Status mismatch"),
  );

  if (
    hasStatusMismatch &&
    enforcementActionForWalkthrough &&
    !isNaN(cvIntForWalkthrough) &&
    cvIntForWalkthrough < 8
  ) {
    const recordedStatus = String(receipt.status ?? "");
    console.log("-".repeat(50));
    console.log("LEGACY RECEIPT NOTE");
    console.log("-".repeat(50));
    console.log();
    console.log(
      "This receipt predates the Sprint 15 integrity fix " +
      "(v1.3 / checks_version 8).",
    );
    console.log();
    console.log(
      `The contradiction — enforcement.action='${enforcementActionForWalkthrough}' ` +
      `with status='${recordedStatus}' — indicates that the ` +
      `interceptor surface reported halt or escalate but the receipt ` +
      `claims full checks passed. This is the defect that SAN-213 ` +
      `fixed at emission time and SAN-214 fixed at verification time.`,
    );
    console.log();
    console.log(
      "Re-generate this receipt with SDK >=1.3 to produce a v1.3 " +
      "receipt with consistent status and enforcement.action.",
    );
    console.log();
  }

  // Governance checks
  const checks = (receipt.checks ?? []) as Record<string, unknown>[];
  if (checks.length > 0) {
    console.log("-".repeat(50));
    console.log("GOVERNANCE CHECKS");
    console.log("-".repeat(50));
    for (const check of checks) {
      const icon = check.passed ? "PASS" : "FAIL";
      console.log(`  [${icon}] ${check.check_id}: ${check.name ?? ""}`);
      if (!check.passed && check.evidence) {
        console.log(`         evidence: ${check.evidence}`);
      }
    }
    console.log();
  }

  console.log("=".repeat(50));
}

export const verifyCommand = new Command("verify")
  .description("Verify receipt integrity, signature, and provenance chain")
  .argument("<file>", "Path to receipt JSON file")
  .option("--public-key <path>", "Ed25519 public key for receipt signature")
  .option("--constitution <path>", "Constitution YAML for chain verification")
  .option("--constitution-public-key <path>", "Ed25519 public key for constitution signature")
  .option("--approver-public-key <path>", "Ed25519 public key for approval signature")
  .option("--strict", "Require receipt signature (fail if unsigned or no key)")
  .option("--format <format>", "Output format: summary (default) or json", "summary")
  .action(async (file, opts) => {
    await runVerify(file, opts);
  });
