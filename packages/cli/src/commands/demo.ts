import { Command } from "commander";
import {
  generateKeypair,
  signConstitution,
  generateReceipt,
  signReceipt,
  verifyReceipt,
  verifyConstitutionSignature,
} from "@sanna-ai/core";
import type { Constitution, CheckResult } from "@sanna-ai/core";

export async function runDemo(): Promise<void> {
  console.log("=== Sanna Demo ===");
  console.log();

  // 1. Generate signing keys
  const keypair = generateKeypair("demo");
  console.log(`1. Generated Ed25519 keypair (${keypair.keyId.slice(0, 16)}...)`);

  // 2. Create minimal constitution
  const constitution: Constitution = {
    schema_version: "1.0.0",
    identity: {
      agent_name: "demo-agent",
      domain: "demo",
      description: "Demo agent for the Sanna protocol",
      extensions: {},
    },
    provenance: {
      authored_by: "demo@sanna.dev",
      approved_by: ["reviewer@sanna.dev"],
      approval_date: new Date().toISOString().split("T")[0],
      approval_method: "automated-demo",
      change_history: [],
      signature: null,
    },
    boundaries: [
      {
        id: "B001",
        description: "Operate within demo scope",
        category: "scope",
        severity: "medium",
      },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [
      {
        id: "INV_NO_FABRICATION",
        rule: "Do not claim facts absent from sources.",
        enforcement: "halt",
        check: null,
      },
      {
        id: "INV_MARK_INFERENCE",
        rule: "Clearly mark inferences.",
        enforcement: "warn",
        check: null,
      },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
  };

  // 3. Sign constitution
  const signed = signConstitution(constitution, keypair.privateKey, "demo-signer");
  console.log(`2. Signed constitution (hash: ${signed.policy_hash!.slice(0, 16)}...)`);

  // 4. Verify constitution signature
  const constValid = verifyConstitutionSignature(signed, keypair.publicKey);
  console.log(`3. Verified constitution signature: ${constValid ? "VALID" : "FAILED"}`);

  // 5. Generate a receipt
  const checks: CheckResult[] = [
    {
      check_id: "C1",
      name: "Context Contradiction",
      passed: true,
      severity: "info",
      evidence: null,
    },
    {
      check_id: "C2",
      name: "Mark Inferences",
      passed: true,
      severity: "info",
      evidence: null,
    },
    {
      check_id: "C3",
      name: "No False Certainty",
      passed: true,
      severity: "info",
      evidence: null,
    },
  ];

  const receipt = generateReceipt({
    correlation_id: "demo-correlation-001",
    inputs: { query: "What is the project status?", context: "The project is on track." },
    outputs: { response: "Based on context, the project is on track." },
    checks,
    constitution_ref: {
      document_id: `${signed.identity.agent_name}/1.0`,
      policy_hash: signed.policy_hash,
    },
    enforcementSurface: "middleware",
    invariantsScope: "full",
  });
  console.log(`4. Generated receipt: ${receipt.receipt_id.slice(0, 24)}...`);
  console.log(`   Status: ${receipt.status} (${receipt.checks_passed}/${receipt.checks_passed + receipt.checks_failed} passed)`);

  // 6. Sign receipt
  const receiptObj = receipt as unknown as Record<string, unknown>;
  signReceipt(receiptObj, keypair.privateKey, "demo-signer");
  console.log("5. Signed receipt with Ed25519");

  // 7. Verify receipt
  const vr = verifyReceipt(receiptObj, keypair.publicKey);
  console.log(`6. Verified receipt: ${vr.valid ? "VALID" : "INVALID"}`);
  if (vr.errors.length > 0) {
    for (const err of vr.errors) {
      console.log(`   Error: ${err}`);
    }
  }

  console.log();
  console.log("Demo complete. All steps executed in memory — no files written.");
}

export const demoCommand = new Command("demo")
  .description("Run self-contained governance demo")
  .action(async () => {
    await runDemo();
  });
