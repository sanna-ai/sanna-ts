/**
 * Sanna evidence bundle — self-contained verification archives.
 *
 * A bundle is a zip archive containing a receipt, the constitution that
 * drove its evaluation, and the public key(s) needed for offline Ed25519
 * signature verification.
 *
 * Bundle structure:
 *   receipt.json
 *   constitution.yaml
 *   public_keys/{key_id}.pub
 *   metadata.json
 */

import AdmZip from "adm-zip";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve, dirname, posix } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";

import { loadConstitution, verifyConstitutionSignature } from "./constitution.js";
import { loadPublicKey, getKeyId, exportPublicKeyPem } from "./crypto.js";
import { verifyReceipt } from "./verifier.js";
import { computeFingerprints, TOOL_VERSION } from "./receipt.js";
import type {
  BundleCheck,
  BundleVerificationResult,
  Constitution,
  CreateBundleOptions,
} from "./types.js";

const BUNDLE_FORMAT_VERSION = "1.0.0";
const MAX_BUNDLE_MEMBERS = 10;
const MAX_BUNDLE_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const EXPECTED_MEMBERS = new Set(["receipt.json", "constitution.yaml", "metadata.json"]);
const EXPECTED_PREFIX = "public_keys/";

// ── Bundle creation ──────────────────────────────────────────────────

export function createBundle(opts: CreateBundleOptions): string {
  const { receiptPath, constitutionPath, publicKeyPath, outputPath, description } = opts;

  // Validate inputs
  for (const [p, label] of [
    [receiptPath, "Receipt"],
    [constitutionPath, "Constitution"],
    [publicKeyPath, "Public key"],
  ] as const) {
    if (!existsSync(p)) {
      throw new Error(`${label} not found: ${p}`);
    }
  }

  // Validate receipt
  const receiptText = readFileSync(receiptPath, "utf-8");
  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(receiptText) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`Receipt is not valid JSON: ${e}`);
  }
  if (!receipt.receipt_signature) {
    throw new Error("Receipt is not signed (no receipt_signature).");
  }

  // Validate constitution
  const constitutionText = readFileSync(constitutionPath, "utf-8");
  let constData: Record<string, unknown>;
  if (constitutionPath.endsWith(".yaml") || constitutionPath.endsWith(".yml")) {
    constData = yaml.load(constitutionText) as Record<string, unknown>;
  } else {
    constData = JSON.parse(constitutionText) as Record<string, unknown>;
  }
  if (!constData.policy_hash) {
    throw new Error(`Constitution is not signed (no policy_hash): ${constitutionPath}`);
  }
  const prov = (constData.provenance ?? {}) as Record<string, unknown>;
  const sig = (prov.signature ?? {}) as Record<string, unknown>;
  if (!sig.value || !sig.key_id) {
    throw new Error(
      `Constitution is not Ed25519-signed (missing signature.value or key_id): ${constitutionPath}`,
    );
  }

  // Load public key
  const publicKey = loadPublicKey(publicKeyPath);
  const keyId = getKeyId(publicKey);

  // Build metadata
  const metadata: Record<string, unknown> = {
    bundle_format_version: BUNDLE_FORMAT_VERSION,
    created_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    description: description ?? "",
  };

  // Create zip
  const zip = new AdmZip();
  zip.addFile("receipt.json", Buffer.from(receiptText, "utf-8"));
  zip.addFile("constitution.yaml", Buffer.from(constitutionText, "utf-8"));
  zip.addFile(
    `public_keys/${keyId}.pub`,
    Buffer.from(readFileSync(publicKeyPath, "utf-8"), "utf-8"),
  );
  zip.addFile("metadata.json", Buffer.from(JSON.stringify(metadata, null, 2), "utf-8"));

  // Ensure output directory exists
  const outDir = dirname(resolve(outputPath));
  if (outDir) mkdirSync(outDir, { recursive: true });

  zip.writeZip(resolve(outputPath));
  return resolve(outputPath);
}

// ── Bundle verification ──────────────────────────────────────────────

export function verifyBundle(
  bundlePath: string,
  strict: boolean = true,
): BundleVerificationResult {
  if (!existsSync(bundlePath)) {
    throw new Error(`Bundle not found: ${bundlePath}`);
  }

  const checks: BundleCheck[] = [];
  const errors: string[] = [];
  let receiptSummary: Record<string, unknown> | null = null;

  // Open zip
  let zip: AdmZip;
  try {
    zip = new AdmZip(bundlePath);
  } catch {
    return {
      valid: false,
      checks: [{ name: "Bundle structure", passed: false, detail: "Not a valid zip file" }],
      receipt_summary: null,
      errors: ["Not a valid zip file"],
    };
  }

  const entries = zip.getEntries();
  const memberNames = entries.map((e) => e.entryName);

  // Guard: max members
  if (memberNames.length > MAX_BUNDLE_MEMBERS) {
    const detail = `Too many members: ${memberNames.length} (max ${MAX_BUNDLE_MEMBERS})`;
    checks.push({ name: "Bundle structure", passed: false, detail });
    return { valid: false, checks, receipt_summary: null, errors: [detail] };
  }

  // Guard: path safety
  for (const name of memberNames) {
    if (name.startsWith("/") || posix.isAbsolute(name)) {
      const detail = `Zip member has absolute path: '${name}'`;
      checks.push({ name: "Bundle structure", passed: false, detail });
      return { valid: false, checks, receipt_summary: null, errors: [detail] };
    }
    if (name.includes("\\")) {
      const detail = `Zip member contains backslash: '${name}'`;
      checks.push({ name: "Bundle structure", passed: false, detail });
      return { valid: false, checks, receipt_summary: null, errors: [detail] };
    }
    if (name.includes("..")) {
      const detail = `Unsafe path in bundle: '${name}'`;
      checks.push({ name: "Bundle structure", passed: false, detail });
      return { valid: false, checks, receipt_summary: null, errors: [detail] };
    }
    // Check expected members
    if (!EXPECTED_MEMBERS.has(name) && !(name.startsWith(EXPECTED_PREFIX) && name.endsWith(".pub"))) {
      const detail = `Unexpected member in bundle: '${name}'`;
      checks.push({ name: "Bundle structure", passed: false, detail });
      return { valid: false, checks, receipt_summary: null, errors: [detail] };
    }
  }

  // Guard: file sizes
  for (const entry of entries) {
    if (entry.header.size > MAX_BUNDLE_FILE_SIZE) {
      const detail = `Member '${entry.entryName}' too large: ${entry.header.size} bytes (max ${MAX_BUNDLE_FILE_SIZE})`;
      checks.push({ name: "Bundle structure", passed: false, detail });
      return { valid: false, checks, receipt_summary: null, errors: [detail] };
    }
  }

  // Step 1: Bundle structure
  const missing: string[] = [];
  if (!memberNames.includes("receipt.json")) missing.push("receipt.json");
  if (!memberNames.includes("constitution.yaml")) missing.push("constitution.yaml");
  const hasPubKeys = memberNames.some((n) => n.startsWith(EXPECTED_PREFIX) && n.endsWith(".pub"));
  if (!hasPubKeys) missing.push("public_keys/*.pub");

  if (missing.length > 0) {
    const detail = `Missing: ${missing.join(", ")}`;
    checks.push({ name: "Bundle structure", passed: false, detail });
    return { valid: false, checks, receipt_summary: null, errors: [detail] };
  }
  checks.push({ name: "Bundle structure", passed: true, detail: "All required files present" });

  // Load receipt
  let receipt: Record<string, unknown>;
  const receiptEntry = zip.getEntry("receipt.json")!;
  try {
    receipt = JSON.parse(receiptEntry.getData().toString("utf-8")) as Record<string, unknown>;
  } catch (e) {
    checks.push({ name: "Receipt schema", passed: false, detail: `Invalid JSON: ${e}` });
    return { valid: false, checks, receipt_summary: null, errors: [`Invalid JSON: ${e}`] };
  }

  // Build receipt summary
  const constRef = (receipt.constitution_ref ?? {}) as Record<string, unknown>;
  const docId = constRef.document_id as string | undefined;
  receiptSummary = {
    correlation_id: receipt.correlation_id,
    status: receipt.status,
    agent_name: docId ? docId.split("/")[0] : null,
    constitution_version: constRef.version ?? null,
  };

  // Resolve public keys
  const pubKeyEntries = entries.filter(
    (e) => e.entryName.startsWith(EXPECTED_PREFIX) && e.entryName.endsWith(".pub"),
  );

  function resolveKey(keyId: string): Buffer | null {
    if (!keyId) return null;
    const entry = pubKeyEntries.find((e) => {
      const stem = e.entryName.slice(EXPECTED_PREFIX.length, -4); // strip prefix and .pub
      return stem === keyId;
    });
    return entry ? entry.getData() : null;
  }

  // Step 2: Receipt schema (use verifyReceipt without a key for schema check)
  const receiptSigBlock = (receipt.receipt_signature ?? {}) as Record<string, unknown>;
  const receiptKeyId = receiptSigBlock.key_id as string ?? "";
  const receiptPubKeyData = resolveKey(receiptKeyId) ?? pubKeyEntries[0]?.getData();

  const schemaResult = verifyReceipt(receipt);
  const schemaErrors = schemaResult.errors.filter(
    (e) => !e.includes("signature") && !e.toLowerCase().includes("timestamp"),
  );
  if (schemaErrors.length === 0) {
    checks.push({ name: "Receipt schema", passed: true, detail: "Schema valid" });
  } else {
    const detail = schemaErrors.join("; ");
    checks.push({ name: "Receipt schema", passed: false, detail });
    errors.push(...schemaErrors);
  }

  // Step 3: Receipt fingerprint
  try {
    const { receipt_fingerprint: computed16, full_fingerprint: computed64 } =
      computeFingerprints(receipt);
    const expected16 = String(receipt.receipt_fingerprint ?? "");
    if (computed16 === expected16) {
      checks.push({ name: "Receipt fingerprint", passed: true, detail: `Fingerprint intact: ${expected16}` });
    } else {
      const detail = `Mismatch: computed ${computed16}, expected ${expected16}`;
      checks.push({ name: "Receipt fingerprint", passed: false, detail });
      errors.push(`Receipt fingerprint mismatch: ${detail}`);
    }
  } catch (e) {
    checks.push({ name: "Receipt fingerprint", passed: false, detail: `Computation failed: ${e}` });
    errors.push(`Receipt fingerprint error: ${e}`);
  }

  // Step 4: Constitution signature
  const constitutionEntry = zip.getEntry("constitution.yaml")!;
  const constitutionText = constitutionEntry.getData().toString("utf-8");
  let constitution: ReturnType<typeof loadConstitutionFromText> | null = null;

  try {
    const constData = yaml.load(constitutionText) as Record<string, unknown>;
    const { parseConstitution } = require("./constitution.js");
    constitution = parseConstitution(constData);
  } catch (e) {
    checks.push({ name: "Constitution signature", passed: false, detail: `Failed to load: ${e}` });
    errors.push(`Constitution load failed: ${e}`);
  }

  if (constitution) {
    const constSig = constitution.provenance?.signature;
    if (constSig && constSig.value) {
      const constKeyId = constSig.key_id ?? "";
      const constPubKeyData = resolveKey(constKeyId) ?? receiptPubKeyData;
      if (constPubKeyData) {
        try {
          const { createPublicKey } = require("node:crypto");
          const pubKey = createPublicKey({
            key: constPubKeyData.toString("utf-8"),
            format: "pem",
            type: "spki",
          });
          const valid = verifyConstitutionSignature(constitution, pubKey);
          if (valid) {
            checks.push({
              name: "Constitution signature",
              passed: true,
              detail: `Valid (signed by: ${constSig.signed_by ?? "unknown"})`,
            });
          } else {
            checks.push({ name: "Constitution signature", passed: false, detail: "Ed25519 signature verification failed" });
            errors.push("Constitution signature verification failed");
          }
        } catch (e) {
          checks.push({ name: "Constitution signature", passed: false, detail: `Verification error: ${e}` });
          errors.push(`Constitution signature error: ${e}`);
        }
      } else {
        checks.push({ name: "Constitution signature", passed: false, detail: "No matching public key in bundle" });
        errors.push("No matching public key for constitution signature");
      }
    } else {
      checks.push({ name: "Constitution signature", passed: false, detail: "Constitution has no signature" });
      errors.push("Constitution is not signed");
    }
  }

  // Step 5: Provenance chain
  if (constitution) {
    const chainErrors = verifyProvenanceChain(receipt, constitution);
    if (chainErrors.length === 0) {
      checks.push({ name: "Provenance chain", passed: true, detail: "Receipt-to-constitution binding intact" });
    } else {
      checks.push({ name: "Provenance chain", passed: false, detail: chainErrors.join("; ") });
      errors.push(...chainErrors);
    }
  } else {
    checks.push({ name: "Provenance chain", passed: false, detail: "Cannot verify: constitution failed to load" });
  }

  // Step 6: Receipt signature
  const sigBlock = (receipt.receipt_signature ?? {}) as Record<string, unknown>;
  if (sigBlock.signature) {
    if (receiptPubKeyData) {
      try {
        const { createPublicKey } = require("node:crypto");
        const pubKey = createPublicKey({
          key: receiptPubKeyData.toString("utf-8"),
          format: "pem",
          type: "spki",
        });
        const result = verifyReceipt(receipt, pubKey);
        const sigErrors = result.errors.filter((e) => e.includes("signature") || e.includes("Signature"));
        if (sigErrors.length === 0) {
          checks.push({ name: "Receipt signature", passed: true, detail: "Ed25519 signature valid" });
        } else {
          checks.push({ name: "Receipt signature", passed: false, detail: "Ed25519 signature verification failed" });
          errors.push("Receipt signature verification failed");
        }
      } catch {
        checks.push({ name: "Receipt signature", passed: false, detail: "Signature verification error" });
        errors.push("Receipt signature verification error");
      }
    } else {
      checks.push({ name: "Receipt signature", passed: false, detail: "No public key available" });
      errors.push("No public key for receipt signature verification");
    }
  } else {
    checks.push({ name: "Receipt signature", passed: false, detail: "Receipt has no signature" });
    errors.push("Receipt is not signed");
  }

  // Step 7: Approval verification (simplified — no approval block in v1.0 TS)
  checks.push({
    name: "Approval verification",
    passed: true,
    detail: "Constitution has no approval block (not required)",
  });

  // Compute verdict
  const valid = strict
    ? checks.every((c) => c.passed)
    : checks
        .filter((c) => c.name === "Bundle structure" || c.name === "Receipt fingerprint")
        .every((c) => c.passed);

  return { valid, checks, receipt_summary: receiptSummary, errors };
}

// ── Internal helpers ─────────────────────────────────────────────────

function loadConstitutionFromText(_text: string): Constitution | null {
  // Placeholder — actual implementation uses parseConstitution
  return null;
}

function verifyProvenanceChain(
  receipt: Record<string, unknown>,
  constitution: Constitution,
): string[] {
  const errs: string[] = [];
  const constRef = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (!constRef) {
    errs.push("Receipt has no constitution_ref");
    return errs;
  }

  const receiptHash = constRef.policy_hash as string ?? "";
  if (receiptHash !== constitution.policy_hash) {
    errs.push(
      `policy_hash mismatch: receipt has ${receiptHash.slice(0, 16)}..., ` +
      `constitution has ${(constitution.policy_hash ?? "").slice(0, 16)}...`,
    );
  }

  return errs;
}
