/**
 * Sanna Protocol — Constitution Approval Workflow
 *
 * Multi-party approval for constitutions with Ed25519 signatures.
 * Approval requests track required signatures and expiration.
 */

import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { canonicalize } from "./hashing.js";
import { sign, verify, getKeyId } from "./crypto.js";
import { readFileSync } from "node:fs";
import { safeWriteJson } from "./safe-io.js";
import type {
  ApprovalRequest,
  ApprovalSignature,
  ApprovalStatus,
  ApprovalVerificationResult,
} from "./types.js";

// ── Approval request creation ───────────────────────────────────────

export interface CreateApprovalOptions {
  required_approvals?: number;
  expires_in_hours?: number;
}

/**
 * Create a new approval request for a constitution.
 *
 * @param constitutionHash SHA-256 hash of the constitution content
 * @param requester Identifier of the person requesting approval
 * @param options Configuration for required approvals and expiry
 */
export function createApprovalRequest(
  constitutionHash: string,
  requester: string,
  options: CreateApprovalOptions = {},
): ApprovalRequest {
  const requiredApprovals = options.required_approvals ?? 1;
  const expiresInHours = options.expires_in_hours ?? 72;

  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInHours * 3600_000);

  return {
    id: randomUUID(),
    constitution_hash: constitutionHash,
    requester,
    requested_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    status: "pending",
    required_approvals: requiredApprovals,
    approvals: [],
  };
}

// ── Approval signing ────────────────────────────────────────────────

/**
 * Build the signable data for an approval signature.
 * Signs: constitution_hash | request_id | approver_key_id
 */
function buildApprovalSignableData(
  requestId: string,
  constitutionHash: string,
  approverKeyId: string,
): Buffer {
  const signable = canonicalize({
    request_id: requestId,
    constitution_hash: constitutionHash,
    approver_key_id: approverKeyId,
  });
  return Buffer.from(signable, "utf-8");
}

/**
 * Add an approval signature to an approval request.
 *
 * Signs constitution_hash + request_id + approver_key_id with the
 * approver's Ed25519 private key. If the required number of approvals
 * is reached, the request status changes to "approved".
 *
 * @param request The approval request to sign
 * @param privateKey Ed25519 private key of the approver
 * @returns The updated request (mutated in place)
 */
export function signApproval(
  request: ApprovalRequest,
  privateKey: KeyObject,
): ApprovalRequest {
  if (request.status !== "pending") {
    throw new Error(
      `Cannot sign approval: request status is '${request.status}', expected 'pending'`,
    );
  }

  if (isApprovalExpired(request)) {
    request.status = "expired";
    throw new Error("Cannot sign approval: request has expired");
  }

  const approverKeyId = getKeyId(privateKey);

  // Check for duplicate approvals
  if (request.approvals.some((a) => a.approver_key_id === approverKeyId)) {
    throw new Error(
      `Approver ${approverKeyId} has already signed this request`,
    );
  }

  const data = buildApprovalSignableData(
    request.id,
    request.constitution_hash,
    approverKeyId,
  );
  const signature = sign(data, privateKey);

  const approval: ApprovalSignature = {
    approver_key_id: approverKeyId,
    approved_at: new Date().toISOString(),
    signature,
  };

  request.approvals.push(approval);

  // Auto-approve when threshold reached
  if (request.approvals.length >= request.required_approvals) {
    request.status = "approved";
  }

  return request;
}

// ── Approval verification ───────────────────────────────────────────

/**
 * Verify all approval signatures on an approval request.
 *
 * @param request The approval request to verify
 * @param publicKeys Map from key_id to public KeyObject
 */
export function verifyApproval(
  request: ApprovalRequest,
  publicKeys: Map<string, KeyObject>,
): ApprovalVerificationResult {
  const details: ApprovalVerificationResult["details"] = [];
  let verifiedCount = 0;

  for (const approval of request.approvals) {
    const pubKey = publicKeys.get(approval.approver_key_id);
    if (!pubKey) {
      details.push({
        approver_key_id: approval.approver_key_id,
        signature_valid: false,
        error: "Public key not found",
      });
      continue;
    }

    try {
      const data = buildApprovalSignableData(
        request.id,
        request.constitution_hash,
        approval.approver_key_id,
      );
      const valid = verify(data, approval.signature, pubKey);
      details.push({
        approver_key_id: approval.approver_key_id,
        signature_valid: valid,
      });
      if (valid) verifiedCount++;
    } catch (err) {
      details.push({
        approver_key_id: approval.approver_key_id,
        signature_valid: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    valid: verifiedCount >= request.required_approvals,
    verified_count: verifiedCount,
    required_count: request.required_approvals,
    details,
  };
}

// ── Expiry check ────────────────────────────────────────────────────

/**
 * Check if an approval request has expired.
 */
export function isApprovalExpired(request: ApprovalRequest): boolean {
  return new Date(request.expires_at).getTime() < Date.now();
}

// ── Approval Store ──────────────────────────────────────────────────

export interface ApprovalStoreFilters {
  status?: ApprovalStatus;
  requester?: string;
  constitution_hash?: string;
}

/**
 * In-memory store for approval requests.
 * Optionally persists to a JSON file.
 */
export class ApprovalStore {
  private _requests = new Map<string, ApprovalRequest>();
  private _persistPath: string | null;

  constructor(persistPath?: string) {
    this._persistPath = persistPath ?? null;

    if (this._persistPath) {
      this._load();
    }
  }

  save(request: ApprovalRequest): string {
    this._requests.set(request.id, structuredClone(request));
    this._persist();
    return request.id;
  }

  get(id: string): ApprovalRequest | undefined {
    const req = this._requests.get(id);
    return req ? structuredClone(req) : undefined;
  }

  list(filters: ApprovalStoreFilters = {}): ApprovalRequest[] {
    const results: ApprovalRequest[] = [];
    for (const req of this._requests.values()) {
      if (filters.status && req.status !== filters.status) continue;
      if (filters.requester && req.requester !== filters.requester) continue;
      if (
        filters.constitution_hash &&
        req.constitution_hash !== filters.constitution_hash
      )
        continue;
      results.push(structuredClone(req));
    }
    return results;
  }

  updateStatus(id: string, status: ApprovalStatus): boolean {
    const req = this._requests.get(id);
    if (!req) return false;
    req.status = status;
    this._persist();
    return true;
  }

  private _persist(): void {
    if (!this._persistPath) return;
    safeWriteJson(this._persistPath, Array.from(this._requests.values()));
  }

  private _load(): void {
    if (!this._persistPath) return;
    try {
      const raw = readFileSync(this._persistPath, "utf-8");
      const arr = JSON.parse(raw) as ApprovalRequest[];
      for (const req of arr) {
        this._requests.set(req.id, req);
      }
    } catch {
      // File doesn't exist yet — start empty
    }
  }
}
