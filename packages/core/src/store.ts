/**
 * Sanna ReceiptStore — SQLite persistence for reasoning receipts.
 *
 * Stores receipts with indexed metadata for fleet-level governance queries.
 * Uses better-sqlite3 for synchronous SQLite access.
 */

import Database from "better-sqlite3";
import { mkdirSync, existsSync, chmodSync, openSync, fstatSync, closeSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { homedir, platform } from "node:os";
import type { ReceiptQueryFilters } from "./types.js";

const SCHEMA_VERSION = 1;

const CREATE_SCHEMA = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    id              TEXT PRIMARY KEY,
    agent_id        TEXT,
    constitution_id TEXT,
    correlation_id  TEXT,
    timestamp       TEXT,
    overall_status  TEXT,
    enforcement     INTEGER DEFAULT 0,
    check_statuses  TEXT,
    receipt_json    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_agent_id ON receipts(agent_id);
CREATE INDEX IF NOT EXISTS idx_receipts_constitution_id ON receipts(constitution_id);
CREATE INDEX IF NOT EXISTS idx_receipts_correlation_id ON receipts(correlation_id);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_overall_status ON receipts(overall_status);
CREATE INDEX IF NOT EXISTS idx_receipts_enforcement ON receipts(enforcement);
`;

function extractAgentId(receipt: Record<string, unknown>): string | null {
  const ref = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (!ref || typeof ref !== "object") return null;
  const docId = ref.document_id;
  if (!docId || typeof docId !== "string") return null;
  const parts = docId.split("/", 2);
  return parts[0] || null;
}

function extractConstitutionId(receipt: Record<string, unknown>): string | null {
  const ref = receipt.constitution_ref as Record<string, unknown> | undefined;
  if (!ref || typeof ref !== "object") return null;
  const docId = ref.document_id;
  return typeof docId === "string" ? docId : null;
}

function extractCheckStatuses(receipt: Record<string, unknown>): string {
  const checks = receipt.checks;
  if (!Array.isArray(checks) || checks.length === 0) return "[]";
  const statuses: { check_id: string; status: string }[] = [];
  for (const check of checks) {
    if (!check || typeof check !== "object") continue;
    const c = check as Record<string, unknown>;
    const checkId = String(c.check_id ?? "unknown");
    const explicit = c.status as string | undefined;
    let status: string;
    if (explicit) {
      status = explicit;
    } else if (c.passed) {
      status = "PASS";
    } else {
      status = "FAIL";
    }
    statuses.push({ check_id: checkId, status });
  }
  return JSON.stringify(statuses);
}

function isHalt(receipt: Record<string, unknown>): number {
  const enforcement = receipt.enforcement as Record<string, unknown> | undefined;
  if (enforcement && typeof enforcement === "object") {
    const action = enforcement.action;
    if (action === "halted" || action === "escalated") return 1;
  }
  return 0;
}

export class ReceiptStore {
  private _db: Database.Database;
  private _closed = false;

  constructor(dbPath: string = ".sanna/receipts.db") {
    const resolved = resolve(dbPath);

    // Refuse /tmp paths unless SANNA_ALLOW_TEMP_DB=1
    const tmpPrefixes = ["/tmp", "/var/tmp", "/private/tmp"];
    if (tmpPrefixes.some((p) => resolved.startsWith(p))) {
      if (process.env.SANNA_ALLOW_TEMP_DB !== "1") {
        throw new Error(
          `Refusing to store receipts in temp directory: ${dbPath}. ` +
          `Use a persistent, user-owned path like ~/.sanna/receipts.db. ` +
          `Set SANNA_ALLOW_TEMP_DB=1 to bypass (CI/testing only).`,
        );
      }
    }

    // Bare filename → ~/.sanna/receipts/
    if (!dbPath.includes("/") && !dbPath.includes("\\") && !dbPath.startsWith(".")) {
      const defaultDir = resolve(homedir(), ".sanna", "receipts");
      dbPath = resolve(defaultDir, dbPath);
    }

    // Ensure parent directory exists
    const dir = dirname(resolve(dbPath));
    if (dir) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    // Secure file permissions on Unix
    if (platform() !== "win32" && existsSync(resolve(dbPath))) {
      try {
        const fd = openSync(resolve(dbPath), "r+");
        try {
          const st = fstatSync(fd);
          if (!st.isFile()) {
            throw new Error(`${dbPath} is not a regular file`);
          }
          if (st.uid !== process.getuid!()) {
            if (process.env.SANNA_SKIP_DB_OWNERSHIP_CHECK !== "1") {
              throw new Error(
                `${dbPath} is not owned by current user. ` +
                `Set SANNA_SKIP_DB_OWNERSHIP_CHECK=1 to bypass.`,
              );
            }
          }
        } finally {
          closeSync(fd);
        }
        chmodSync(resolve(dbPath), 0o600);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") {
          // File doesn't exist yet, will be created by better-sqlite3
        } else {
          throw e;
        }
      }
    }

    this._db = new Database(resolve(dbPath));
    this._db.pragma("journal_mode = WAL");

    this._initSchema();

    // Harden DB file after creation
    if (platform() !== "win32") {
      try {
        chmodSync(resolve(dbPath), 0o600);
      } catch {
        // May not exist yet on first open
      }
    }
  }

  private _initSchema(): void {
    this._db.exec(CREATE_SCHEMA);
    const row = this._db.prepare("SELECT version FROM schema_version LIMIT 1").get() as
      | { version: number }
      | undefined;
    if (!row) {
      this._db.prepare("INSERT INTO schema_version (version) VALUES (?)").run(SCHEMA_VERSION);
    } else if (row.version !== SCHEMA_VERSION) {
      throw new Error(
        `ReceiptStore schema version mismatch: expected ${SCHEMA_VERSION}, found ${row.version}.`,
      );
    }
  }

  save(receipt: Record<string, unknown>): string {
    let receiptId = receipt.receipt_id;
    if (!receiptId || typeof receiptId !== "string") {
      receiptId = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
    }

    const agentId = extractAgentId(receipt);
    const constitutionId = extractConstitutionId(receipt);
    const correlationId = typeof receipt.correlation_id === "string" ? receipt.correlation_id : null;
    const timestamp = typeof receipt.timestamp === "string" ? receipt.timestamp : null;
    const overallStatus = typeof receipt.status === "string" ? receipt.status : null;
    const halt = isHalt(receipt);
    const checkStatuses = extractCheckStatuses(receipt);
    const receiptJson = JSON.stringify(receipt);

    this._db
      .prepare(
        `INSERT OR REPLACE INTO receipts
         (id, agent_id, constitution_id, correlation_id, timestamp,
          overall_status, enforcement, check_statuses, receipt_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        receiptId,
        agentId,
        constitutionId,
        correlationId,
        timestamp,
        overallStatus,
        halt,
        checkStatuses,
        receiptJson,
      );

    return receiptId as string;
  }

  private _buildWhere(filters: ReceiptQueryFilters): { where: string; params: unknown[] } {
    const clauses: string[] = [];
    const params: unknown[] = [];

    if (filters.agent_id !== undefined) {
      clauses.push("agent_id = ?");
      params.push(filters.agent_id);
    }
    if (filters.constitution_id !== undefined) {
      clauses.push("constitution_id = ?");
      params.push(filters.constitution_id);
    }
    if (filters.correlation_id !== undefined) {
      clauses.push("correlation_id = ?");
      params.push(filters.correlation_id);
    }
    if (filters.status !== undefined) {
      clauses.push("overall_status = ?");
      params.push(filters.status);
    }
    if (filters.enforcement) {
      clauses.push("enforcement = 1");
    }
    if (filters.since !== undefined) {
      clauses.push("timestamp >= ?");
      params.push(filters.since);
    }
    if (filters.until !== undefined) {
      clauses.push("timestamp <= ?");
      params.push(filters.until);
    }

    const where = clauses.length > 0 ? clauses.join(" AND ") : "1=1";
    return { where, params };
  }

  query(filters: ReceiptQueryFilters = {}): Record<string, unknown>[] {
    const { where, params } = this._buildWhere(filters);
    let sql = `SELECT receipt_json FROM receipts WHERE ${where} ORDER BY timestamp DESC`;

    if (filters.limit !== undefined && filters.limit >= 0) {
      sql += " LIMIT ? OFFSET ?";
      params.push(filters.limit, filters.offset ?? 0);
    }

    const rows = this._db.prepare(sql).all(...params) as { receipt_json: string }[];
    return rows.map((r) => JSON.parse(r.receipt_json) as Record<string, unknown>);
  }

  count(filters: ReceiptQueryFilters = {}): number {
    const { where, params } = this._buildWhere(filters);
    const sql = `SELECT COUNT(*) as cnt FROM receipts WHERE ${where}`;
    const row = this._db.prepare(sql).get(...params) as { cnt: number };
    return row.cnt;
  }

  close(): void {
    if (!this._closed) {
      this._db.close();
      this._closed = true;
    }
  }

  [Symbol.dispose](): void {
    this.close();
  }
}
