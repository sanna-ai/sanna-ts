/**
 * SAN-765: verifier enforcement of spec Section 7.3 assurance rule.
 * Drives the child_process interceptor with an allowed action to produce a real,
 * schema-valid authority-only receipt, then asserts:
 *   - assurance="partial" passes the 7.3 check (no error)
 *   - assurance="full"    fails the 7.3 check with the exact cross-SDK message
 */
import { describe, it, expect, afterEach } from "vitest";
import { createRequire } from "node:module";
import * as path from "node:path";
import { patchChildProcess, unpatchChildProcess } from "../src/interceptors/index.js";
import { verifyReceipt } from "../src/verifier.js";
import type { Receipt, ReceiptSink, SinkResult } from "../src/types.js";

const require_ = createRequire(import.meta.url);
const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures");
const CLI_CONSTITUTION = path.join(FIXTURES_DIR, "cli-test.yaml");

const ASSURANCE_7_3_MSG =
  "Authority-only receipt (invariants_scope=authority_only) with a Receipt Triad " +
  "must have assurance='partial' per spec Section 7.3 (no reasoning checks ran).";

class TestSink implements ReceiptSink {
  receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> {
    this.receipts.push(receipt);
    return { success: true, receiptId: receipt.receipt_id };
  }
}

function invocation(sink: TestSink): Receipt[] {
  return sink.receipts.filter((r: any) => r.event_type !== "session_manifest");
}

afterEach(() => { unpatchChildProcess(); });

describe("SAN-765 verifier -- spec Section 7.3 authority-only assurance rule", () => {
  it("real interceptor receipt (assurance=partial) does not trigger the 7.3 error", async () => {
    const sink = new TestSink();
    await patchChildProcess({ constitutionPath: CLI_CONSTITUTION, sink, agentId: "test-agent", mode: "enforce" });
    const cp = require_("node:child_process");
    cp.spawnSync("echo", ["hello"], { encoding: "utf-8" });
    const receipts = invocation(sink);
    expect(receipts.length).toBe(1);
    const receipt = receipts[0] as unknown as Record<string, unknown>;
    expect(receipt.invariants_scope).toBe("authority_only");
    expect(receipt.assurance).toBe("partial");
    const result = verifyReceipt(receipt);
    expect(result.errors).not.toContain(ASSURANCE_7_3_MSG);
  });

  it("receipt with assurance=full fails with the exact 7.3 message and valid=false", async () => {
    const sink = new TestSink();
    await patchChildProcess({ constitutionPath: CLI_CONSTITUTION, sink, agentId: "test-agent", mode: "enforce" });
    const cp = require_("node:child_process");
    cp.spawnSync("echo", ["hello"], { encoding: "utf-8" });
    const receipts = invocation(sink);
    expect(receipts.length).toBe(1);
    const receipt = receipts[0] as unknown as Record<string, unknown>;
    const tampered = { ...receipt, assurance: "full" };
    const result = verifyReceipt(tampered);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(ASSURANCE_7_3_MSG);
  });
});
