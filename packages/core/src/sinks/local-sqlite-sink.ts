/** LocalSQLiteSink — wraps ReceiptStore for the ReceiptSink interface. */

import { ReceiptStore } from "../store.js";
import type { FailurePolicy, ReceiptSink, SinkResult } from "./types.js";
import { SinkError, createSinkResult } from "./types.js";

export class LocalSQLiteSink implements ReceiptSink {
  private readonly _store: ReceiptStore;
  private readonly _failurePolicy: FailurePolicy;

  constructor(dbPath: string, failurePolicy: FailurePolicy = "log_and_continue") {
    this._store = new ReceiptStore(dbPath);
    this._failurePolicy = failurePolicy;
  }

  async store(receipt: Record<string, unknown>): Promise<SinkResult> {
    try {
      this._store.save(receipt);
      return createSinkResult(1, 0);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (this._failurePolicy === "raise") {
        throw new SinkError(msg);
      }
      return createSinkResult(0, 1, [msg]);
    }
  }

  async batchStore(receipts: Record<string, unknown>[]): Promise<SinkResult> {
    let stored = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const receipt of receipts) {
      try {
        this._store.save(receipt);
        stored++;
      } catch (e) {
        failed++;
        const msg = e instanceof Error ? e.message : String(e);
        errors.push(msg);
        if (this._failurePolicy !== "raise") {
          // log_and_continue or buffer_and_retry — keep going
        }
      }
    }

    if (failed > 0 && this._failurePolicy === "raise") {
      throw new SinkError(`${failed} receipt(s) failed: ${errors.join("; ")}`);
    }

    return createSinkResult(stored, failed, errors);
  }

  async flush(): Promise<void> {
    // SQLite WAL commits are immediate — no-op
  }

  async close(): Promise<void> {
    await this.flush();
    this._store.close();
  }
}
