/** NullSink — no-op sink for testing and dry-run mode. */

import type { ReceiptSink, SinkResult } from "./types.js";
import { createSinkResult } from "./types.js";

export class NullSink implements ReceiptSink {
  async store(_receipt: Record<string, unknown>): Promise<SinkResult> {
    return createSinkResult(1, 0);
  }

  async batchStore(receipts: Record<string, unknown>[]): Promise<SinkResult> {
    return createSinkResult(receipts.length, 0);
  }

  async flush(): Promise<void> {}

  async close(): Promise<void> {}
}
