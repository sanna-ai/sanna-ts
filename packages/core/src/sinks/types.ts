/** ReceiptSink — abstract interface for receipt persistence backends. */

export type FailurePolicy = "log_and_continue" | "raise" | "buffer_and_retry";

export interface SinkResult {
  readonly stored: number;
  readonly failed: number;
  readonly errors: readonly string[];
  readonly ok: boolean;
}

export class SinkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SinkError";
  }
}

export interface ReceiptSink {
  store(receipt: Record<string, unknown>): Promise<SinkResult>;
  batchStore(receipts: Record<string, unknown>[]): Promise<SinkResult>;
  flush(): Promise<void>;
  close(): Promise<void>;
}

export function createSinkResult(
  stored: number,
  failed: number,
  errors: readonly string[] = [],
): SinkResult {
  return { stored, failed, errors, ok: failed === 0 };
}
