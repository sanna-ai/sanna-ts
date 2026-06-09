import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { TOOL_VERSION } from "../src/receipt.js";

const pkg = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"),
    "utf8",
  ),
) as { version: string };

describe("version parity (SAN-796; the drift class that bit Python)", () => {
  it("TOOL_VERSION equals @sanna-ai/core package.json version", () => {
    expect(TOOL_VERSION).toBe(pkg.version);
  });
});
