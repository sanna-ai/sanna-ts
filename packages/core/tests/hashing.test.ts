import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { EMPTY_HASH, hashContent, hashBytes, hashObj, canonicalize, normalizeFloats } from "../src/hashing.js";
import { sanitizeForSigning } from "../src/crypto.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const golden = JSON.parse(readFileSync(resolve(FIXTURES, "golden-hashes.json"), "utf-8"));

describe("EMPTY_HASH", () => {
  it("matches SHA-256 of zero bytes", () => {
    expect(EMPTY_HASH).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("matches golden-hashes.json", () => {
    expect(EMPTY_HASH).toBe(golden.EMPTY_HASH);
  });

  it("hashBytes of empty buffer produces EMPTY_HASH", () => {
    expect(hashBytes(Buffer.alloc(0))).toBe(EMPTY_HASH);
  });
});

describe("hashContent", () => {
  it("hashes a known string deterministically", () => {
    const h = hashContent("hello");
    expect(h).toHaveLength(64);
    // SHA-256 of "hello" (already NFC, no trailing ws, no CRLF)
    expect(h).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });

  it("normalizes CRLF line endings", () => {
    expect(hashContent("a\r\nb")).toBe(hashContent("a\nb"));
  });

  it("strips trailing whitespace per line", () => {
    expect(hashContent("a   \nb")).toBe(hashContent("a\nb"));
  });

  it("strips leading/trailing whitespace from the whole string", () => {
    expect(hashContent("  hello  ")).toBe(hashContent("hello"));
  });

  it("supports truncation", () => {
    const h16 = hashContent("hello", 16);
    expect(h16).toHaveLength(16);
    expect(h16).toBe("2cf24dba5fb0a30e");
  });
});

describe("hashObj", () => {
  it("produces deterministic output for nested objects", () => {
    const obj = { z: 1, a: { y: 2, b: 3 } };
    const h1 = hashObj(obj);
    const h2 = hashObj({ a: { b: 3, y: 2 }, z: 1 });
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });

  it("canonicalize sorts keys", () => {
    const c = canonicalize({ z: 1, a: 2 });
    expect(c).toBe('{"a":2,"z":1}');
  });
});

describe("SAN-537: sanitizeForSigning alias identity", () => {
  it("sanitizeForSigning is the canonical normalizeFloats (same callable reference)", () => {
    // ES module re-export creates a binding to the same function object.
    // If a future refactor wraps the alias in a local function, this test
    // fails -- catches the drift-mode where a wrapper silently introduces
    // semantic divergence.
    expect(sanitizeForSigning).toBe(normalizeFloats);
  });
});

describe("constitution content_hash (golden)", () => {
  it("minimal.yaml content_hash is deterministic", () => {
    const content = readFileSync(
      resolve(FIXTURES, "constitutions/minimal.yaml"),
      "utf-8",
    );
    const hash = hashContent(content, 64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    // Verify determinism
    expect(hashContent(content, 64)).toBe(hash);
  });

  it("full-featured.yaml content_hash matches golden", () => {
    const content = readFileSync(
      resolve(FIXTURES, "constitutions/full-featured.yaml"),
      "utf-8",
    );
    const hash = hashContent(content, 64);
    expect(hash).toBe(golden.constitutions["full-featured"].content_hash);
  });
});
