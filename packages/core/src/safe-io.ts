/**
 * Sanna Protocol — Safe I/O Utilities
 *
 * Atomic file writes, symlink protection, and path validation
 * to prevent common security issues in file operations.
 */

import {
  readFileSync,
  renameSync,
  unlinkSync,
  mkdirSync,
  mkdtempSync,
  chmodSync,
  lstatSync,
  existsSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
} from "node:fs";
import { resolve, dirname, join, relative, sep, parse as parsePath } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import yaml from "js-yaml";

import type { SafeWriteOptions, PathValidationResult } from "./types.js";

// ── Path validation ─────────────────────────────────────────────────

/**
 * Validate that a path does not escape a base directory.
 *
 * Checks for:
 * - Null bytes in path
 * - Path traversal after resolution (resolved path must start with base)
 */
export function validatePath(path: string, baseDir: string): PathValidationResult {
  // Reject null bytes
  if (path.includes("\0")) {
    return {
      valid: false,
      resolved: "",
      error: "Path contains null bytes",
    };
  }

  const resolvedBase = resolve(baseDir);
  const resolvedPath = resolve(resolvedBase, path);

  // Ensure resolved path is within base directory
  const rel = relative(resolvedBase, resolvedPath);
  if (rel.startsWith("..") || resolve(resolvedBase, rel) !== resolvedPath) {
    return {
      valid: false,
      resolved: resolvedPath,
      error: `Path escapes base directory: ${resolvedPath} is not under ${resolvedBase}`,
    };
  }

  return { valid: true, resolved: resolvedPath };
}

// ── Symlink detection ───────────────────────────────────────────────

/**
 * Check if any component in the path is a symlink.
 * Walks each component from root to the final path.
 */
export function isSymlink(path: string): boolean {
  const resolved = resolve(path);
  const { root } = parsePath(resolved);
  const parts = resolved.slice(root.length).split(sep).filter(Boolean);

  let current = root;
  for (const part of parts) {
    current = join(current, part);
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) return true;
    } catch {
      // Component doesn't exist — not a symlink
      break;
    }
  }

  return false;
}

// ── Directory operations ────────────────────────────────────────────

/**
 * Create a directory recursively with the specified permissions.
 */
export function ensureDirectory(path: string, mode: number = 0o755): void {
  mkdirSync(resolve(path), { recursive: true, mode });
}

/**
 * Create a secure temporary directory with restricted permissions (0o700).
 */
export function secureTempDir(prefix: string = "sanna-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  try {
    // Tighten permissions — mkdtempSync may use system default
    chmodSync(dir, 0o700);
  } catch {
    // Some platforms may not support chmod
  }
  return dir;
}

// ── Atomic file writing ─────────────────────────────────────────────

/**
 * Atomically write content to a file via temp file + rename.
 *
 * Steps:
 * 1. Write to path.tmp.{random}
 * 2. fsync the file descriptor
 * 3. Rename temp → target (atomic on POSIX)
 * 4. On failure, clean up the temp file
 *
 * Also rejects symlinks at the target path.
 */
export function safeWriteFile(
  path: string,
  content: string | Buffer,
  options: SafeWriteOptions = {},
): void {
  const mode = options.mode ?? 0o644;
  const doEnsureDir = options.ensureDir ?? true;

  const target = resolve(path);

  // Reject symlinks at target
  if (existsSync(target) && isSymlink(target)) {
    throw new Error(`Refusing to write through symlink: ${target}`);
  }

  // Ensure parent directory exists
  if (doEnsureDir) {
    const dir = dirname(target);
    mkdirSync(dir, { recursive: true });
  }

  const suffix = randomBytes(6).toString("hex");
  const tmpPath = `${target}.tmp.${suffix}`;

  try {
    const data =
      typeof content === "string" ? Buffer.from(content, "utf-8") : content;
    const fd = openSync(tmpPath, "w", mode);
    try {
      writeSync(fd, data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmpPath, target);
  } catch (err) {
    // Clean up temp file on failure
    try {
      unlinkSync(tmpPath);
    } catch {
      // Temp file may not exist
    }
    throw err;
  }
}

/**
 * Atomically write JSON data to a file.
 */
export function safeWriteJson(
  path: string,
  data: unknown,
  options: SafeWriteOptions = {},
): void {
  const json = JSON.stringify(data, null, 2) + "\n";
  safeWriteFile(path, json, options);
}

/**
 * Atomically write YAML data to a file.
 */
export function safeWriteYaml(
  path: string,
  data: unknown,
  options: SafeWriteOptions = {},
): void {
  const yamlStr = yaml.dump(data, {
    lineWidth: -1,
    noRefs: true,
    quotingType: "'",
    forceQuotes: false,
  });
  safeWriteFile(path, yamlStr, options);
}

// ── Safe file reading ───────────────────────────────────────────────

/**
 * Read a file with symlink protection.
 *
 * If baseDir is provided, validates the path doesn't escape it.
 * Rejects paths containing symlinks.
 */
export function safeReadFile(path: string, baseDir?: string): string {
  const target = resolve(path);

  // Validate against base directory if provided
  if (baseDir) {
    const validation = validatePath(path, baseDir);
    if (!validation.valid) {
      throw new Error(`Path validation failed: ${validation.error}`);
    }
  }

  // Reject symlinks
  if (isSymlink(target)) {
    throw new Error(`Refusing to read through symlink: ${target}`);
  }

  return readFileSync(target, "utf-8");
}
