/**
 * Generate docs/state.md for sanna-ts (monorepo).
 *
 * Reads sources of truth and writes a deterministic state document.
 * Never hand-edit docs/state.md — regenerate with this script.
 *
 * Usage:
 *   npx tsx tools/generate-state-doc.ts          # regenerate docs/state.md
 *   npx tsx tools/generate-state-doc.ts --check  # exit 1 if docs/state.md is stale
 *
 * SAN-493: state.md header no longer embeds a git SHA. The SHA was always
 * one-commit-stale because regen runs pre-commit (per the sealed-gate
 * pattern, HEAD at regen time is the parent commit). Commit SHAs come from
 * git log; state.md contains only derived state from sources of truth.
 */

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const PACKAGES = ['core', 'cli', 'gateway', 'mcp-server'] as const;
type PackageName = typeof PACKAGES[number];

interface PackageInfo {
  name: string;
  version: string;
  description: string;
  testCount: number;
}

function repoRoot(): string {
  return execSync('git rev-parse --show-toplevel', { encoding: 'utf8' }).trim();
}

function readPackageInfo(root: string, pkg: PackageName): PackageInfo {
  const pkgJson = JSON.parse(
    readFileSync(join(root, 'packages', pkg, 'package.json'), 'utf8')
  ) as Record<string, unknown>;
  const name = typeof pkgJson.name === 'string' ? pkgJson.name : `@sanna-ai/${pkg}`;
  const version = typeof pkgJson.version === 'string' ? pkgJson.version : '(unknown)';
  const description = typeof pkgJson.description === 'string' ? pkgJson.description : '';

  const testFiles = countTestFilesForPackage(root, pkg);

  return { name, version, description, testCount: testFiles };
}

function countTestFilesForPackage(root: string, pkg: PackageName): number {
  try {
    const output = execSync('git ls-files packages/', { cwd: root, encoding: 'utf8' }).trim();
    if (!output) return 0;
    return output
      .split('\n')
      .filter(f => f.startsWith(`packages/${pkg}/`) && (f.endsWith('.test.ts') || f.endsWith('.spec.ts')))
      .length;
  } catch {
    return 0;
  }
}

function countAllTestFiles(root: string): number {
  try {
    const output = execSync('git ls-files packages/', { cwd: root, encoding: 'utf8' }).trim();
    if (!output) return 0;
    return output
      .split('\n')
      .filter(f => f.endsWith('.test.ts') || f.endsWith('.spec.ts'))
      .length;
  } catch {
    return 0;
  }
}

interface ReceiptConstants {
  SPEC_VERSION: string;
  CHECKS_VERSION: string;
  TOOL_VERSION: string;
  TOOL_NAME: string;
}

function readReceiptConstants(root: string): ReceiptConstants {
  const src = readFileSync(join(root, 'packages', 'core', 'src', 'receipt.ts'), 'utf8');
  function extract(name: string): string {
    const m = src.match(new RegExp(`export const ${name}\\s*=\\s*"([^"]+)"`));
    return m ? m[1] : '(unknown)';
  }
  return {
    SPEC_VERSION: extract('SPEC_VERSION'),
    CHECKS_VERSION: extract('CHECKS_VERSION'),
    TOOL_VERSION: extract('TOOL_VERSION'),
    TOOL_NAME: extract('TOOL_NAME'),
  };
}

interface SubmoduleInfo {
  sha: string;
  specFile: string;
}

function readSubmoduleInfo(root: string): SubmoduleInfo {
  let sha = '(unknown)';
  try {
    const out = execSync('git submodule status spec', { cwd: root, encoding: 'utf8' }).trim();
    const m = out.match(/^[\s+-]?([0-9a-f]{40})/);
    if (m) sha = m[1].slice(0, 12);
  } catch {
    // ignore
  }

  let specFile = '(unknown)';
  const specDir = join(root, 'spec', 'spec');
  if (existsSync(specDir)) {
    try {
      const files = execSync('ls', { cwd: specDir, encoding: 'utf8' })
        .split('\n')
        .filter(f => f.match(/sanna-specification-v[\d.]+\.md$/))
        .sort()
        .reverse();
      if (files.length > 0) specFile = files[0];
    } catch {
      // ignore
    }
  }

  return { sha, specFile };
}

function getLatestChangelog(root: string): string {
  const path = join(root, 'CHANGELOG.md');
  if (!existsSync(path)) return '(no CHANGELOG.md)';
  const lines = readFileSync(path, 'utf8').split('\n');
  const entry: string[] = [];
  let inEntry = false;
  for (const line of lines) {
    if (line.startsWith('## ')) {
      if (inEntry) break;
      inEntry = true;
    }
    if (inEntry) entry.push(line);
    if (entry.length >= 10) break;
  }
  return entry.length ? entry.join('\n') : '(no entries found)';
}

function generateBody(root: string): string {
  const packages: Record<PackageName, PackageInfo> = {} as Record<PackageName, PackageInfo>;
  for (const pkg of PACKAGES) {
    packages[pkg] = readPackageInfo(root, pkg);
  }
  const totalTests = countAllTestFiles(root);
  const constants = readReceiptConstants(root);
  const submodule = readSubmoduleInfo(root);
  const changelog = getLatestChangelog(root);

  const pkgRows = PACKAGES.map(pkg => {
    const p = packages[pkg];
    return `| ${p.name} | ${p.version} | ${p.testCount} | ${p.description} |`;
  });

  const sections = [
    '# sanna-ts — State',
    '',
    '## Packages',
    '',
    '| Package | Version | Test Files | Description |',
    '|---|---|---|---|',
    ...pkgRows,
    '',
    `**Aggregate test files:** ${totalTests} (\`packages/*/tests/**/*.test.ts\`)`,
    '',
    '## Receipt Constants (`packages/core/src/receipt.ts`)',
    '',
    '```',
    `SPEC_VERSION   = "${constants.SPEC_VERSION}"`,
    `CHECKS_VERSION = "${constants.CHECKS_VERSION}"`,
    `TOOL_VERSION   = "${constants.TOOL_VERSION}"`,
    `TOOL_NAME      = "${constants.TOOL_NAME}"`,
    '```',
    '',
    '## Spec Submodule (`spec/`)',
    '',
    `Pinned SHA: \`${submodule.sha}\``,
    `Spec file:  \`spec/spec/${submodule.specFile}\``,
    '',
    '## Latest CHANGELOG Entry',
    '',
    changelog,
    '',
  ];
  return sections.join('\n');
}

function generateFull(root: string, timestamp: string): string {
  const header = [
    `<!-- auto-generated by tools/generate-state-doc.ts — do not edit manually -->`,
    `<!-- generated: ${timestamp} -->`,
    '',
    '',
  ].join('\n');
  return header + generateBody(root);
}

function comparable(content: string): string {
  return content
    .split('\n')
    .filter(l => !l.startsWith('<!-- generated:'))
    .join('\n')
    .trim();
}

function isoTimestamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function main(): void {
  const checkMode = process.argv.includes('--check');
  const root = repoRoot();
  const statePath = join(root, 'docs', 'state.md');

  if (checkMode) {
    if (!existsSync(statePath)) {
      process.stderr.write('ERROR: docs/state.md does not exist.\nRun: npx tsx tools/generate-state-doc.ts\n');
      process.exit(1);
    }
    const current = readFileSync(statePath, 'utf8');
    const timestamp = isoTimestamp();
    const fresh = generateFull(root, timestamp);

    if (comparable(current) === comparable(fresh)) {
      process.stdout.write('docs/state.md is up to date.\n');
      process.exit(0);
    }

    process.stderr.write('ERROR: docs/state.md is stale. Regenerate with:\n  npx tsx tools/generate-state-doc.ts\n\n');
    const currentLines = comparable(current).split('\n');
    const freshLines = comparable(fresh).split('\n');
    const maxLines = Math.max(currentLines.length, freshLines.length);
    let shown = 0;
    for (let i = 0; i < maxLines && shown < 40; i++) {
      const a = currentLines[i] ?? '';
      const b = freshLines[i] ?? '';
      if (a !== b) {
        process.stderr.write(`- ${a}\n+ ${b}\n`);
        shown++;
      }
    }
    process.exit(1);
  } else {
    const timestamp = isoTimestamp();
    const content = generateFull(root, timestamp);
    mkdirSync(join(root, 'docs'), { recursive: true });
    writeFileSync(statePath, content, 'utf8');
    const totalTests = countAllTestFiles(root);
    const constants = readReceiptConstants(root);
    process.stdout.write(
      `Generated docs/state.md (tests=${totalTests}, spec_version=${constants.SPEC_VERSION}, tool_version=${constants.TOOL_VERSION})\n`
    );
  }
}

main();
