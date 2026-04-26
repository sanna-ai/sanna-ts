# sanna-ts — AGENTS.md

AI agent context file (cross-tool standard: Claude Code, Cursor, Codex CLI,
Copilot CLI, Gemini CLI all read this). TypeScript SDK monorepo (4 packages:
core, cli, gateway, mcp-server) implementing the Sanna governance protocol.

## Critical rules

- Never skip hooks (`--no-verify`). On hook failure: diagnose root cause, fix, create a **new** commit — do not amend.
- Never use `git add -f`. If `.gitignore` blocks a file, stop and ask.
- Never force-push. Never push directly to main.
- Never embed notion.so URLs in any committed file (repos are public; reference tickets by ID only: SAN-NNN).
- One branch = one scope. Do not bundle unrelated work in a single branch or PR.
- Never blindly retry or suggest "refresh" — diagnose root cause.
- Trace the full code path (TS → cross-language fixture → Python parity) before proposing a fix.

## Context — read these

- [docs/architecture.md](docs/architecture.md) — monorepo structure, per-package detail, key decisions, security hardening, receipt schema, cross-language compatibility
- [docs/state.md](docs/state.md) — auto-generated: per-package versions, aggregate test count, receipt constants, spec submodule SHA
- [packages/core/package.json](packages/core/package.json) — core package version (source of truth for npm package version)
- [spec/](spec/) — git submodule → sanna-ai/sanna-protocol (golden fixtures, schemas, canonical spec)
- [CHANGELOG.md](CHANGELOG.md) — version history
- `sanna-protocol/docs/decisions/` — ADR records for cross-SDK architectural decisions (bootstrapped in a follow-up PR per SAN-326 sequencing)

## Per-developer notes

For personal scratch (machine-specific paths, WIP rule overrides), use
`CLAUDE.local.md` (gitignored). The committed `AGENTS.md` is the canonical
shared file.
