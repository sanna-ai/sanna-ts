# sanna-ts

TypeScript SDK for the [Sanna Protocol](https://github.com/sanna-ai/sanna-protocol) — AI governance with constitution enforcement and cryptographic receipts.

Implements **Sanna Protocol v1.0**.

## Packages

| Package | npm |
|---------|-----|
| [`@sanna/core`](packages/core/) | [![npm](https://img.shields.io/npm/v/@sanna/core)](https://www.npmjs.com/package/@sanna/core) |

## Install

```bash
npm install @sanna/core
```

Requires Node.js 22+ (native Ed25519, zero external crypto dependencies).

## Highlights

- 141 tests across 7 test suites
- Cross-language receipt portability with the [Python SDK](https://github.com/sanna-ai/sanna)
- Ed25519 signing/verification via Node.js native crypto
- RFC 8785 JSON Canonicalization Scheme
- Golden fixture verification against the [protocol spec](https://github.com/sanna-ai/sanna-protocol)

## Related

- [sanna-ai/sanna-protocol](https://github.com/sanna-ai/sanna-protocol) — Protocol specification, schemas, and test fixtures
- [sanna-ai/sanna](https://github.com/sanna-ai/sanna) — Python reference implementation

## License

[AGPL-3.0](LICENSE)
