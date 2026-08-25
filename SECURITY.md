# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✓                  |
| < 1.0   | ✗                  |

## Reporting a Vulnerability

Please report security vulnerabilities privately. Do **not** open a public issue.

1. Email the maintainer via the address listed in `go.mod` (`github.com/Boreas37/onyx`) or open a **private** security advisory on GitHub: https://github.com/Boreas37/onyx/security/advisories/new
2. Include a minimal reproduction, the onyx version (`onyx version --json`), the Wordfence feed timestamp (`onyx db stats`), and whether `ONYX_DB_PUBKEY` was set.
3. We aim to acknowledge within 72 hours and to ship a fix within 14 days. Until a fix is released, please do not disclose the issue publicly.

## Supply-Chain Hardening

- On `onyx update`, the feed artifact (`wordfence-latest.json.gz`), each delta, the `manifest.json` itself, and the optional `popular.json.gz` / `fingerprints.json.gz` assets are verified with [minisign](https://jedisct1.github.io/minisign/) detached signatures when `ONYX_DB_PUBKEY` is set. A missing or bad signature is a hard error.
- The manifest carries a downgrade guard (`generated_at` monotonicity). Set `ONYX_ALLOW_OLDER_MANIFEST=1` only for intentional rollbacks.
- The database read-index sidecar (`*.idx`) is a local cache: corruption or staleness falls back to the full JSON loader. The HTTP response cache uses `0600`/`0700` permissions.

## Scope

In-scope: the scanner engine, report renderers, update/delta pipeline, credential-auditing probes (`wp-login`, XML-RPC multicall) when run against targets you own.

Out-of-scope: denial-of-service against third-party sites, issues that require a malicious Wordfence mirror *without* `ONYX_DB_PUBKEY` set (TLS-only mode is best-effort).
