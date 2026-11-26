# @orbiterdev/mcp-audit

> Zero-upload, 100% offline **Enforcement-Gap & Blast-Radius Auditor** for AI agent MCP and hook configurations (Claude Code, Codex, Antigravity, Gemini CLI, Cursor, and Windsurf).

Part of the **Orbiter Dev** open-core agent safety tooling (Apache-2.0).

> **Distribution status:** Run directly from GitHub via `npx github:orbiterdev-ai/mcp-audit` or clone and run with Node.js (zero dependencies). Publication of `@orbiterdev/mcp-audit` to npmjs.org is queued pending npm registry publishing.

## Why Enforcement-Gap Auditing?

Static signature scanners (such as `mcp-scan`) focus on detecting known prompt-injection patterns inside tool descriptions. `@orbiterdev/mcp-audit` complements signature scanners by auditing **enforcement gaps and blast radius** across your local agent setup:

- **Unhooked destructive MCP servers** (databases, shell sinks, and broad filesystem mounts with no deterministic gate).
- **Missing or disabled lifecycle hooks** (`PreToolUse`, `BeforeTool`, or `dangerouslySkipPermissions: true`).
- **Plaintext `env` tokens and credentials** stored directly inside MCP configuration files.
- **Lethal-trifecta topology** (untrusted input reader + private data access + shell or network egress without an approval gate).
- **Supply-chain drift** (unpinned `npx`/`uvx`/`bunx` runners and missing SHA-256 `tools/list` schema hashes).

## Quickstart

### Run Directly from GitHub via `npx`

```bash
npx --yes github:orbiterdev-ai/mcp-audit
```

Audit an explicit configuration file or fail CI in strict mode:

```bash
npx --yes github:orbiterdev-ai/mcp-audit --config path/to/mcp.json --strict
npx --yes github:orbiterdev-ai/mcp-audit --config path/to/mcp.json --sarif
```

### Run Offline from Source (Zero Dependencies)

```bash
git clone https://github.com/orbiterdev-ai/mcp-audit.git
cd mcp-audit
node bin/cli.js --config path/to/mcp.json --strict
```

### Exit Code Contract (CI-Safe)

- **Explicit `--config <path>` (or positional path) missing or unreadable:** exits immediately with code `2` and emits no passing score.
- **Auto-discovery finds 0 configs:** clearly reports `0 configs discovered (not evaluated)` (never `100/100 PASS`) and exits with code `1` when `--strict` is set.
- **Evaluated config under `--strict`:** exits with code `1` when score < 90 or any CRITICAL/HIGH finding is detected; exits `0` when passing.

## 10 Deterministic Offline Checks

| Check | Severity | Focus |
|---|---|---|
| `AUD-01` | HIGH | **Unpinned Package Execution**: Flags unpinned `npx`/`uvx`/`bunx` packages exposed to supply-chain rug pulls. |
| `AUD-02` | CRITICAL | **Plaintext Secrets in Config**: Flags hardcoded API tokens, private keys, or passwords in MCP `env` blocks. |
| `AUD-03` | CRITICAL | **Lethal-Trifecta Topology**: Detects untrusted input reader + private access + shell/egress sink without an approval gate. |
| `AUD-04` | HIGH | **Unprotected Agent Lifecycle Hooks**: Flags disabled permissions or missing `PreToolUse` / `BeforeTool` blocking gates. |
| `AUD-05` | CRITICAL | **Exposed Network Listeners**: Flags `0.0.0.0` or cleartext HTTP endpoints lacking authentication. |
| `AUD-06` | CRITICAL | **Shell Injection Arguments**: Detects shell subshells, pipes, or metacharacters (`&&`, `;`, `\|`, `$()`). |
| `AUD-07` | HIGH | **Over-Broad Filesystem Mounts**: Flags root `/` or `$HOME` mounts where repository-scoped paths suffice. |
| `AUD-08` | WARN | **Unverified Schema Pinning**: Flags missing SHA-256 schema hashes for `tools/list` rug-pull protection. |
| `AUD-09` | WARN | **Co-Resident Browser OAuth Bypass**: Warns when desktop browser automation shares the GUI session with OAuth apps. |
| `AUD-10` | HIGH | **Over-Permissive DB Credentials**: Flags database connections lacking read-only enforcement or using admin credentials. |

## Privacy & 100% Offline Guarantee

`@orbiterdev/mcp-audit` makes **zero outbound HTTP, HTTPS, or socket calls**. This invariant is enforced in automated tests (`test/network_isolation.test.js`). All inspection runs locally on your machine, and outputs pass through a 4-layer sanitizer that redacts local workstation paths, tokens, device serials, and private network IPs.

## Next-Step Remediation: Enforce vs. Request

Native hooks enforce approval automatically before an action runs in supported agents, while Orbiter's MCP connector lets cloud and business workflows request the same one-tap iOS & Android biometric sign-off where hooks are unavailable.

### 1. Zero-Install Hosted Remote MCP (Claude.ai, n8n, LangGraph, CrewAI)

For cloud and business workflows without local hook harnesses, connect directly via OAuth 2.1 Streamable HTTP:

```text
https://mcp.orbiterdev.ai/mcp
```

### 2. Deterministic Local Lifecycle Hooks (Claude Code, Codex, Antigravity, Gemini CLI)

Build the verified source release from [`orbiterdev-ai/mcp-server`](https://github.com/orbiterdev-ai/mcp-server) to install fail-closed `PreToolUse` / `BeforeTool` / `PermissionRequest` mobile sign-off gates:

```bash
git clone https://github.com/orbiterdev-ai/mcp-server.git
cd mcp-server && npm ci && npm run build
node dist/index.js claude setup
# Also supported: codex setup, antigravity setup, gemini setup
```

Full provider setup commands and policy options: [https://orbiterdev.ai/setup](https://orbiterdev.ai/setup)

**Plans:** Free `€0` (50 approvals/week) | Pro `€19.99/mo` (`€219.99/yr` annual). Requires the free Orbiter Dev mobile app (iOS & Android with Face ID & Android biometrics).

## Want an Inline Stdio Policy Proxy Wrapper (`orbiter wrap`)?

If you use a hookless MCP client (such as Cursor, Claude Desktop, or Windsurf) and want a zero-code stdio wrapper (`orbiter wrap -- <any-mcp-server>`) that pins tool hashes and pauses mutating calls for mobile biometric sign-off, upvote or open a request in GitHub Issues:

- Feedback & demand tracker: [https://github.com/orbiterdev-ai/mcp-audit/issues](https://github.com/orbiterdev-ai/mcp-audit/issues)

---

[Website](https://orbiterdev.ai) | [Setup Guide](https://orbiterdev.ai/setup) | [Documentation](https://orbiterdev.ai/docs) | [Privacy](https://orbiterdev.ai/legal/privacy)
