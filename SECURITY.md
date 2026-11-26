# Security Policy

## Supported Versions

Security updates are provided for the latest release line of `@orbiterdev/mcp-audit`:

| Version | Supported |
|---------|-----------|
| `1.0.x` | Yes |
| `< 1.0.0` | No |

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for security vulnerabilities.

Report suspected security issues privately by emailing **[support@orbiterdev.ai](mailto:support@orbiterdev.ai)** with the subject line `[SECURITY] mcp-audit: <short summary>`.

Include as much of the following as possible:

- Affected version, Node.js runtime, and operating system
- Reproduction steps or minimal sanitized proof-of-concept configuration
- Potential impact and any suggested remediation

## Response SLA

- **Initial acknowledgment:** within 24 business hours
- **Triage and severity confirmation:** within 72 hours
- **Target remediation timelines:**
  - Critical severity: within 7 days
  - High severity: within 14 days
  - Moderate severity: within 30 days
- **Coordinated disclosure:** we coordinate public advisories and credit researchers once a fix is released (unless anonymity is requested).

## Security Architecture & Trust Boundary

`@orbiterdev/mcp-audit` is designed with strict local-only isolation:

- **Zero network egress:** the auditor makes zero outbound HTTP, HTTPS, or socket connections (verified continuously by `test/network_isolation.test.js`).
- **4-layer output redaction:** terminal, JSON, and SARIF outputs sanitize local paths, API tokens, private network IPs, and device serials before display.
- **Out-of-band biometric enforcement boundary:** when paired with Orbiter Dev runtime hooks (`@orbiterdev/mcp-server`), high-risk AI agent actions are evaluated outside the model context window and require explicit out-of-band mobile confirmation (Face ID on iOS or Android biometrics) over TLS before execution proceeds.

## Scope Exclusions

- Findings requiring prior full local workstation compromise by the same OS user
- Denial-of-service against intentionally malformed multi-gigabyte local JSON inputs
- Issues in third-party MCP servers audited by this tool (report those to the respective upstream maintainers)
