/**
 * Output Reporters for @orbiterdev/mcp-audit:
 * - Terminal (human table with colors)
 * - JSON
 * - SARIF 2.1.0 (GitHub code scanning format)
 */

const { CHECK_DEFINITIONS } = require('./scanner');
const { sanitizeObject } = require('./sanitizer');

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GRAY = '\x1b[90m';

function formatTerminal(report) {
  const sanitized = sanitizeObject(report);
  const lines = [];

  lines.push(`${BOLD}================================================================${RESET}`);
  lines.push(`${BOLD} @orbiterdev/mcp-audit - Offline Enforcement-Gap & Blast-Radius Auditor v1.0.0${RESET}`);
  lines.push(`${GRAY} Config: ${sanitized.filePath}${RESET}`);
  lines.push(`${BOLD}================================================================${RESET}`);

  let scoreColor = GREEN;
  if (sanitized.score < 40) scoreColor = RED;
  else if (sanitized.score < 70) scoreColor = YELLOW;
  else if (sanitized.score < 90) scoreColor = CYAN;

  lines.push(` Enforcement Score: ${scoreColor}${BOLD}${sanitized.score}/100 [${sanitized.rating}]${RESET}`);
  lines.push(` Servers Scanned: ${sanitized.summary.totalServers} | Findings: ${sanitized.summary.totalFindings} (CRITICAL: ${sanitized.summary.critical}, HIGH: ${sanitized.summary.high}, WARN: ${sanitized.summary.warn})`);
  lines.push('----------------------------------------------------------------');

  if (sanitized.findings.length === 0) {
    lines.push(` ${GREEN}${BOLD}[PASS] All 10 deterministic enforcement-gap & blast-radius checks passed!${RESET}`);
    lines.push(` No unhooked destructive sinks, plaintext env tokens, or Lethal-Trifecta risks detected.`);
  } else {
    for (const finding of sanitized.findings) {
      const def = CHECK_DEFINITIONS[finding.checkId] || { severity: 'WARN' };
      let sevColor = YELLOW;
      if (def.severity === 'CRITICAL') sevColor = RED;
      else if (def.severity === 'HIGH') sevColor = YELLOW;

      lines.push(` [${sevColor}${BOLD}${def.severity}${RESET}] ${BOLD}${finding.checkId} - ${def.name}${RESET}`);
      lines.push(`   Server:   ${finding.server}`);
      lines.push(`   Detail:   ${finding.detail}`);
      lines.push(`   Remedy:   ${CYAN}${finding.remediation}${RESET}`);
      lines.push('');
    }
  }

  lines.push('----------------------------------------------------------------');
  lines.push(`${BOLD}Next step - Enforce deterministic PreToolUse hooks (iOS & Android biometrics):${RESET}`);
  lines.push(`  Hosted Remote MCP: ${CYAN}https://mcp.orbiterdev.ai/mcp${RESET}`);
  lines.push(`  Local Hooks Setup: ${CYAN}https://orbiterdev.ai/setup${RESET}  ${GRAY}(Claude Code, Codex, Antigravity, Gemini CLI)${RESET}`);
  lines.push('');
  lines.push(`${GRAY}Using a hookless MCP client (Cursor, Claude Desktop, Windsurf)?${RESET}`);
  lines.push(`${GRAY}Want an inline stdio policy proxy wrapper (orbiter wrap -- <server>)?${RESET}`);
  lines.push(`  Upvote or request it: ${CYAN}https://github.com/orbiterdev-ai/mcp-audit/issues${RESET}`);
  lines.push(`${BOLD}================================================================${RESET}`);

  return lines.join('\n');
}

function formatJson(report) {
  const sanitized = sanitizeObject(report);
  return JSON.stringify(sanitized, null, 2);
}

function formatSarif(report) {
  const sanitized = sanitizeObject(report);

  const rules = Object.values(CHECK_DEFINITIONS).map((def) => ({
    id: def.id,
    name: def.name.replace(/\s+/g, ''),
    shortDescription: { text: def.name },
    fullDescription: { text: def.description },
    defaultConfiguration: {
      level: def.severity === 'CRITICAL' || def.severity === 'HIGH' ? 'error' : 'warning',
    },
  }));

  const results = sanitized.findings.map((f) => {
    const def = CHECK_DEFINITIONS[f.checkId] || { severity: 'WARN' };
    return {
      ruleId: f.checkId,
      level: def.severity === 'CRITICAL' || def.severity === 'HIGH' ? 'error' : 'warning',
      message: { text: `${f.detail} Remediation: ${f.remediation}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: sanitized.filePath },
          },
        },
      ],
    };
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: '@orbiterdev/mcp-audit',
            version: '1.0.0',
            informationUri: 'https://orbiterdev.ai',
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

module.exports = {
  formatTerminal,
  formatJson,
  formatSarif,
};
