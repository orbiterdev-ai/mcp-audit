const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runAudit } = require('../lib/scanner');
const { formatTerminal, formatJson, formatSarif } = require('../lib/reporters');

test('Reporters: Terminal reporter formats clean table, enforcement-gap CTA, and proxy feedback link', () => {
  const config = {
    mcpServers: {
      unpinned: { command: 'npx', args: ['-y', 'server'] },
    },
  };
  const report = runAudit(config);
  const terminal = formatTerminal(report);
  assert.ok(terminal.includes('@orbiterdev/mcp-audit'));
  assert.ok(terminal.includes('Enforcement-Gap & Blast-Radius Auditor'));
  assert.ok(terminal.includes('AUD-01'));
  assert.ok(terminal.includes('https://mcp.orbiterdev.ai/mcp'));
  assert.ok(terminal.includes('https://orbiterdev.ai/setup'));
  assert.ok(terminal.includes('orbiter wrap'));
  assert.ok(terminal.includes('https://github.com/orbiterdev-ai/mcp-audit/issues'));
  assert.equal(terminal.includes('\u2014'), false, 'Terminal output must contain zero Unicode em dashes');
});

test('Reporters: JSON reporter produces valid parseable JSON', () => {
  const config = {
    mcpServers: {
      db: { command: 'node', args: ['postgres://admin:pass@remote:5432/db'] },
    },
  };
  const report = runAudit(config);
  const jsonStr = formatJson(report);
  const parsed = JSON.parse(jsonStr);
  assert.equal(typeof parsed.score, 'number');
  assert.ok(Array.isArray(parsed.findings));
});

test('Reporters: SARIF reporter outputs OASIS SARIF 2.1.0 schema', () => {
  const config = {
    mcpServers: {
      bad: { command: 'bash', args: ['-c', 'cat /etc/passwd; rm -rf /'] },
    },
  };
  const report = runAudit(config);
  const sarifStr = formatSarif(report);
  const sarif = JSON.parse(sarifStr);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, '@orbiterdev/mcp-audit');
  assert.ok(sarif.runs[0].results.length > 0);
});
