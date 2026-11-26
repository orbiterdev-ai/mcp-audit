const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseArgs } = require('../bin/cli');

const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'cli.js');

function runCli(args, options = {}) {
  const result = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: options.cwd || process.cwd(),
    env: {
      ...process.env,
      ...(options.env || {}),
    },
    encoding: 'utf8',
    timeout: 15000,
  });
  if (result.error) throw result.error;
  return result;
}

function mkTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('F09 parseArgs: distinguishes explicit --config, positional path, and auto-discovery', () => {
  assert.equal(parseArgs([]).explicitConfigPath, null);
  assert.equal(parseArgs(['--config', 'mcp.json']).explicitConfigPath, 'mcp.json');
  assert.equal(parseArgs(['--config=mcp.json']).explicitConfigPath, 'mcp.json');
  assert.equal(parseArgs(['./custom-mcp.json', '--strict']).explicitConfigPath, './custom-mcp.json');
  assert.throws(() => parseArgs(['--config']), /requires a file path/i);
  assert.throws(() => parseArgs(['--unknown-flag']), /unknown option/i);
});

test('F09 CLI: missing explicit --config fails with exit 2 and emits NO score 100 / PASS', () => {
  const tmpDir = mkTempDir('mcp-audit-f09-missing-');
  const missingPath = path.join(tmpDir, 'does-not-exist.json');

  try {
    for (const extraFlags of [['--strict'], ['--json', '--strict'], ['--sarif', '--strict'], []]) {
      const res = runCli(['--config', missingPath, ...extraFlags], { cwd: tmpDir });
      assert.equal(res.status, 2, `expected exit 2 for flags [${extraFlags.join(' ')}], got ${res.status}`);
      assert.match(res.stderr, /not found/i);
      assert.equal(res.stdout.trim(), '', 'missing explicit config must not emit a passing report');
      assert.doesNotMatch(res.stdout, /\bPASS\b|100/);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('F09 CLI: missing explicit positional path fails with exit 2 and no PASS', () => {
  const tmpDir = mkTempDir('mcp-audit-f09-pos-');
  const missingPath = path.join(tmpDir, 'missing-positional.json');

  try {
    const res = runCli([missingPath, '--strict'], { cwd: tmpDir });
    assert.equal(res.status, 2);
    assert.match(res.stderr, /not found/i);
    assert.equal(res.stdout.trim(), '');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('F09 CLI: empty auto-discovery clearly reports 0 configs discovered (not evaluated) and fails nonzero under --strict', () => {
  const emptyDir = mkTempDir('mcp-audit-f09-empty-');

  try {
    // Non-strict terminal output
    const termRes = runCli(['--dir', emptyDir], { cwd: emptyDir });
    assert.equal(termRes.status, 0);
    assert.match(termRes.stdout, /0 configs discovered \(not evaluated\)/i);
    assert.doesNotMatch(termRes.stdout, /100\/100|\[PASS\]/);

    // Non-strict JSON output
    const jsonRes = runCli(['--dir', emptyDir, '--json'], { cwd: emptyDir });
    assert.equal(jsonRes.status, 0);
    const parsed = JSON.parse(jsonRes.stdout);
    assert.equal(parsed.evaluated, false);
    assert.equal(parsed.configsEvaluated, 0);
    assert.equal(parsed.score, null);
    assert.equal(parsed.rating, 'NOT_EVALUATED');
    assert.match(parsed.message, /0 configs discovered \(not evaluated\)/i);

    // Strict mode MUST fail nonzero when 0 configs are discovered
    const strictRes = runCli(['--dir', emptyDir, '--strict'], { cwd: emptyDir });
    assert.equal(strictRes.status, 1);
    assert.match(strictRes.stdout, /0 configs discovered \(not evaluated\)/i);

    // Strict JSON mode also fails nonzero and preserves NOT_EVALUATED payload
    const strictJsonRes = runCli(['--dir', emptyDir, '--json', '--strict'], { cwd: emptyDir });
    assert.equal(strictJsonRes.status, 1);
    const strictParsed = JSON.parse(strictJsonRes.stdout);
    assert.equal(strictParsed.evaluated, false);
    assert.equal(strictParsed.configsEvaluated, 0);
    assert.equal(strictParsed.rating, 'NOT_EVALUATED');

    // Strict SARIF mode fails nonzero and records executionSuccessful: false
    const strictSarifRes = runCli(['--dir', emptyDir, '--sarif', '--strict'], { cwd: emptyDir });
    assert.equal(strictSarifRes.status, 1);
    const sarif = JSON.parse(strictSarifRes.stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
  } finally {
    fs.rmSync(emptyDir, { recursive: true, force: true });
  }
});

test('F09 CLI: valid clean config passes in --strict mode with 100/PASS and vulnerable config fails with exit 1', () => {
  const tmpDir = mkTempDir('mcp-audit-f09-valid-');
  const cleanFile = path.join(tmpDir, 'clean.mcp.json');
  const riskyFile = path.join(tmpDir, 'risky.mcp.json');

  fs.writeFileSync(
    cleanFile,
    JSON.stringify({
      hooks: { PreToolUse: 'orbiter-approval-gate' },
      mcpServers: {
        secureRepoFs: {
          command: 'node',
          args: ['repo-fs.js', './src'],
          env: { API_KEY: '${API_KEY}' },
          schemaHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
      },
    })
  );

  fs.writeFileSync(
    riskyFile,
    JSON.stringify({
      mcpServers: {
        unpinned: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
        },
      },
    })
  );

  try {
    const cleanRes = runCli(['--config', cleanFile, '--json', '--strict'], { cwd: tmpDir });
    assert.equal(cleanRes.status, 0, cleanRes.stderr);
    const cleanReport = JSON.parse(cleanRes.stdout);
    assert.equal(cleanReport.score, 100);
    assert.equal(cleanReport.rating, 'PASS');
    assert.equal(cleanReport.findings.length, 0);

    const riskyRes = runCli(['--config', riskyFile, '--json', '--strict'], { cwd: tmpDir });
    assert.equal(riskyRes.status, 1);
    const riskyReport = JSON.parse(riskyRes.stdout);
    assert.ok(riskyReport.score < 90);
    assert.ok(riskyReport.findings.length >= 2);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
