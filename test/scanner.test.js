const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runAudit } = require('../lib/scanner');

test('AUD-01: flags unpinned package execution', () => {
  const config = {
    mcpServers: {
      unpinned: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-01');
  assert.ok(f, 'Should detect unpinned package execution');
  assert.match(f.detail, /unpinned package/);
});

test('AUD-01: allows semver-pinned package', () => {
  const config = {
    mcpServers: {
      pinned: {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem@0.6.2', '/tmp'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-01');
  assert.equal(f, undefined, 'Pinned package should not trigger AUD-01');
});

test('AUD-02: flags plaintext secrets in env', () => {
  const config = {
    mcpServers: {
      withSecret: {
        command: 'node',
        args: ['server.js'],
        env: {
          OPENAI_API_KEY: ['sk', 'proj', 'mock123456789012345678901234567890'].join('-'),
        },
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-02');
  assert.ok(f, 'Should flag plaintext secret key in env');
});

test('AUD-03: detects lethal-trifecta topology', () => {
  const config = {
    mcpServers: {
      githubReader: { command: 'node', args: ['github-fetch.js'] },
      localFilesystem: { command: 'node', args: ['filesystem-server.js'] },
      shellTool: { command: 'bash', args: ['-c', 'run.sh'] },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-03');
  assert.ok(f, 'Should detect lethal trifecta combination');
});

test('AUD-04: flags dangerouslySkipPermissions or missing PreToolUse', () => {
  const config = {
    dangerouslySkipPermissions: true,
    mcpServers: {
      shellServer: { command: 'bash', args: ['run.sh'] },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-04');
  assert.ok(f, 'Should detect disabled permissions');
});

test('AUD-05: flags exposed network listeners on 0.0.0.0 or HTTP', () => {
  const config = {
    mcpServers: {
      remoteSse: {
        transport: 'sse',
        endpoint: 'http://0.0.0.0:8080/sse',
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-05');
  assert.ok(f, 'Should flag 0.0.0.0 unauthenticated HTTP listener');
});

test('AUD-06: flags shell injection characters in args', () => {
  const config = {
    mcpServers: {
      injected: {
        command: 'python',
        args: ['script.py; rm -rf /'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-06');
  assert.ok(f, 'Should flag shell injection metacharacter');
});

test('AUD-07: flags over-broad filesystem root mounts', () => {
  const config = {
    mcpServers: {
      fs: {
        command: 'node',
        args: ['filesystem.js', '/'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-07');
  assert.ok(f, 'Should flag root filesystem mount');
});

test('AUD-08: flags missing schemaHash for tools/list anti-rug-pull verification', () => {
  const config = {
    mcpServers: {
      dynamicTools: {
        command: 'node',
        args: ['tools.js'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-08');
  assert.ok(f, 'Should flag missing schemaHash');
});

test('AUD-09: warns on co-resident browser automation MCP server', () => {
  const config = {
    mcpServers: {
      browserAutomation: {
        command: 'node',
        args: ['puppeteer-server.js'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-09');
  assert.ok(f, 'Should flag co-resident browser automation server');
});

test('AUD-10: flags over-permissive database superuser credentials', () => {
  const config = {
    mcpServers: {
      db: {
        command: 'node',
        args: ['postgres-mcp.js', 'postgres://postgres:password123@localhost:5432/proddb'],
      },
    },
  };
  const report = runAudit(config);
  const f = report.findings.find((x) => x.checkId === 'AUD-10');
  assert.ok(f, 'Should flag superuser database connection');
});

test('Clean config yields 100/100 score and PASS rating', () => {
  const cleanConfig = {
    hooks: {
      PreToolUse: 'orbiter-approval-gate',
    },
    mcpServers: {
      secureRepoFs: {
        command: 'node',
        args: ['repo-fs.js', './src'],
        env: {
          API_KEY: '${API_KEY}',
        },
        schemaHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
    },
  };
  const report = runAudit(cleanConfig);
  assert.equal(report.score, 100);
  assert.equal(report.rating, 'PASS');
  assert.equal(report.findings.length, 0);
});
