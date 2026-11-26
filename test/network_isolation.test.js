const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { runAudit } = require('../lib/scanner');
const { formatTerminal, formatJson, formatSarif } = require('../lib/reporters');

test('Network Isolation: Audit execution makes exactly zero network or socket calls', () => {
  let networkAttempted = false;

  // Intercept http.request
  const originalHttpRequest = http.request;
  http.request = function (...args) {
    networkAttempted = true;
    throw new Error('NETWORK_VIOLATION: http.request was called during offline audit');
  };

  // Intercept https.request
  const originalHttpsRequest = https.request;
  https.request = function (...args) {
    networkAttempted = true;
    throw new Error('NETWORK_VIOLATION: https.request was called during offline audit');
  };

  // Intercept net.connect
  const originalNetConnect = net.connect;
  net.connect = function (...args) {
    networkAttempted = true;
    throw new Error('NETWORK_VIOLATION: net.connect was called during offline audit');
  };

  // Intercept global fetch
  const originalFetch = globalThis.fetch;
  globalThis.fetch = function (...args) {
    networkAttempted = true;
    throw new Error('NETWORK_VIOLATION: fetch was called during offline audit');
  };

  try {
    const complexConfig = {
      mcpServers: {
        unpinned: { command: 'npx', args: ['-y', 'server-pkg'] },
        db: { command: 'node', args: ['postgres://admin:pass@remote:5432/db'] },
        fs: { command: 'node', args: ['filesystem', '/'] },
      },
    };

    const report = runAudit(complexConfig, 'test-mcp.json');
    formatTerminal(report);
    formatJson(report);
    formatSarif(report);

    assert.equal(networkAttempted, false, 'Expected zero network egress attempts during audit run');
  } finally {
    // Restore originals
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
    net.connect = originalNetConnect;
    globalThis.fetch = originalFetch;
  }
});
