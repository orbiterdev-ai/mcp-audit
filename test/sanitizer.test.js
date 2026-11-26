const { test } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeText, sanitizeObject } = require('../lib/sanitizer');

test('Sanitizer: Redacts local filesystem paths', () => {
  const winPath = 'Found vulnerability at C:\\Users\\Developer\\AppData\\mcp.json';
  const macPath = 'Found in /Users/developer/Documents/repo/config.json';

  assert.ok(!sanitizeText(winPath).includes('Developer'));
  assert.ok(!sanitizeText(macPath).includes('developer'));
});

test('Sanitizer: Redacts API tokens and secrets', () => {
  const tok = ['sk', 'proj', 'mock1234567890abcdef1234567890'].join('-');
  const secretText = `Key is ${tok} in env`;
  const sanitized = sanitizeText(secretText);
  assert.ok(!sanitized.includes('mock1234567890abcdef1234567890'));
  assert.match(sanitized, /sk-p\*{4}7890/);
});

test('Sanitizer: Redacts LAN and Tailscale IPs', () => {
  const lanText = 'Server listening on 192.0.2.1 and 198.51.100.1'; // <LAN_IP> <TAILSCALE_IP>
  const sanitized = sanitizeText(lanText);
  assert.ok(!sanitized.includes('192.0.2.1'));
  assert.ok(!sanitized.includes('198.51.100.1'));
  assert.ok(sanitized.includes('<LAN_IP_REDACTED>'));
});

test('Sanitizer: Redacts hardware device serials', () => {
  const serialText = 'Device serial MOCKDEVICE01 connected'; // <DEVICE_SERIAL>
  const sanitized = sanitizeText(serialText);
  assert.ok(!sanitized.includes('MOCKDEVICE01'));
  assert.ok(sanitized.includes('<DEVICE_SERIAL_REDACTED>'));
});

test('Sanitizer: Recursively sanitizes nested objects', () => {
  const nested = {
    path: 'C:\\Users\\Developer\\repo',
    secret: ['ghp', 'mock12345678901234567890123456789012'].join('_'),
    items: ['192.0.2.1', { serial: 'MOCKDEVICE01' }], // <LAN_IP> <DEVICE_SERIAL>
  };
  const sanitized = sanitizeObject(nested);
  assert.ok(!JSON.stringify(sanitized).includes('Developer'));
  assert.ok(!JSON.stringify(sanitized).includes('192.0.2.1'));
  assert.ok(!JSON.stringify(sanitized).includes('MOCKDEVICE01'));
});
