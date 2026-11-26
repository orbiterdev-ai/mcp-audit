/**
 * @orbiterdev/mcp-audit entrypoint.
 * Zero-upload offline MCP security scanner.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { runAudit, CHECK_DEFINITIONS } = require('./scanner');
const { formatTerminal, formatJson, formatSarif } = require('./reporters');
const { sanitizeText, sanitizeObject } = require('./sanitizer');

const KNOWN_CONFIG_PATHS = [
  '.cursor/mcp.json',
  '.mcp.json',
  '.claude/settings.json',
  'claude_desktop_config.json',
  'mcp_config.json',
];

function discoverDefaultConfig(targetDir = process.cwd(), options = {}) {
  const includeHome = options.includeHome !== false;

  // Check local project files
  for (const rel of KNOWN_CONFIG_PATHS) {
    const candidate = path.resolve(targetDir, rel);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }

  if (!includeHome) {
    return null;
  }

  // Check user home dir files
  const home = options.homeDir || os.homedir();
  const homeCandidates = [
    path.join(home, '.cursor', 'mcp.json'),
    path.join(home, '.claude.json'),
    path.join(home, '.codex', 'mcp.json'),
    path.join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json'),
    path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  ];

  for (const candidate of homeCandidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }

  return null;
}

function auditConfigFile(configPath) {
  if (!fs.existsSync(configPath)) {
    throw new Error(`MCP config file not found: ${configPath}`);
  }
  const stat = fs.statSync(configPath);
  if (!stat.isFile()) {
    throw new Error(`MCP config path is not a regular file: ${configPath}`);
  }
  const raw = fs.readFileSync(configPath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Failed to parse JSON from ${configPath}: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`MCP config file must contain a JSON object: ${configPath}`);
  }
  return runAudit(parsed, configPath);
}

module.exports = {
  runAudit,
  auditConfigFile,
  discoverDefaultConfig,
  CHECK_DEFINITIONS,
  formatTerminal,
  formatJson,
  formatSarif,
  sanitizeText,
  sanitizeObject,
};
