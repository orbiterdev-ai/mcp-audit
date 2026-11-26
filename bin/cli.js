#!/usr/bin/env node

/**
 * CLI binary for @orbiterdev/mcp-audit
 * Zero upload, 100% offline MCP security audit.
 */

const fs = require('fs');
const path = require('path');
const {
  auditConfigFile,
  discoverDefaultConfig,
  formatTerminal,
  formatJson,
  formatSarif,
  sanitizeText,
} = require('../lib/index');

function printUsage() {
  console.log(`
@orbiterdev/mcp-audit v1.0.0
Zero-upload 10-check offline MCP Enforcement-Gap & Blast-Radius Auditor.

Usage:
  npx --yes github:orbiterdev-ai/mcp-audit [options] [config-path]
  node bin/cli.js [options] [config-path]

Options:
  --config <path>    Explicit path to mcp.json or claude_desktop_config.json
  --dir <path>       Directory to search for MCP configurations
  --json             Output findings in machine-readable JSON format
  --sarif            Output findings in SARIF 2.1.0 format (GitHub Actions)
  --strict           Exit code 1 if score < 90, any critical/high findings, or 0 configs discovered
  -h, --help         Show this help message
`);
}

function parseArgs(args) {
  let explicitConfigPath = null;
  let explicitDir = null;
  let jsonMode = false;
  let sarifMode = false;
  let strictMode = false;
  let showHelp = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      showHelp = true;
    } else if (arg === '--json') {
      jsonMode = true;
    } else if (arg === '--sarif') {
      sarifMode = true;
    } else if (arg === '--strict') {
      strictMode = true;
    } else if (arg === '--config') {
      if (i + 1 >= args.length || !args[i + 1] || args[i + 1].startsWith('-')) {
        throw new Error('--config requires a file path');
      }
      if (explicitConfigPath !== null) {
        throw new Error('Multiple explicit config paths provided');
      }
      explicitConfigPath = args[++i];
    } else if (arg.startsWith('--config=')) {
      const value = arg.slice('--config='.length);
      if (!value) {
        throw new Error('--config requires a non-empty file path');
      }
      if (explicitConfigPath !== null) {
        throw new Error('Multiple explicit config paths provided');
      }
      explicitConfigPath = value;
    } else if (arg === '--dir') {
      if (i + 1 >= args.length || !args[i + 1] || args[i + 1].startsWith('-')) {
        throw new Error('--dir requires a directory path');
      }
      explicitDir = args[++i];
    } else if (arg.startsWith('--dir=')) {
      const value = arg.slice('--dir='.length);
      if (!value) {
        throw new Error('--dir requires a non-empty directory path');
      }
      explicitDir = value;
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      if (explicitConfigPath !== null) {
        throw new Error(`Unexpected extra positional argument: ${arg}`);
      }
      explicitConfigPath = arg;
    }
  }

  return {
    explicitConfigPath,
    explicitDir,
    jsonMode,
    sarifMode,
    strictMode,
    showHelp,
  };
}

function emitNotEvaluated({ jsonMode, sarifMode, strictMode }) {
  const message = '0 configs discovered (not evaluated).';
  if (jsonMode) {
    console.log(
      JSON.stringify(
        {
          evaluated: false,
          configsEvaluated: 0,
          score: null,
          rating: 'NOT_EVALUATED',
          message,
          remediation: 'Pass --config <path> to audit an explicit MCP configuration file, or see https://orbiterdev.ai/setup to install deterministic PreToolUse hooks.',
          proxyFeedback: 'Want an inline stdio policy wrapper (orbiter wrap -- <server>)? Upvote at https://github.com/orbiterdev-ai/mcp-audit/issues',
        },
        null,
        2
      )
    );
  } else if (sarifMode) {
    console.log(
      JSON.stringify(
        {
          $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
          version: '2.1.0',
          runs: [
            {
              tool: {
                driver: {
                  name: '@orbiterdev/mcp-audit',
                  version: '1.0.0',
                  informationUri: 'https://orbiterdev.ai',
                  rules: [],
                },
              },
              results: [],
              invocations: [
                {
                  executionSuccessful: !strictMode,
                  toolExecutionNotifications: [
                    {
                      level: strictMode ? 'error' : 'note',
                      message: { text: message },
                    },
                  ],
                },
              ],
            },
          ],
        },
        null,
        2
      )
    );
  } else {
    console.log(message);
    console.log('No MCP configuration file detected in target directory or default paths.');
    console.log('Pass --config <path> to audit an explicit file.');
    console.log('\nNext step - Enforce deterministic PreToolUse hooks (iOS & Android biometrics):');
    console.log('  Hosted Remote MCP: https://mcp.orbiterdev.ai/mcp');
    console.log('  Local Hooks Setup: https://orbiterdev.ai/setup');
    console.log('\nWant an inline stdio policy proxy wrapper (orbiter wrap -- <server>)?');
    console.log('  Upvote or request it: https://github.com/orbiterdev-ai/mcp-audit/issues');
  }
}

function main() {
  let parsedArgs;
  try {
    parsedArgs = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`Error: ${sanitizeText(err.message)}`);
    process.exit(2);
  }

  const {
    explicitConfigPath,
    explicitDir,
    jsonMode,
    sarifMode,
    strictMode,
    showHelp,
  } = parsedArgs;

  if (showHelp) {
    printUsage();
    process.exit(0);
  }

  let configPath = null;

  if (explicitConfigPath !== null) {
    const resolvedPath = path.resolve(explicitConfigPath);
    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: Explicit MCP config file not found: ${sanitizeText(explicitConfigPath)}`);
      process.exit(2);
    }
    try {
      const stat = fs.statSync(resolvedPath);
      if (!stat.isFile()) {
        console.error(`Error: Explicit MCP config path is not a file: ${sanitizeText(explicitConfigPath)}`);
        process.exit(2);
      }
      fs.accessSync(resolvedPath, fs.constants.R_OK);
    } catch (err) {
      console.error(`Error: Explicit MCP config file cannot be read (${sanitizeText(explicitConfigPath)}): ${sanitizeText(err.message)}`);
      process.exit(2);
    }
    configPath = resolvedPath;
  } else {
    if (explicitDir !== null) {
      const resolvedDir = path.resolve(explicitDir);
      if (!fs.existsSync(resolvedDir) || !fs.statSync(resolvedDir).isDirectory()) {
        console.error(`Error: Target directory not found or not a directory: ${sanitizeText(explicitDir)}`);
        process.exit(2);
      }
      configPath = discoverDefaultConfig(resolvedDir, { includeHome: false });
    } else {
      configPath = discoverDefaultConfig(process.cwd(), { includeHome: true });
    }

    if (!configPath) {
      emitNotEvaluated({ jsonMode, sarifMode, strictMode });
      process.exit(strictMode ? 1 : 0);
    }
  }

  try {
    const report = auditConfigFile(configPath);

    if (jsonMode) {
      console.log(formatJson(report));
    } else if (sarifMode) {
      console.log(formatSarif(report));
    } else {
      console.log(formatTerminal(report));
    }

    if (strictMode && (report.score < 90 || report.summary.critical > 0 || report.summary.high > 0)) {
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error executing MCP audit: ${sanitizeText(err.message)}`);
    process.exit(2);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  parseArgs,
};
