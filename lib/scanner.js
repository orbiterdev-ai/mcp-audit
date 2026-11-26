/**
 * 10 Deterministic Offline Security Checks for MCP Configurations.
 * Evaluates configs against AUD-01 through AUD-10.
 * Zero network calls.
 */

const { sanitizeText } = require('./sanitizer');

const CHECK_DEFINITIONS = {
  'AUD-01': {
    id: 'AUD-01',
    name: 'Unpinned Package Execution',
    severity: 'HIGH',
    impact: -15,
    description: 'Flags unpinned package executions (npx/uvx/bunx) vulnerable to supply-chain rug-pulls.',
  },
  'AUD-02': {
    id: 'AUD-02',
    name: 'Plaintext Secrets in Config',
    severity: 'CRITICAL',
    impact: -25,
    description: 'Flags hardcoded plaintext API keys and credentials in server env blocks.',
  },
  'AUD-03': {
    id: 'AUD-03',
    name: 'Lethal-Trifecta Topology',
    severity: 'CRITICAL',
    impact: -25,
    description: 'Detects concurrent untrusted input reader + private access + egress sink without approval turnstile.',
  },
  'AUD-04': {
    id: 'AUD-04',
    name: 'Unprotected Agent Lifecycle Hooks',
    severity: 'HIGH',
    impact: -15,
    description: 'Checks if PreToolUse / BeforeTool blocking gates are skipped or missing on shell/SQL mutations.',
  },
  'AUD-05': {
    id: 'AUD-05',
    name: 'Exposed Network Listeners',
    severity: 'CRITICAL',
    impact: -25,
    description: 'Flags SSE or HTTP MCP bindings on 0.0.0.0 or cleartext HTTP without auth headers.',
  },
  'AUD-06': {
    id: 'AUD-06',
    name: 'Shell Injection Arguments',
    severity: 'CRITICAL',
    impact: -25,
    description: 'Detects unescaped shell metacharacters, subshells, or pipes passed inside args.',
  },
  'AUD-07': {
    id: 'AUD-07',
    name: 'Over-Broad Filesystem Mounts',
    severity: 'HIGH',
    impact: -15,
    description: 'Flags root (/) or user home directory mounts when repository-scoped paths suffice.',
  },
  'AUD-08': {
    id: 'AUD-08',
    name: 'Unverified Schema Pinning (tools/list)',
    severity: 'WARN',
    impact: -5,
    description: 'Flags missing SHA-256 schema description hashes across MCP definitions (anti-rug-pull guard).',
  },
  'AUD-09': {
    id: 'AUD-09',
    name: 'Co-Resident Browser OAuth Bypass',
    severity: 'WARN',
    impact: -5,
    description: 'Warns when computer-use or CDP browser automation shares desktop session with OAuth apps.',
  },
  'AUD-10': {
    id: 'AUD-10',
    name: 'Over-Permissive Database Credentials',
    severity: 'HIGH',
    impact: -15,
    description: 'Flags database MCP servers configured with administrative or DDL write credentials.',
  },
};

function runAudit(configData, filePath = 'mcp.json') {
  const findings = [];
  const servers = configData.mcpServers || configData.servers || {};
  const serverEntries = Object.entries(servers);

  // Indicators for AUD-03 Lethal-Trifecta
  let hasUntrustedInput = false;
  let hasPrivateAccess = false;
  let hasEgressOrShell = false;

  for (const [serverName, serverDef] of serverEntries) {
    const cmd = String(serverDef.command || '').toLowerCase();
    const args = Array.isArray(serverDef.args) ? serverDef.args.map(String) : [];
    const env = serverDef.env && typeof serverDef.env === 'object' ? serverDef.env : {};

    // --- AUD-01: Unpinned Package Execution ---
    const isPackageRunner = ['npx', 'uvx', 'bunx', 'pnpm dlx'].some((r) => cmd.includes(r) || args.includes(r));
    if (isPackageRunner) {
      for (const arg of args) {
        if (arg.startsWith('-')) continue;
        const isFilePath =
          arg.startsWith('.') ||
          arg.startsWith('/') ||
          arg.startsWith('\\') ||
          /^[a-zA-Z]:[\\/]/.test(arg) ||
          arg.endsWith('.js') ||
          arg.endsWith('.py') ||
          arg.endsWith('.ts');
        if (isFilePath) continue;

        const isScoped = arg.startsWith('@');
        const hasVersionPin = isScoped ? arg.slice(1).includes('@') : arg.includes('@');
        if (!hasVersionPin) {
          findings.push({
            checkId: 'AUD-01',
            server: serverName,
            file: filePath,
            detail: `Server '${serverName}' invokes unpinned package '${sanitizeText(arg)}'. Supply-chain rug-pull risk.`,
            remediation: `Pin package to exact semver: ${arg}@<version>`,
          });
          break;
        }
      }
    }

    // --- AUD-02: Plaintext Secrets in Config ---
    for (const [envKey, envVal] of Object.entries(env)) {
      const valStr = String(envVal);
      const isEnvRef = valStr.startsWith('${') || valStr.startsWith('$');
      if (!isEnvRef) {
        const isSecretPattern =
          /^(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9_]{36,}|sbp_[a-f0-9]{40}|AKIA[0-9A-Z]{16})$/.test(valStr) ||
          /(?:key|token|secret|password|auth|bearer)/i.test(envKey) && valStr.length >= 16;
        if (isSecretPattern) {
          findings.push({
            checkId: 'AUD-02',
            server: serverName,
            file: filePath,
            detail: `Plaintext credential found in env key '${envKey}' for server '${serverName}'.`,
            remediation: `Move credential to OS SecretStorage / Keychain or reference via \${${envKey}}.`,
          });
        }
      }
    }

    // --- AUD-05: Exposed Network Listeners ---
    const url = serverDef.url || (serverDef.transport === 'sse' ? serverDef.endpoint : null);
    if (url) {
      const urlStr = String(url).toLowerCase();
      if (urlStr.includes('0.0.0.0') || urlStr.startsWith('http://')) {
        const hasAuth = env.AUTH_HEADER || env.AUTHORIZATION || (serverDef.headers && Object.keys(serverDef.headers).length > 0);
        if (!hasAuth || urlStr.startsWith('http://')) {
          findings.push({
            checkId: 'AUD-05',
            server: serverName,
            file: filePath,
            detail: `Server '${serverName}' binds to non-TLS or unauthenticated endpoint '${sanitizeText(urlStr)}'.`,
            remediation: `Enforce TLS 1.3 (https://) and require authenticated authorization headers.`,
          });
        }
      }
    }

    // --- AUD-06: Shell Injection Arguments ---
    for (const arg of args) {
      if (/(&&|\|\||;|`|\$\()/.test(arg)) {
        findings.push({
          checkId: 'AUD-06',
          server: serverName,
          file: filePath,
          detail: `Server '${serverName}' contains shell metacharacters in argument '${sanitizeText(arg)}'.`,
          remediation: `Split arguments into separate array elements without shell subshell syntax.`,
        });
        break;
      }
    }

    // --- AUD-07: Over-Broad Filesystem Mounts ---
    const isFilesystemServer = serverName.toLowerCase().includes('filesystem') || args.some((a) => a.includes('filesystem'));
    if (isFilesystemServer) {
      for (const arg of args) {
        const norm = arg.replace(/\\/g, '/').toLowerCase();
        if (norm === '/' || norm === '~' || norm === '$home' || /^[a-z]:\/?$/i.test(arg) || norm === '/users' || norm === '/home') {
          findings.push({
            checkId: 'AUD-07',
            server: serverName,
            file: filePath,
            detail: `Server '${serverName}' mounts overly broad filesystem root '${sanitizeText(arg)}'.`,
            remediation: `Restrict allowed paths to specific repository subdirectories.`,
          });
          break;
        }
      }
    }

    // --- AUD-08: Unverified Schema Pinning (tools/list) ---
    if (!serverDef.schemaHash && !serverDef.toolsHash && !serverDef.descriptionHash) {
      findings.push({
        checkId: 'AUD-08',
        server: serverName,
        file: filePath,
        detail: `Server '${serverName}' lacks SHA-256 schemaHash pinning for tools/list anti-rug-pull verification.`,
        remediation: `Record canonical SHA-256 tool description hash in server definition schemaHash.`,
      });
    }

    // --- AUD-09: Co-Resident Same-Host Browser OAuth Bypass ---
    const isBrowserServer = ['puppeteer', 'playwright', 'cdp', 'browser', 'computer-use'].some(
      (b) => serverName.toLowerCase().includes(b) || cmd.includes(b) || args.some((a) => a.toLowerCase().includes(b))
    );
    if (isBrowserServer) {
      findings.push({
        checkId: 'AUD-09',
        server: serverName,
        file: filePath,
        detail: `Server '${serverName}' provides browser control on desktop GUI host. Bypasses same-host OAuth prompts.`,
        remediation: `Isolate browser automation into headless container or enforce out-of-band mobile verification.`,
      });
    }

    // --- AUD-10: Over-Permissive Database Credentials ---
    const isDbServer = ['postgres', 'mysql', 'sqlite', 'mariadb', 'supabase'].some(
      (db) => serverName.toLowerCase().includes(db) || cmd.includes(db) || args.some((a) => a.toLowerCase().includes(db))
    );
    if (isDbServer) {
      const allText = (cmd + ' ' + args.join(' ') + ' ' + JSON.stringify(env)).toLowerCase();
      const hasSuperuser = allText.includes('postgres:') || allText.includes('root:') || allText.includes('admin:');
      const hasReadonly = allText.includes('readonly') || allText.includes('read_only');
      if (hasSuperuser || !hasReadonly) {
        findings.push({
          checkId: 'AUD-10',
          server: serverName,
          file: filePath,
          detail: `Database server '${serverName}' lacks read-only connection enforcement or uses admin credentials.`,
          remediation: `Configure read-only credentials or append '?sslmode=require&readonly=true'.`,
        });
      }
    }

    // Taint tracking for AUD-03
    const sName = serverName.toLowerCase();
    if (sName.includes('fetch') || sName.includes('github') || sName.includes('slack') || sName.includes('rss') || sName.includes('issue')) {
      hasUntrustedInput = true;
    }
    if (isFilesystemServer || isDbServer || sName.includes('vault') || sName.includes('secret')) {
      hasPrivateAccess = true;
    }
    if (cmd.includes('bash') || cmd.includes('sh') || cmd.includes('curl') || cmd.includes('ssh') || sName.includes('shell') || sName.includes('terminal')) {
      hasEgressOrShell = true;
    }
  }

  // --- AUD-03: Lethal-Trifecta Topology ---
  if (hasUntrustedInput && hasPrivateAccess && hasEgressOrShell) {
    findings.push({
      checkId: 'AUD-03',
      server: 'all-servers',
      file: filePath,
      detail: `Lethal-Trifecta Topology: untrusted input + private filesystem/DB + shell egress active without approval gate.`,
      remediation: `Enforce out-of-band PreToolUse mobile approvals on shell and external sinks: https://orbiterdev.ai/setup`,
    });
  }

  // --- AUD-04: Unprotected Agent Lifecycle Hooks ---
  const hooksConfig = configData.hooks || (configData.claude && configData.claude.hooks);
  const skipPerms = configData.dangerouslySkipPermissions || (configData.claude && configData.claude.dangerouslySkipPermissions);
  if (skipPerms === true || (!hooksConfig && serverEntries.length > 0 && hasEgressOrShell)) {
    findings.push({
      checkId: 'AUD-04',
      server: 'global',
      file: filePath,
      detail: `AI agent runs without a verified PreToolUse blocking hook or with permissions disabled.`,
      remediation: `Install @orbiterdev/mcp-server native PreToolUse hooks to gate risky actions: https://orbiterdev.ai/setup`,
    });
  }

  // Compute 0-100 Score
  let totalDeductions = 0;
  for (const f of findings) {
    const def = CHECK_DEFINITIONS[f.checkId];
    if (def) {
      totalDeductions += Math.abs(def.impact);
    }
  }

  const score = Math.max(0, 100 - totalDeductions);
  let rating = 'PASS';
  if (score < 40) rating = 'CRITICAL';
  else if (score < 70) rating = 'HIGH';
  else if (score < 90) rating = 'WARN';

  return {
    filePath,
    score,
    rating,
    findings,
    summary: {
      totalServers: serverEntries.length,
      totalFindings: findings.length,
      critical: findings.filter((f) => CHECK_DEFINITIONS[f.checkId]?.severity === 'CRITICAL').length,
      high: findings.filter((f) => CHECK_DEFINITIONS[f.checkId]?.severity === 'HIGH').length,
      warn: findings.filter((f) => CHECK_DEFINITIONS[f.checkId]?.severity === 'WARN').length,
    },
  };
}

module.exports = {
  CHECK_DEFINITIONS,
  runAudit,
};
