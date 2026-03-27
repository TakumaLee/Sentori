import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, McpServerConfig, McpServerEntry, ScannerOptions } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson, isCacheOrDataFile, isTestFileForScoring } from '../utils/file-utils';
import { DANGEROUS_TOOLS, DANGEROUS_PERMISSIONS } from '../patterns/injection-patterns';

export const mcpConfigAuditor: ScannerModule = {
  name: 'MCP Config Auditor',
  description: 'Audits MCP server configuration files for overly permissive tools, missing access controls, and insecure settings',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findConfigFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    // Skip package manifests and non-agent config files
    const SKIP_PATTERNS = [
      /package\.json$/,
      /tsconfig\.json$/,
      /pubspec\.yaml$/,
      /\.eslintrc/,
      /jest\.config/,
      /release-please/,
      /renovate/,
      /dependabot/,
    ];

    for (const file of files) {
      if (SKIP_PATTERNS.some(p => p.test(file))) continue;

      try {
        const content = readFileContent(file);
        let parsed: unknown = null;

        if (isJsonFile(file)) {
          parsed = tryParseJson(content);
        } else if (isYamlFile(file)) {
          parsed = yaml.load(content);
        }

        if (parsed && typeof parsed === 'object') {
          // Schema gate: skip files that don't look like MCP config at all
          // (no mcpServers/mcp_servers/servers, no tools array, no server/command/env keys)
          const obj = parsed as Record<string, unknown>;
          const hasMcpKeys = obj.mcpServers || obj.mcp_servers || obj.servers;
          const hasToolsArray = Array.isArray(obj.tools);
          const hasConfigKeys = ['server', 'command', 'env', 'endpoint', 'host', 'port']
            .some(k => Object.keys(obj).some(ok => ok.toLowerCase().includes(k)));
          if (!hasMcpKeys && !hasToolsArray && !hasConfigKeys) continue;

          const fileFindings = auditConfig(obj, file);
          // Downgrade findings from cache/data directories to info
          if (isCacheOrDataFile(file)) {
            for (const f of fileFindings) {
              if (f.severity !== 'info') {
                f.severity = 'info';
                f.description += ' [cache/data file — severity reduced]';
              }
            }
          }
          findings.push(...fileFindings);
        }
      } catch {
        // Skip unreadable/unparseable files
      }
    }

    // Confidence: definite — config-based findings are concrete
    for (const f of findings) f.confidence = 'definite';

    return {
      scanner: 'MCP Config Auditor',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

export function auditConfig(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Check if this looks like an MCP config
  const mcpServers = (config.mcpServers || config.mcp_servers || config.servers) as Record<string, McpServerEntry> | undefined;

  if (mcpServers && typeof mcpServers === 'object') {
    for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
      findings.push(...auditServer(serverName, serverConfig, filePath));
    }

    // Chain attack detection: analyze combinations of servers
    findings.push(...auditServerChainAttacks(mcpServers, filePath));
  }

  // Also check top-level for tool configs
  if (config.tools && Array.isArray(config.tools)) {
    findings.push(...auditTools(config.tools, filePath));
  }

  // Check for environment variable exposure
  findings.push(...auditEnvVars(config, filePath));

  // Tool description poisoning detection
  findings.push(...auditToolDescriptionPoisoning(config, filePath));

  return findings;
}

// ============================================================
// CVE-2025-6514: mcp-remote < 0.0.8 SSRF → RCE (CVSS 9.6)
// ============================================================

/**
 * Returns true if the semver string represents a version < 0.0.8.
 * Only handles the 0.0.x range relevant to CVE-2025-6514.
 */
function isVulnerableMcpRemoteVersion(version: string): boolean {
  // Strip any pre-release / build metadata suffixes
  const clean = version.split(/[-+]/)[0];
  const parts = clean.split('.').map(p => parseInt(p, 10));
  if (parts.length < 3 || parts.some(n => isNaN(n))) return false;
  const [major, minor, patch] = parts;
  if (major !== 0 || minor !== 0) return false; // only 0.0.x is affected
  return patch < 8;
}

/**
 * Detects mcp-remote usage vulnerable to CVE-2025-6514.
 * Scans command / args fields of a single McpServerEntry.
 */
function detectCVE20256514(serverName: string, server: McpServerEntry, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const command = (server.command || '').trim();
  const args = ((server.args || []) as unknown[]).filter((a): a is string => typeof a === 'string');

  // Helper to push a critical finding (known vulnerable version)
  const pushCritical = (version: string) => findings.push({
    id: `CVE-2025-6514-${serverName}`,
    scanner: 'mcp-config-auditor',
    severity: 'critical',
    rule: 'CVE-2025-6514',
    title: `Server "${serverName}" uses mcp-remote@${version} — CVSS 9.6 RCE vulnerability (CVE-2025-6514)`,
    description: `mcp-remote@${version} detected — Versions <0.0.8 do not validate OAuth authorization_endpoint, enabling token hijacking and remote code execution.`,
    file: filePath,
    recommendation: 'Upgrade to mcp-remote@0.0.8 or later: npx mcp-remote@latest',
  });

  // Helper to push a high finding (version unconfirmed)
  const pushHighUnknown = () => findings.push({
    id: `CVE-2025-6514-${serverName}-unversioned`,
    scanner: 'mcp-config-auditor',
    severity: 'high',
    rule: 'CVE-2025-6514',
    title: `Server "${serverName}" uses mcp-remote without explicit version — CVE-2025-6514 risk`,
    description: 'Cannot confirm mcp-remote version. Versions <0.0.8 do not validate OAuth authorization_endpoint, enabling token hijacking and remote code execution (CVSS 9.6).',
    file: filePath,
    recommendation: 'Explicitly pin mcp-remote@0.0.8 or later: npx mcp-remote@0.0.8',
  });

  // Case 1: command IS mcp-remote (no explicit version possible from command field alone)
  if (command === 'mcp-remote' || command.endsWith('/mcp-remote') || command.endsWith('\\mcp-remote')) {
    pushHighUnknown();
    return findings;
  }

  // Case 2: npx / bunx / pnpx with mcp-remote in args
  const LAUNCHERS = ['npx', 'bunx', 'pnpx', 'yarn', 'pnpm'];
  if (LAUNCHERS.includes(command) || LAUNCHERS.some(l => command.endsWith('/' + l) || command.endsWith('\\' + l))) {
    for (const arg of args) {
      // Match "mcp-remote" or "mcp-remote@<version>"
      const m = arg.match(/^mcp-remote(?:@(.+))?$/);
      if (!m) continue;

      const version = m[1]; // undefined if no @version
      if (!version || version === 'latest' || version === '*') {
        pushHighUnknown();
      } else if (isVulnerableMcpRemoteVersion(version)) {
        pushCritical(version);
      }
      // version >= 0.0.8 → safe, no finding
      break; // only process first mcp-remote occurrence
    }
  }

  return findings;
}

// ============================================================

function auditServer(name: string, server: McpServerEntry, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // CVE-2025-6514: mcp-remote version check (P0)
  findings.push(...detectCVE20256514(name, server, filePath));

  // Check command for dangerous executables
  if (server.command) {
    const dangerousCmds = ['bash', 'cmd', 'powershell', 'python', 'node', '/bin/sh', '/bin/zsh', 'ruby', 'perl', 'lua', 'deno', 'bun'];
    for (const cmd of dangerousCmds) {
      if (server.command === cmd || server.command.endsWith('/' + cmd)) {
        findings.push({
          id: `MCP-CMD-${name}`,
          scanner: 'mcp-config-auditor',
          severity: 'high',
          title: `Server "${name}" uses potentially dangerous command: ${cmd}`,
          description: `The MCP server "${name}" is configured to run "${server.command}" which could allow arbitrary code execution.`,
          file: filePath,
          recommendation: 'Use specific executables instead of shell interpreters. Restrict the command to the minimum required functionality.',
        });
      }
    }
  }

  // Check args for dangerous flags
  if (server.args && Array.isArray(server.args)) {
    for (const arg of server.args) {
      if (typeof arg === 'string' && (arg.includes('--allow-all') || arg.includes('--no-restrict') || arg.includes('--unsafe'))) {
        findings.push({
          id: `MCP-ARG-${name}-${arg}`,
          scanner: 'mcp-config-auditor',
          severity: 'critical',
          title: `Server "${name}" has unsafe argument: ${arg}`,
          description: `The argument "${arg}" disables security restrictions on server "${name}".`,
          file: filePath,
          recommendation: 'Remove unsafe flags and configure specific permissions instead.',
        });
      }
    }

    // Check for wildcard paths
    for (const arg of server.args) {
      if (typeof arg === 'string' && (arg === '/' || arg === '/*' || arg === '/**' || arg === '*' || arg === 'C:\\')) {
        findings.push({
          id: `MCP-WILDCARD-${name}`,
          scanner: 'mcp-config-auditor',
          severity: 'critical',
          title: `Server "${name}" has wildcard/root path access`,
          description: `The server "${name}" is configured with path "${arg}" which grants access to the entire filesystem.`,
          file: filePath,
          recommendation: 'Restrict path access to specific directories needed by the tool.',
        });
      }
    }
  }

  // Check for missing allowlist/denylist
  if (!server.allowlist && !server.denylist && !server.blockedPaths && !server.allowedPaths) {
    const hasTools = server.tools && Array.isArray(server.tools) && server.tools.length > 0;
    if (hasTools || server.command) {
      findings.push({
        id: `MCP-NOLIST-${name}`,
        scanner: 'mcp-config-auditor',
        severity: 'high',
        title: `Server "${name}" lacks allowlist/denylist`,
        description: `The server "${name}" has no explicit allowlist or denylist configured, meaning all operations may be permitted by default. Without a tool allowlist, the server is vulnerable to tool poisoning attacks (MCP-ITP).`,
        file: filePath,
        recommendation: 'Add allowlist or denylist configuration to restrict permitted operations.',
      });
    }
  }

  // Check env vars for leaked secrets
  if (server.env && typeof server.env === 'object') {
    for (const [key, value] of Object.entries(server.env)) {
      if (typeof value === 'string' && !value.startsWith('${') && !value.startsWith('$')) {
        const secretPatterns = ['key', 'secret', 'token', 'password', 'passwd', 'credential', 'signing', 'private', 'connection', 'database_url', 'connection_string'];
        if (secretPatterns.some(p => key.toLowerCase().includes(p))) {
          findings.push({
            id: `MCP-ENV-${name}-${key}`,
            scanner: 'mcp-config-auditor',
            severity: 'critical',
            title: `Server "${name}" has hardcoded secret in env: ${key}`,
            description: `The environment variable "${key}" appears to contain a hardcoded secret value instead of a reference to a secret store.`,
            file: filePath,
            recommendation: 'Use environment variable references (${VAR}) or a secret manager instead of hardcoded values.',
          });
        }
      }
    }
  }

  // Check tools for dangerous permissions
  if (server.tools && Array.isArray(server.tools)) {
    findings.push(...auditTools(server.tools, filePath, name));
  }

  return findings;
}

function auditTools(tools: unknown[], filePath?: string, serverName?: string): Finding[] {
  const findings: Finding[] = [];
  const prefix = serverName ? `Server "${serverName}" → ` : '';

  for (const tool of tools) {
    if (typeof tool !== 'object' || tool === null) continue;
    const t = tool as Record<string, unknown>;
    const toolName = (t.name as string) || 'unknown';

    // Check if tool name matches dangerous patterns
    for (const dangerous of DANGEROUS_TOOLS) {
      if (toolName.toLowerCase().includes(dangerous)) {
        findings.push({
          id: `MCP-TOOL-${serverName || 'root'}-${toolName}`,
          scanner: 'mcp-config-auditor',
          severity: 'high',
          title: `${prefix}Dangerous tool detected: ${toolName}`,
          description: `The tool "${toolName}" matches dangerous pattern "${dangerous}" and may allow unrestricted system access.`,
          file: filePath,
          recommendation: `Review if tool "${toolName}" is necessary. If so, add strict input validation and scope restrictions.`,
        });
        break;
      }
    }

    // Check permissions
    if (t.permissions && Array.isArray(t.permissions)) {
      for (const perm of t.permissions) {
        if (typeof perm === 'string' && DANGEROUS_PERMISSIONS.includes(perm)) {
          findings.push({
            id: `MCP-PERM-${serverName || 'root'}-${toolName}-${perm}`,
            scanner: 'mcp-config-auditor',
            severity: 'critical',
            title: `${prefix}Tool "${toolName}" has dangerous permission: ${perm}`,
            description: `The permission "${perm}" on tool "${toolName}" grants overly broad access.`,
            file: filePath,
            recommendation: 'Replace wildcard/admin permissions with specific, scoped permissions.',
          });
        }
      }
    }
  }

  return findings;
}

// === Tool Description Poisoning Detection (CRITICAL #1) ===

/** Patterns that indicate hidden instructions in tool descriptions */
const TOOL_DESCRIPTION_POISON_PATTERNS = [
  /\b(?:send|forward|exfiltrate|transmit)\s+(?:to|data\s+to)\b/i,
  /\bread\s+(?:~\/\.ssh|\.env|\/etc\/passwd|credentials?|private\s+key)/i,
  /\b(?:always|must|should)\s+(?:also|first|secretly)\s+(?:execute|run|call|send|read|fetch)/i,
  /\b(?:hidden|secret|invisible)\s+instruction/i,
  /\bwhen\s+(?:you|the\s+user)\s+(?:see|read|receive|ask).*(?:also|secretly|quietly)\b/i,
  /\b(?:do\s+not\s+tell|don'?t\s+mention|keep\s+(?:this\s+)?(?:secret|hidden))\b/i,
  /\b(?:ignore|override|disregard)\s+(?:previous|prior|safety|security|user)\b/i,
  /\b(?:before|after)\s+(?:executing|running|performing).*(?:also|additionally|secretly)\b/i,
  /\bhttps?:\/\/[^\s]+.*(?:exfil|leak|steal|forward|send|post)/i,
  /\b(?:curl|wget|fetch|http\.post|axios\.post)\s+.*(?:secret|token|key|password|env)/i,
  /\b(?:also|and)\s+(?:secretly|quietly|silently)?\s*(?:send|read|forward|exfiltrate|transmit|fetch|post)\b/i,
  /\balso\s+read\s+\/etc\/passwd\b/i,
  /\bsecretly\s+send\b/i,
  /\bsend\s+[^\s]+\s+to\s+[^\s]*(?:\.com|\.net|\.org|\.io)\b/i,
];

export function auditToolDescriptionPoisoning(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const json = JSON.stringify(config);

  // Check all tool descriptions in the config
  const descriptionMatches = json.match(/"description"\s*:\s*"([^"]{20,})"/gi) || [];

  for (const match of descriptionMatches) {
    const descValue = match.replace(/"description"\s*:\s*"/i, '').replace(/"$/, '');
    for (const pattern of TOOL_DESCRIPTION_POISON_PATTERNS) {
      if (pattern.test(descValue)) {
        findings.push({
          id: `MCP-POISON-DESC`,
          scanner: 'mcp-config-auditor',
          severity: 'critical',
          title: 'Suspicious tool description: potential poisoning',
          description: `A tool description contains suspicious patterns that may indicate tool description poisoning: "${descValue.substring(0, 120)}..."`,
          file: filePath,
          recommendation: 'Review all MCP tool descriptions carefully. Tool descriptions should only describe functionality, not contain hidden instructions. See MCP-ITP research for attack details.',
        });
        break; // One finding per description is enough
      }
    }
  }

  return findings;
}

// === MCP Server Chain Attack Detection (CRITICAL #2) ===

/** Server capability categories based on command/name/args */
function classifyServerCapabilities(name: string, server: McpServerEntry): Set<string> {
  const caps = new Set<string>();
  const lowerName = name.toLowerCase();
  const cmd = (server.command || '').toLowerCase();
  const argsStr = (server.args || []).join(' ').toLowerCase();
  const combined = `${lowerName} ${cmd} ${argsStr}`;

  if (/filesystem|file[_-]?system|fs[_-]?server|file[_-]?(?:read|write|access)|directory/i.test(combined)) {
    caps.add('filesystem');
  }
  if (/\bgit\b|github|gitlab|bitbucket/i.test(combined)) {
    caps.add('git');
  }
  if (/\b(?:web[_-]?fetch|browser|puppeteer|playwright|selenium|chromium|http[_-]?client|web[_-]?scrape)/i.test(combined)) {
    caps.add('web');
  }
  if (/\b(?:bash|sh|zsh|cmd|powershell|exec|shell|terminal|subprocess|child_process)\b/i.test(combined)) {
    caps.add('exec');
  }
  if (/\b(?:http|https|webhook|email|smtp|sendgrid|mailgun|ses|fetch|request|network|api[_-]?client)\b/i.test(combined)) {
    caps.add('network');
  }
  if (/\b(?:search|brave|google|bing|duckduckgo|serpapi)\b/i.test(combined)) {
    caps.add('web');
  }

  return caps;
}

function hasPathRestriction(server: McpServerEntry): boolean {
  const argsStr = (server.args || []).join(' ');
  return /--allow[_-]?dir|--root[_-]?dir|--allowed[_-]?path|--sandbox|--restrict/i.test(argsStr) ||
    !!(server.allowedPaths || (server as Record<string, unknown>).rootDir || (server as Record<string, unknown>).sandboxPath);
}

export function auditServerChainAttacks(servers: Record<string, McpServerEntry>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const serverCaps = new Map<string, Set<string>>();

  for (const [name, server] of Object.entries(servers)) {
    serverCaps.set(name, classifyServerCapabilities(name, server));
  }

  // Collect all capabilities across all servers
  const allCaps = new Set<string>();
  for (const caps of serverCaps.values()) {
    for (const c of caps) allCaps.add(c);
  }

  // Rule 1: exec/shell + network → CRITICAL
  if (allCaps.has('exec') && allCaps.has('network')) {
    const execServers = [...serverCaps.entries()].filter(([, c]) => c.has('exec')).map(([n]) => n);
    const netServers = [...serverCaps.entries()].filter(([, c]) => c.has('network')).map(([n]) => n);
    findings.push({
      id: 'MCP-CHAIN-EXEC-NET',
      scanner: 'mcp-config-auditor',
      severity: 'critical',
      title: 'MCP chain attack risk: exec + network servers',
      description: `Servers with exec/shell capability (${execServers.join(', ')}) coexist with network-capable servers (${netServers.join(', ')}). A compromised server could execute arbitrary code and exfiltrate data via the network server.`,
      file: filePath,
      recommendation: 'Avoid combining exec/shell servers with network-capable servers. If necessary, enforce strict sandboxing on exec servers and network allowlists.',
    });
  }

  // Rule 2: filesystem + git → HIGH
  if (allCaps.has('filesystem') && allCaps.has('git')) {
    const fsServers = [...serverCaps.entries()].filter(([, c]) => c.has('filesystem')).map(([n]) => n);
    const gitServers = [...serverCaps.entries()].filter(([, c]) => c.has('git')).map(([n]) => n);

    // Check if filesystem servers have path restrictions
    const unrestricted = fsServers.filter(name => {
      const server = servers[name];
      return !hasPathRestriction(server);
    });

    findings.push({
      id: 'MCP-CHAIN-FS-GIT',
      scanner: 'mcp-config-auditor',
      severity: 'high',
      title: 'MCP chain attack risk: filesystem + git servers',
      description: `Filesystem servers (${fsServers.join(', ')}) coexist with git servers (${gitServers.join(', ')}). A malicious git repository (e.g., poisoned README) could trigger prompt injection that leverages the filesystem server to read/write arbitrary files.${unrestricted.length > 0 ? ` Filesystem servers without path restrictions: ${unrestricted.join(', ')}.` : ''}`,
      file: filePath,
      recommendation: 'Add path restrictions to filesystem servers (--allow-dir). Review git repositories for injection payloads. See CVE-2025-68143/44/45.',
    });
  }

  // Rule 3: filesystem + web/browser → HIGH
  if (allCaps.has('filesystem') && allCaps.has('web')) {
    const fsServers = [...serverCaps.entries()].filter(([, c]) => c.has('filesystem')).map(([n]) => n);
    const webServers = [...serverCaps.entries()].filter(([, c]) => c.has('web')).map(([n]) => n);

    findings.push({
      id: 'MCP-CHAIN-FS-WEB',
      scanner: 'mcp-config-auditor',
      severity: 'high',
      title: 'MCP chain attack risk: filesystem + web servers',
      description: `Filesystem servers (${fsServers.join(', ')}) coexist with web/browser servers (${webServers.join(', ')}). Malicious web content could inject instructions that leverage the filesystem server to read or modify local files.`,
      file: filePath,
      recommendation: 'Add path restrictions to filesystem servers. Implement web content sanitization to strip hidden instructions from fetched content.',
    });
  }

  // Rule 4: filesystem + network (exfiltration channel) → HIGH
  if (allCaps.has('filesystem') && allCaps.has('network')) {
    const fsServers = [...serverCaps.entries()].filter(([, c]) => c.has('filesystem')).map(([n]) => n);
    const netServers = [...serverCaps.entries()].filter(([, c]) => c.has('network')).map(([n]) => n);
    // Only fire if not already covered by exec+network
    if (!allCaps.has('exec')) {
      findings.push({
        id: 'MCP-CHAIN-FS-NET',
        scanner: 'mcp-config-auditor',
        severity: 'high',
        title: 'MCP exfiltration risk: filesystem + network servers',
        description: `Filesystem servers (${fsServers.join(', ')}) coexist with network-capable servers (${netServers.join(', ')}). An attacker could read sensitive files via filesystem server and exfiltrate data via the network server.`,
        file: filePath,
        recommendation: 'Restrict filesystem server paths. Implement network request allowlists. Monitor for unusual file reads followed by network calls.',
      });
    }
  }

  return findings;
}

/**
 * Keys that indicate a file is a real config (server/MCP config) vs data/cache.
 */
const CONFIG_INDICATOR_KEYS = ['server', 'command', 'env', 'mcpServers', 'mcp_servers', 'endpoint', 'host', 'port'];

function looksLikeConfigFile(config: Record<string, unknown>): boolean {
  const keys = Object.keys(config).map(k => k.toLowerCase());
  return CONFIG_INDICATOR_KEYS.some(ck => keys.some(k => k.includes(ck)));
}

function auditEnvVars(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];

  // Recursively search for env-like patterns
  const json = JSON.stringify(config);

  // Check for URLs with credentials
  const urlWithCreds = /https?:\/\/[^:]+:[^@]+@/g;
  if (urlWithCreds.test(json)) {
    // Determine severity based on whether this is a config file or data/cache
    const isConfig = looksLikeConfigFile(config);
    const isCache = filePath ? isCacheOrDataFile(filePath) : false;
    const severity = (isCache || !isConfig) ? 'info' as const : 'critical' as const;
    const suffix = isCache ? ' [cache/data file — severity reduced]' : (!isConfig ? ' [data file — not a config]' : '');

    findings.push({
      id: `MCP-URL-CREDS`,
      scanner: 'mcp-config-auditor',
      severity,
      title: 'URL with embedded credentials detected',
      description: `A URL containing embedded username:password credentials was found in the configuration.${suffix}`,
      file: filePath,
      recommendation: 'Remove credentials from URLs. Use environment variables or a secret manager.',
    });
  }

  return findings;
}
