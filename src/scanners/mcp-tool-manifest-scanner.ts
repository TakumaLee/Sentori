/**
 * MCP Tool Manifest Scanner
 *
 * Detects:
 *  1. Tool Redefinition Attack — multiple servers declaring the same tool name
 *  2. Tool Description Injection — hidden prompt injection payloads in tool descriptions
 *  3. Unverified OAuth Endpoint — insecure or suspicious authorization_endpoint URLs
 */

import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, McpServerEntry, ScannerOptions } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson, isCacheOrDataFile } from '../utils/file-utils';

// ============================================================
// Patterns: Tool Description Injection
// ============================================================

const TOOL_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+previous\s+instructions/i,
  /you\s+are\s+now/i,
  /system\s*:/i,
  /\[INST\]/i,
  /exfiltrate/i,
  /send\s+to\s+http/i,
  /fetch.*http.*cookie/i,
  /<\|.*\|>/, // ChatML injection
  // Additional high-signal patterns
  /\bdo\s+not\s+(?:mention|reveal|tell)\b/i,
  /\boverride\s+(?:previous|prior|safety|security)\b/i,
  /\bsecretly\s+(?:send|read|forward|exfiltrate|transmit|fetch|post)\b/i,
  /\bexecute\s+(?:shell|bash|cmd|powershell)\b/i,
  /\bread\s+(?:~\/\.ssh|\.env|\/etc\/passwd|credentials?|private[\s_-]?key)/i,
];

// Suspicious domain fragments for OAuth endpoint checks
const SUSPICIOUS_DOMAIN_FRAGMENTS = [
  'ngrok.io',
  'ngrok-free.app',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '.onion',
  'localtest.me',
  'lvh.me',
  'nip.io',
  'xip.io',
  'attacker',
  'evil',
  'malware',
];

// ============================================================
// Main scanner export
// ============================================================

export const mcpToolManifestScanner: ScannerModule = {
  name: 'MCP Tool Manifest Scanner',
  description: 'Detects tool redefinition attacks, tool description injection, and unverified OAuth endpoints in MCP configurations',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

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

    const files = await findConfigFiles(
      targetPath,
      options?.exclude,
      options?.includeVendored,
      options?.sentoriIgnorePatterns,
    );

    // Collect tool registrations across all config files for cross-file redefinition check
    // Map: toolName → array of { serverName, filePath }
    const globalToolRegistry = new Map<string, Array<{ serverName: string; filePath: string }>>();

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

        if (!parsed || typeof parsed !== 'object') continue;

        const config = parsed as Record<string, unknown>;
        const mcpServers = (config.mcpServers || config.mcp_servers || config.servers) as
          | Record<string, McpServerEntry>
          | undefined;

        if (!mcpServers || typeof mcpServers !== 'object') continue;

        // Per-file: collect tool names and detect injections + OAuth issues
        const fileToolRegistry = new Map<string, string[]>(); // toolName → [serverNames]

        for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
          if (!serverConfig || typeof serverConfig !== 'object') continue;

          // --- Detection 2: Tool Description Injection ---
          const toolsList = serverConfig.tools;
          if (Array.isArray(toolsList)) {
            for (const tool of toolsList) {
              if (!tool || typeof tool !== 'object') continue;
              const t = tool as Record<string, unknown>;
              const toolName = (t.name as string) || 'unknown';
              const description = (t.description as string) || '';

              // Register tool for redefinition tracking (within file)
              if (!fileToolRegistry.has(toolName)) {
                fileToolRegistry.set(toolName, []);
              }
              fileToolRegistry.get(toolName)!.push(serverName);

              // Register globally (cross-file)
              if (!globalToolRegistry.has(toolName)) {
                globalToolRegistry.set(toolName, []);
              }
              globalToolRegistry.get(toolName)!.push({ serverName, filePath: file });

              // Scan description for injection patterns
              if (description) {
                for (const pattern of TOOL_INJECTION_PATTERNS) {
                  if (pattern.test(description)) {
                    const severity = isCacheOrDataFile(file) ? 'info' as const : 'critical' as const;
                    findings.push({
                      id: `TOOL-DESC-INJECT-${serverName}-${toolName}`,
                      scanner: 'mcp-tool-manifest-scanner',
                      severity,
                      rule: 'tool-description-injection',
                      title: `Tool description injection detected: "${toolName}" in server "${serverName}"`,
                      description: `The tool description for "${toolName}" contains a suspicious prompt injection pattern. ` +
                        `Malicious tool descriptions can hijack AI agent behavior at runtime. ` +
                        `Matched: ${pattern.toString()}`,
                      evidence: description.substring(0, 200),
                      file,
                      recommendation:
                        'Audit all tool descriptions from third-party MCP servers. ' +
                        'Tool descriptions should only describe functionality. ' +
                        'Consider using a tool allowlist and description hash pinning.',
                    });
                    break; // One finding per tool
                  }
                }
              }
            }
          }

          // --- Detection 3: Unverified OAuth Endpoint ---
          findings.push(...detectOAuthEndpointIssues(serverName, serverConfig, file));
        }

        // --- Detection 1: Tool Redefinition (within same file) ---
        for (const [toolName, servers] of fileToolRegistry.entries()) {
          if (servers.length > 1) {
            const severity = isCacheOrDataFile(file) ? 'info' as const : 'high' as const;
            findings.push({
              id: `TOOL-REDEF-${toolName}`,
              scanner: 'mcp-tool-manifest-scanner',
              severity,
              rule: 'tool-redefinition-attack',
              title: `Tool redefinition conflict: "${toolName}" declared by multiple servers`,
              description:
                `The tool "${toolName}" is declared by multiple MCP servers in the same config: [${servers.join(', ')}]. ` +
                `A malicious server loaded later can silently shadow a trusted server's tool, ` +
                `intercepting calls and potentially exfiltrating sensitive data.`,
              file,
              recommendation:
                'Ensure each tool name is unique across all MCP servers. ' +
                'Use namespaced tool names (e.g., "serverA__read_file") to avoid collisions. ' +
                'Audit third-party servers before adding them to your config.',
            });
          }
        }
      } catch {
        // Skip unreadable / unparseable files
      }
    }

    // --- Detection 4: Cross-File Tool Redefinition ---
    for (const [toolName, registrations] of globalToolRegistry.entries()) {
      const distinctFiles = [...new Set(registrations.map(r => r.filePath))];
      if (distinctFiles.length > 1) {
        const entries = registrations.map(r => `${r.serverName} (${r.filePath})`).join(', ');
        findings.push({
          id: `TOOL-XFILE-REDEF-${toolName}`,
          scanner: 'mcp-tool-manifest-scanner',
          severity: 'high',
          rule: 'tool-redefinition-attack',
          title: `Cross-file tool redefinition: "${toolName}" declared in multiple config files`,
          description:
            `The tool "${toolName}" is declared across ${distinctFiles.length} separate config files: [${entries}]. ` +
            `A malicious config file loaded later can silently shadow a trusted server's tool, ` +
            `intercepting calls and potentially exfiltrating sensitive data.`,
          file: distinctFiles[0],
          recommendation:
            'Ensure each tool name is unique across all MCP configurations. ' +
            'Use namespaced tool names (e.g., "serverA__read_file") to avoid collisions. ' +
            'Audit third-party config files before merging them into your environment.',
        });
      }
    }

    // All findings have definite confidence (config-based)
    for (const f of findings) f.confidence = 'definite';

    return {
      scanner: 'MCP Tool Manifest Scanner',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

// ============================================================
// Detection 3: Unverified OAuth Endpoint
// ============================================================

const OAUTH_FIELD_NAMES = [
  'authorization_endpoint',
  'authorizationEndpoint',
  'oauth_endpoint',
  'oauthEndpoint',
  'token_endpoint',
  'tokenEndpoint',
  'oauth',
  'auth_url',
  'authUrl',
];

function detectOAuthEndpointIssues(
  serverName: string,
  server: McpServerEntry,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];

  // Flatten the server config to a plain object for easy traversal
  const serverObj = server as Record<string, unknown>;

  for (const field of OAUTH_FIELD_NAMES) {
    const value = serverObj[field];
    if (!value) continue;

    const urls = extractUrls(value);
    for (const url of urls) {
      const finding = assessOAuthUrl(url, serverName, field, filePath);
      if (finding) findings.push(finding);
    }
  }

  // Also check nested oauth/auth config objects
  const nested = serverObj['oauth'] || serverObj['auth'] || serverObj['oidc'];
  if (nested && typeof nested === 'object' && !Array.isArray(nested)) {
    const nestedObj = nested as Record<string, unknown>;
    for (const [key, val] of Object.entries(nestedObj)) {
      if (/endpoint|url|uri/i.test(key)) {
        const urls = extractUrls(val);
        for (const url of urls) {
          const finding = assessOAuthUrl(url, serverName, `oauth.${key}`, filePath);
          if (finding) findings.push(finding);
        }
      }
    }
  }

  return findings;
}

function extractUrls(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}

function assessOAuthUrl(
  url: string,
  serverName: string,
  field: string,
  filePath: string,
): Finding | null {
  // Must look like a URL
  if (!/^https?:\/\//i.test(url)) return null;

  const isHttps = /^https:\/\//i.test(url);
  const isSuspiciousDomain = SUSPICIOUS_DOMAIN_FRAGMENTS.some(frag =>
    url.toLowerCase().includes(frag),
  );

  if (!isHttps) {
    return {
      id: `OAUTH-HTTP-${serverName}-${field}`,
      scanner: 'mcp-tool-manifest-scanner',
      severity: 'high',
      rule: 'unverified-oauth-endpoint',
      title: `Server "${serverName}" uses non-HTTPS OAuth endpoint (${field})`,
      description:
        `The OAuth/authorization endpoint "${url}" on server "${serverName}" uses plain HTTP. ` +
        `This exposes authorization codes and tokens to interception attacks.`,
      evidence: url,
      file: filePath,
      recommendation:
        'Always use HTTPS for OAuth endpoints. HTTP endpoints allow token interception via MITM. ' +
        'See CVE-2025-6514 for related mcp-remote OAuth endpoint vulnerabilities.',
    };
  }

  if (isSuspiciousDomain) {
    return {
      id: `OAUTH-SUSPICIOUS-${serverName}-${field}`,
      scanner: 'mcp-tool-manifest-scanner',
      severity: 'medium',
      rule: 'unverified-oauth-endpoint',
      title: `Server "${serverName}" has suspicious OAuth endpoint domain (${field})`,
      description:
        `The OAuth/authorization endpoint "${url}" on server "${serverName}" points to a ` +
        `potentially suspicious domain. Development/tunnel domains used in production can ` +
        `redirect OAuth tokens to attacker-controlled servers.`,
      evidence: url,
      file: filePath,
      recommendation:
        'Verify the OAuth endpoint domain is trusted and production-grade. ' +
        'Avoid using ngrok, localhost, or other tunnel/dev endpoints in deployed configurations.',
    };
  }

  return null;
}
