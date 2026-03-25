import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson, isCacheOrDataFile } from '../utils/file-utils';

export const mcpOAuthAuditor: ScannerModule = {
  name: 'MCP OAuth Auditor',
  description: 'Detects OAuth 2.0 misconfiguration in MCP server configs: unvalidated authorization_server, leaked client_id, open redirect_uri, and insecure token_endpoint',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findConfigFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

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
          const fileFindings = auditOAuthConfig(parsed as Record<string, unknown>, file);
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

    for (const f of findings) f.confidence = 'definite';

    return {
      scanner: 'MCP OAuth Auditor',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

const OAUTH_KEYS = ['authorization_server', 'client_id', 'redirect_uri', 'token_endpoint'];

interface OAuthEntry {
  serverName: string;
  oauth: Record<string, unknown>;
}

export function extractOAuthConfigs(config: Record<string, unknown>): OAuthEntry[] {
  const results: OAuthEntry[] = [];

  const mcpServers = (config.mcpServers || config.mcp_servers) as Record<string, unknown> | undefined;
  if (mcpServers && typeof mcpServers === 'object') {
    for (const [name, entry] of Object.entries(mcpServers)) {
      if (!entry || typeof entry !== 'object') continue;
      const serverEntry = entry as Record<string, unknown>;

      // Check for nested oauth sub-object
      if (serverEntry.oauth && typeof serverEntry.oauth === 'object') {
        results.push({ serverName: name, oauth: serverEntry.oauth as Record<string, unknown> });
      }

      // Check if the server entry itself has OAuth fields directly
      const hasDirectOAuthFields = OAUTH_KEYS.some(k => k in serverEntry);
      if (hasDirectOAuthFields) {
        results.push({ serverName: name, oauth: serverEntry });
      }
    }
  }

  // Top-level oauth block
  if (config.oauth && typeof config.oauth === 'object') {
    results.push({ serverName: '(root)', oauth: config.oauth as Record<string, unknown> });
  }

  return results;
}

function auditOAuthConfig(config: Record<string, unknown>, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const entries = extractOAuthConfigs(config);

  for (const { serverName, oauth } of entries) {
    findings.push(...checkMissingOrInsecureAuthServer(serverName, oauth, filePath));
    findings.push(...checkHardcodedClientId(serverName, oauth, filePath));
    findings.push(...checkPermissiveRedirectUri(serverName, oauth, filePath));
    findings.push(...checkInsecureTokenEndpoint(serverName, oauth, filePath));
  }

  return findings;
}

// MCP-OAUTH-001: authorization_server metadata not validated
function checkMissingOrInsecureAuthServer(
  name: string,
  oauth: Record<string, unknown>,
  filePath?: string,
): Finding[] {
  const findings: Finding[] = [];
  const authServer = oauth['authorization_server'];

  const missing = authServer === undefined || authServer === null || authServer === '';
  const insecureHttp =
    typeof authServer === 'string' && authServer.toLowerCase().startsWith('http://');

  if (missing || insecureHttp) {
    findings.push({
      id: `MCP-OAUTH-001-${name}`,
      scanner: 'mcp-oauth-auditor',
      severity: 'high',
      rule: 'MCP-OAUTH-001',
      title: `Server "${name}" OAuth authorization_server is not configured or uses insecure HTTP`,
      description:
        'OAuth 2.0 server metadata (RFC 8414) must be fetched and verified from a secure HTTPS endpoint. Without this, a malicious server can serve fake metadata to redirect tokens.',
      file: filePath,
      recommendation:
        'Set authorization_server to an HTTPS URL and implement RFC 8414 metadata verification before initiating OAuth flows.',
    });
  }

  return findings;
}

// MCP-OAUTH-002: client_id hardcoded in config
function checkHardcodedClientId(
  name: string,
  oauth: Record<string, unknown>,
  filePath?: string,
): Finding[] {
  const findings: Finding[] = [];
  const clientId = oauth['client_id'];

  if (typeof clientId !== 'string') return findings;

  const isEnvVarRef = clientId.startsWith('${');
  const isEnvVarName = /^[A-Z_][A-Z0-9_]*$/.test(clientId);

  if (!isEnvVarRef && !isEnvVarName) {
    findings.push({
      id: `MCP-OAUTH-002-${name}`,
      scanner: 'mcp-oauth-auditor',
      severity: 'high',
      rule: 'MCP-OAUTH-002',
      title: `Server "${name}" has hardcoded client_id in config`,
      description:
        'client_id is hardcoded as a literal string. While client_id is not a secret, it should be managed via environment variables or a config manager to prevent accidental leakage in version control.',
      file: filePath,
      recommendation:
        'Move client_id to an environment variable reference (e.g., ${OAUTH_CLIENT_ID}) and add the config file to .gitignore.',
    });
  }

  return findings;
}

// MCP-OAUTH-003: redirect_uri uses wildcard or is overly permissive
function checkPermissiveRedirectUri(
  name: string,
  oauth: Record<string, unknown>,
  filePath?: string,
): Finding[] {
  const findings: Finding[] = [];
  const redirectUri = oauth['redirect_uri'];

  if (typeof redirectUri !== 'string') return findings;

  const hasWildcard = redirectUri.includes('*');
  const isLocalhostNoPath = /^https?:\/\/localhost\/?$/.test(redirectUri);

  if (hasWildcard || isLocalhostNoPath) {
    findings.push({
      id: `MCP-OAUTH-003-${name}`,
      scanner: 'mcp-oauth-auditor',
      severity: 'high',
      rule: 'MCP-OAUTH-003',
      title: `Server "${name}" has overly permissive redirect_uri: "${redirectUri}"`,
      description:
        'A wildcard or overly broad redirect_uri allows attackers to redirect OAuth authorization codes to attacker-controlled endpoints, enabling authorization code theft (open redirect / SSRF).',
      file: filePath,
      recommendation:
        'Specify an exact redirect_uri with full path (e.g., http://localhost:8080/callback). Never use wildcards.',
    });
  }

  return findings;
}

// MCP-OAUTH-004: token_endpoint uses HTTP (not HTTPS)
function checkInsecureTokenEndpoint(
  name: string,
  oauth: Record<string, unknown>,
  filePath?: string,
): Finding[] {
  const findings: Finding[] = [];
  const tokenEndpoint = oauth['token_endpoint'];

  if (typeof tokenEndpoint !== 'string') return findings;

  if (tokenEndpoint.toLowerCase().startsWith('http://')) {
    findings.push({
      id: `MCP-OAUTH-004-${name}`,
      scanner: 'mcp-oauth-auditor',
      severity: 'critical',
      rule: 'MCP-OAUTH-004',
      title: `Server "${name}" token_endpoint uses insecure HTTP: "${tokenEndpoint}"`,
      description:
        'Tokens exchanged over HTTP are transmitted in cleartext, exposing them to network interception (MITM attacks). This violates OAuth 2.0 security requirements (RFC 6749 §3.1).',
      file: filePath,
      recommendation:
        'Change token_endpoint to use HTTPS. Never exchange OAuth tokens over unencrypted connections.',
    });
  }

  return findings;
}
