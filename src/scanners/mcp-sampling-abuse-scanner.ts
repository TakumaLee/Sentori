/**
 * MCP Sampling Abuse Scanner
 *
 * Detects MCP server configurations that enable unnecessary sampling
 * (server-initiated LLM calls) or lack rate limits on sampling usage.
 *
 * References:
 * - MCP Spec: https://spec.modelcontextprotocol.io/specification/client-features/sampling/
 * - Risk: unrestricted sampling allows servers to make unlimited LLM calls on behalf of users
 */

import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson } from '../utils/file-utils';

const SCANNER_NAME = 'MCP Sampling Abuse Scanner';

export const mcpSamplingAbuseScanner: ScannerModule = {
  name: SCANNER_NAME,
  description: 'Detects unnecessary MCP sampling capability and missing rate limits on server-initiated LLM calls',

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findConfigFiles(targetPath);

    const SKIP_PATTERNS = [
      /package\.json$/,
      /tsconfig\.json$/,
      /jest\.config/,
      /\.eslintrc/,
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
          findings.push(...auditSamplingConfig(parsed as Record<string, unknown>, file));
        }
      } catch {
        // skip unreadable files
      }
    }

    return {
      scanner: SCANNER_NAME,
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

function auditSamplingConfig(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Check mcpServers entries for sampling-related configurations
  const mcpServers = (config['mcpServers'] || config['mcp_servers'] || config['servers']) as Record<string, unknown> | undefined;

  if (mcpServers && typeof mcpServers === 'object') {
    for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
      if (!serverConfig || typeof serverConfig !== 'object') continue;
      findings.push(...auditServerSampling(serverName, serverConfig as Record<string, unknown>, filePath));
    }
  }

  // Also check top-level capabilities (e.g. in MCP server manifest files)
  findings.push(...auditTopLevelCapabilities(config, filePath));

  // Check for alwaysAllow patterns that bypass confirmation for sampling
  findings.push(...auditAlwaysAllowSampling(config, filePath));

  return findings;
}

function auditServerSampling(serverName: string, server: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Check if sampling is explicitly enabled in server config
  const caps = server['capabilities'] as Record<string, unknown> | undefined;
  if (caps && typeof caps === 'object') {
    const hasSampling = 'sampling' in caps;

    if (hasSampling) {
      const samplingConfig = caps['sampling'] as Record<string, unknown> | undefined;

      // Check for rate limit absence
      const hasRateLimit = samplingConfig && (
        'maxRequestsPerMinute' in samplingConfig ||
        'rateLimit' in samplingConfig ||
        'maxCallsPerSession' in samplingConfig ||
        'throttle' in samplingConfig
      );

      if (!hasRateLimit) {
        findings.push({
          id: `MCP-SAMPLING-NOLIMIT-${serverName}`,
          scanner: SCANNER_NAME,
          severity: 'medium',
          rule: 'MCP-SAMPLING-001',
          title: `Server "${serverName}" has sampling enabled without rate limits`,
          description: `The MCP server "${serverName}" advertises sampling capability (server-initiated LLM calls) but no rate limit is configured. Without rate limits, a compromised or malicious server could make unlimited LLM calls, incurring unbounded cost and potentially exfiltrating data.`,
          file: filePath,
          recommendation: 'Add rate limiting to sampling configuration (e.g. maxRequestsPerMinute). Review whether this server actually requires sampling capability.',
        });
      }

      // Check for overly broad model access in sampling
      const modelPrefs = samplingConfig && (samplingConfig['modelPreferences'] || samplingConfig['models']) as unknown;
      if (Array.isArray(modelPrefs) && modelPrefs.includes('*')) {
        findings.push({
          id: `MCP-SAMPLING-WILDCARD-${serverName}`,
          scanner: SCANNER_NAME,
          severity: 'high',
          rule: 'MCP-SAMPLING-002',
          title: `Server "${serverName}" requests wildcard model access for sampling`,
          description: `The MCP server "${serverName}" is configured to use any model ("*") for sampling. This allows the server to invoke the most expensive/capable model available without restriction.`,
          file: filePath,
          recommendation: 'Restrict sampling to specific, appropriate models. Avoid wildcard model access.',
        });
      }
    }
  }

  return findings;
}

function auditTopLevelCapabilities(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // MCP server manifest: top-level capabilities.sampling
  const caps = config['capabilities'] as Record<string, unknown> | undefined;
  if (!caps || typeof caps !== 'object') return findings;

  if (!('sampling' in caps)) return findings;

  const samplingConfig = caps['sampling'] as Record<string, unknown> | undefined;

  // Sampling enabled: emit awareness finding
  findings.push({
    id: 'MCP-SAMPLING-ENABLED',
    scanner: SCANNER_NAME,
    severity: 'info',
    rule: 'MCP-SAMPLING-003',
    title: 'MCP server manifest declares sampling capability',
    description: 'This MCP server manifest declares sampling capability, meaning it can initiate LLM calls on behalf of the user. Ensure this is intentional and that appropriate controls are in place.',
    file: filePath,
    recommendation: 'Verify that sampling is required for this server\'s functionality. Add rate limits, model restrictions, and user confirmation requirements.',
  });

  // Check if human-in-the-loop is bypassed
  const humanInLoop = samplingConfig && samplingConfig['humanInTheLoop'];
  if (humanInLoop === false || humanInLoop === 'never') {
    findings.push({
      id: 'MCP-SAMPLING-NOHUMAN',
      scanner: SCANNER_NAME,
      severity: 'high',
      rule: 'MCP-SAMPLING-004',
      title: 'MCP sampling configured to bypass human confirmation',
      description: 'The server\'s sampling configuration explicitly disables human-in-the-loop review ("humanInTheLoop: never/false"). This allows the server to make LLM calls without user confirmation.',
      file: filePath,
      recommendation: 'Enable human-in-the-loop review for sampling requests, or at minimum for requests involving sensitive data.',
    });
  }

  return findings;
}

function auditAlwaysAllowSampling(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const json = JSON.stringify(config);

  // Detect alwaysAllow arrays containing sampling methods
  if (/"alwaysAllow"\s*:\s*\[/.test(json)) {
    const alwaysAllowMatch = json.match(/"alwaysAllow"\s*:\s*\[([^\]]*)\]/g) || [];
    for (const match of alwaysAllowMatch) {
      if (match.includes('sampling/createMessage') || match.includes('sampling/')) {
        findings.push({
          id: 'MCP-SAMPLING-ALWAYSALLOW',
          scanner: SCANNER_NAME,
          severity: 'high',
          rule: 'MCP-SAMPLING-005',
          title: 'Sampling methods in alwaysAllow — user confirmation bypassed',
          description: 'One or more sampling methods (e.g. sampling/createMessage) are listed in alwaysAllow, bypassing the MCP client\'s user confirmation dialog for server-initiated LLM calls.',
          file: filePath,
          recommendation: 'Remove sampling methods from alwaysAllow. Require explicit user confirmation for every sampling request.',
        });
        break;
      }
    }
  }

  return findings;
}
