import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, ScanContext, ScannerOptions } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson, isTestFileForScoring } from '../utils/file-utils';

/**
 * Agent Config Auditor — scans AI Agent platform configuration files
 * for security misconfigurations.
 *
 * Currently supports Tetora format. Designed to be extensible for
 * other agent platforms in the future.
 */

// Config file names we specifically look for
const AGENT_CONFIG_FILENAMES = [
  'tetora.json',
  'claude.json',
  'config.json',
  'config.yaml',
  'config.yml',
  'auth-profiles.json',
];

function isAgentConfigFile(filePath: string): boolean {
  const basename = filePath.split(/[/\\]/).pop() || '';
  return AGENT_CONFIG_FILENAMES.some(name => basename.toLowerCase() === name.toLowerCase());
}

// Loopback addresses considered safe
const LOOPBACK_ADDRESSES = ['127.0.0.1', '::1', 'localhost', 'loopback'];

function isLoopback(addr: string): boolean {
  return LOOPBACK_ADDRESSES.includes(addr.toLowerCase());
}

export const agentConfigAuditor: ScannerModule = {
  name: 'Agent Config Auditor',
  description: 'Audits AI Agent platform configuration files for security misconfigurations (OpenClaw, etc.)',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findConfigFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    // Filter to agent config files only
    const configFiles = files.filter(f => isAgentConfigFile(f));

    for (const file of configFiles) {
      try {
        const content = readFileContent(file);
        let parsed: unknown = null;

        if (isJsonFile(file)) {
          parsed = tryParseJson(content);
        } else if (isYamlFile(file)) {
          parsed = yaml.load(content);
        }

        if (parsed && typeof parsed === 'object') {
          const config = parsed as Record<string, unknown>;
          findings.push(...auditAgentConfig(config, file));
        }
      } catch {
        // Skip unreadable/unparseable files
      }
    }

    // Confidence: definite — config-based findings are concrete
    for (const f of findings) f.confidence = 'definite';

    return {
      scanner: 'Agent Config Auditor',
      findings,
      scannedFiles: configFiles.length,
      duration: Date.now() - start,
    };
  },
};

export function auditAgentConfig(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Check gateway settings
  findings.push(...auditGateway(config, filePath));

  // Check channel settings
  findings.push(...auditChannels(config, filePath));

  // Check for bot tokens in plaintext
  findings.push(...auditBotTokens(config, filePath));

  // Check logging settings
  findings.push(...auditLogging(config, filePath));

  // Check group policy
  findings.push(...auditGroupPolicy(config, filePath));

  return findings;
}

function auditGateway(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const gateway = (config.gateway || config) as Record<string, unknown>;

  // Check bind address
  const bind = gateway.bind as string | undefined;
  if (bind && !isLoopback(bind)) {
    findings.push({
      id: `AC-001-${filePath}`,
      scanner: 'agent-config-auditor',
      severity: 'critical',
      title: 'Gateway exposed to network',
      description: `Gateway is bound to "${bind}" which exposes it beyond localhost. This allows remote access to the agent gateway.`,
      file: filePath,
      recommendation: 'Bind the gateway to 127.0.0.1 or localhost unless network access is explicitly required and secured.',
    });
  }

  // Check for auth settings
  const hasAuth = gateway.token || gateway.password || gateway.auth ||
    gateway.authToken || gateway.apiKey || gateway.secret ||
    (config.auth && typeof config.auth === 'object');
  if (!hasAuth) {
    // Only flag if this looks like a gateway config (has bind, port, or other gateway indicators)
    const hasGatewayIndicators = gateway.bind !== undefined || gateway.port !== undefined ||
      gateway.host !== undefined || config.gateway !== undefined;
    if (hasGatewayIndicators) {
      findings.push({
        id: `AC-002-${filePath}`,
        scanner: 'agent-config-auditor',
        severity: 'critical',
        title: 'No gateway authentication',
        description: 'No authentication (token, password, or auth config) found for the gateway. Anyone with network access can control the agent.',
        file: filePath,
        recommendation: 'Add authentication to the gateway configuration (e.g., token, password, or auth profile).',
      });
    }
  }

  // Check for default port
  const port = gateway.port as number | undefined;
  if (port === 18789) {
    findings.push({
      id: `AC-006-${filePath}`,
      scanner: 'agent-config-auditor',
      severity: 'medium',
      title: 'Using default port',
      description: 'The gateway is using the default port 18789. This makes it easier for attackers to discover the service.',
      file: filePath,
      recommendation: 'Consider using a non-default port to reduce discoverability.',
    });
  }

  return findings;
}

function auditChannels(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Check channels array or object
  const channels = (config.channels || config.channel) as unknown;
  if (channels) {
    const channelList = Array.isArray(channels) ? channels : [channels];

    for (const channel of channelList) {
      if (typeof channel !== 'object' || channel === null) continue;
      const ch = channel as Record<string, unknown>;
      const channelName = (ch.name || ch.type || ch.platform || 'unknown') as string;

      // Skip internal/system channels that don't expose external messaging surfaces
      const internalChannels = ['unknown', 'internal', 'cron', 'subagent', 'system', 'heartbeat'];
      const isInternal = internalChannels.includes(channelName.toLowerCase());

      // Check for allowFrom (only for external-facing channels)
      if (!isInternal && !ch.allowFrom && !ch.allowedUsers && !ch.allowedIds && !ch.whitelist) {
        findings.push({
          id: `AC-003-${filePath}-${channelName}`,
          scanner: 'agent-config-auditor',
          severity: 'critical',
          title: 'No sender restriction on messaging channel',
          description: `Channel "${channelName}" has no allowFrom or sender restriction. Any user can send commands to the agent via this channel.`,
          file: filePath,
          recommendation: 'Add allowFrom, allowedUsers, or whitelist to restrict who can send messages to the agent.',
        });
      }

      // Check DM policy
      const dmPolicy = ch.dmPolicy as string | undefined;
      if (dmPolicy === 'open') {
        findings.push({
          id: `AC-004-${filePath}-${channelName}`,
          scanner: 'agent-config-auditor',
          severity: 'high',
          title: 'DM policy allows anyone to message',
          description: `Channel "${channelName}" has dmPolicy set to "open", allowing any user to DM the agent.`,
          file: filePath,
          recommendation: 'Set dmPolicy to "restricted" or "allowlist" to control who can DM the agent.',
        });
      }

      // Check group policy
      const groupPolicy = ch.groupPolicy as string | undefined;
      if (groupPolicy && groupPolicy !== 'allowlist' && groupPolicy !== 'deny' && groupPolicy !== 'none') {
        findings.push({
          id: `AC-009-${filePath}-${channelName}`,
          scanner: 'agent-config-auditor',
          severity: 'medium',
          title: 'Group policy not restricted',
          description: `Channel "${channelName}" has groupPolicy set to "${groupPolicy}" instead of "allowlist".`,
          file: filePath,
          recommendation: 'Set groupPolicy to "allowlist" to explicitly control which groups the agent participates in.',
        });
      }
    }
  }

  // Also check top-level dmPolicy and allowFrom
  if (config.dmPolicy === 'open') {
    findings.push({
      id: `AC-004-${filePath}-toplevel`,
      scanner: 'agent-config-auditor',
      severity: 'high',
      title: 'DM policy allows anyone to message',
      description: 'Top-level dmPolicy is set to "open", allowing any user to DM the agent.',
      file: filePath,
      recommendation: 'Set dmPolicy to "restricted" or "allowlist" to control who can DM the agent.',
    });
  }

  // Top-level groupPolicy check
  const topGroupPolicy = config.groupPolicy as string | undefined;
  if (topGroupPolicy && topGroupPolicy !== 'allowlist' && topGroupPolicy !== 'deny' && topGroupPolicy !== 'none') {
    findings.push({
      id: `AC-009-${filePath}-toplevel`,
      scanner: 'agent-config-auditor',
      severity: 'medium',
      title: 'Group policy not restricted',
      description: `Top-level groupPolicy is set to "${topGroupPolicy}" instead of "allowlist".`,
      file: filePath,
      recommendation: 'Set groupPolicy to "allowlist" to explicitly control which groups the agent participates in.',
    });
  }

  return findings;
}

function auditBotTokens(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const json = JSON.stringify(config);

  // Check for bot tokens in plaintext
  const botTokenPatterns = [
    { pattern: /\d{8,}:AA[A-Za-z0-9_-]{30,}/, desc: 'Telegram bot token' },
    { pattern: /xoxb-[0-9]{10,}-[A-Za-z0-9]+/, desc: 'Slack bot token' },
    { pattern: /(?:Bot\s+)?[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/, desc: 'Discord bot token' },
  ];

  for (const { pattern, desc } of botTokenPatterns) {
    if (pattern.test(json)) {
      findings.push({
        id: `AC-005-${filePath}-${desc.replace(/\s+/g, '-')}`,
        scanner: 'agent-config-auditor',
        severity: 'high',
        title: 'Bot token in plaintext config',
        description: `A ${desc} was found in plaintext in the configuration file. This token could be extracted by anyone with file access.`,
        file: filePath,
        recommendation: 'Store bot tokens in environment variables or a secret manager, not in config files.',
      });
    }
  }

  // Check for API keys in config
  const apiKeyPatterns = [
    { pattern: /sk-ant-[A-Za-z0-9_-]{20,}/, desc: 'Anthropic API key' },
    { pattern: /sk-proj-[A-Za-z0-9_-]{20,}/, desc: 'OpenAI project key' },
    { pattern: /sk-[A-Za-z0-9]{20,}/, desc: 'OpenAI API key' },
  ];

  for (const { pattern, desc } of apiKeyPatterns) {
    if (pattern.test(json)) {
      findings.push({
        id: `AC-005-${filePath}-${desc.replace(/\s+/g, '-')}`,
        scanner: 'agent-config-auditor',
        severity: 'high',
        title: 'Bot token in plaintext config',
        description: `A ${desc} was found in plaintext in the configuration file.`,
        file: filePath,
        recommendation: 'Store API keys in environment variables or a secret manager, not in config files.',
      });
    }
  }

  return findings;
}

function auditLogging(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Check for logging configuration
  const hasLogging = config.logging || config.log || config.logs || config.logger;
  const hasGatewayIndicators = config.gateway !== undefined || config.bind !== undefined ||
    config.port !== undefined || config.channels !== undefined;

  if (!hasLogging && hasGatewayIndicators) {
    findings.push({
      id: `AC-007-${filePath}`,
      scanner: 'agent-config-auditor',
      severity: 'medium',
      title: 'No logging configured',
      description: 'No logging configuration found. Without logging, security incidents cannot be detected or investigated.',
      file: filePath,
      recommendation: 'Add logging configuration to record agent activities and enable security auditing.',
    });
  }

  // Check for redactSensitive
  if (!config.redactSensitive && hasGatewayIndicators) {
    findings.push({
      id: `AC-008-${filePath}`,
      scanner: 'agent-config-auditor',
      severity: 'medium',
      title: 'Sensitive data not redacted in logs',
      description: 'No redactSensitive setting found. Sensitive data (tokens, keys, passwords) may appear in logs.',
      file: filePath,
      recommendation: 'Set redactSensitive to true to automatically redact sensitive data from logs.',
    });
  }

  return findings;
}

function auditGroupPolicy(config: Record<string, unknown>, filePath: string): Finding[] {
  // Already handled in auditChannels for both channel-level and top-level
  return [];
}
