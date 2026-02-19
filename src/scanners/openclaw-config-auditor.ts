import * as fs from 'fs';
import * as path from 'path';
import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, tryParseJson } from '../utils/file-utils';

/**
 * OpenClaw Config Auditor
 *
 * Scans OpenClaw-specific configuration files for security risks:
 *   1. API key / secret leakage (sk-ant-, sk-proj-, ANTHROPIC_API_KEY, etc.)
 *   2. Overly broad tool permissions (exec security: "full")
 *   3. Unsafe cron payloads (shell injection patterns)
 *   4. Unencrypted channel tokens (Telegram, Discord, Slack in plaintext)
 */

// ─── File name filters ───────────────────────────────────────────────────────

const OPENCLAW_CONFIG_FILENAMES = new Set([
  'openclaw.json',
  'config.json',
  'auth-profiles.json',
  'auth.json',
]);

const OPENCLAW_CRON_FILENAMES = new Set([
  'jobs.json',
]);

function isOpenClawConfigFile(filePath: string): boolean {
  const basename = path.basename(filePath).toLowerCase();
  return OPENCLAW_CONFIG_FILENAMES.has(basename);
}

function isOpenClawCronFile(filePath: string): boolean {
  const basename = path.basename(filePath).toLowerCase();
  // Must be in a cron directory
  return OPENCLAW_CRON_FILENAMES.has(basename) && /[/\\]cron[/\\]/.test(filePath);
}

// ─── API Key Patterns ─────────────────────────────────────────────────────────

interface ApiKeyPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: 'critical' | 'high';
}

const API_KEY_PATTERNS: ApiKeyPattern[] = [
  {
    id: 'OC-001-anthropic-ant',
    label: 'Anthropic API key (sk-ant-)',
    regex: /sk-ant-[A-Za-z0-9_\-]{20,}/,
    severity: 'critical',
  },
  {
    id: 'OC-001-openai-proj',
    label: 'OpenAI project API key (sk-proj-)',
    regex: /sk-proj-[A-Za-z0-9_\-]{20,}/,
    severity: 'critical',
  },
  {
    id: 'OC-001-openai',
    label: 'OpenAI API key (sk-)',
    regex: /(?<![A-Za-z])sk-[A-Za-z0-9]{20,}(?!-ant-|proj-)/,
    severity: 'critical',
  },
  {
    id: 'OC-001-anthropic-env',
    label: 'Anthropic API key (ANTHROPIC_API_KEY env literal)',
    // Matches "ANTHROPIC_API_KEY": "sk-..." or ANTHROPIC_API_KEY=sk-...
    regex: /ANTHROPIC_API_KEY["'\s]*[:=]["'\s]*sk-[A-Za-z0-9_\-]{10,}/,
    severity: 'critical',
  },
  {
    id: 'OC-001-openai-env',
    label: 'OpenAI API key (OPENAI_API_KEY env literal)',
    regex: /OPENAI_API_KEY["'\s]*[:=]["'\s]*sk-[A-Za-z0-9_\-]{10,}/,
    severity: 'critical',
  },
  {
    id: 'OC-001-brave-api',
    label: 'Brave Search API key',
    // Brave keys look like: BSA[A-Za-z0-9]{30+}
    regex: /BSA[A-Za-z0-9_\-]{25,}/,
    severity: 'high',
  },
  {
    id: 'OC-001-google-api',
    label: 'Google API key (AIza...)',
    regex: /AIza[A-Za-z0-9_\-]{30,}/,
    severity: 'high',
  },
  {
    id: 'OC-001-aws-access',
    label: 'AWS Access Key',
    regex: /(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}/,
    severity: 'critical',
  },
];

// ─── Channel Token Patterns ──────────────────────────────────────────────────

interface TokenPattern {
  id: string;
  label: string;
  regex: RegExp;
}

const CHANNEL_TOKEN_PATTERNS: TokenPattern[] = [
  {
    id: 'OC-004-telegram',
    label: 'Telegram Bot Token',
    // Format: 1234567890:AAbbccddee... (10+ digits : AA + 30+ chars)
    regex: /\d{8,}:AA[A-Za-z0-9_\-]{30,}/,
  },
  {
    id: 'OC-004-discord',
    label: 'Discord Bot Token',
    // Discord token: base64.base64.base64 — 3 segments (lengths vary by token type)
    regex: /[A-Za-z0-9_\-]{20,30}\.[A-Za-z0-9_\-]{4,10}\.[A-Za-z0-9_\-]{20,35}/,
  },
  {
    id: 'OC-004-slack',
    label: 'Slack Bot Token (xoxb-)',
    regex: /xoxb-[0-9]{10,}-[A-Za-z0-9]+/,
  },
  {
    id: 'OC-004-slack-user',
    label: 'Slack User Token (xoxp-)',
    regex: /xoxp-[0-9]{10,}-[A-Za-z0-9\-]+/,
  },
];

// ─── Shell Injection Patterns (for cron payloads) ────────────────────────────

const SHELL_INJECTION_PATTERNS: Array<{ id: string; label: string; regex: RegExp; severity: 'critical' | 'high' | 'medium' }> = [
  {
    id: 'OC-003-subshell',
    label: 'Subshell command substitution $(...) in cron payload',
    regex: /\$\([^)]{1,200}\)/,
    severity: 'high',
  },
  {
    id: 'OC-003-backtick',
    label: 'Backtick command substitution in cron payload',
    regex: /`[^`]{1,200}`/,
    severity: 'high',
  },
  {
    id: 'OC-003-semicolon-rm',
    label: 'Dangerous command chaining with rm in cron payload',
    regex: /;\s*rm\s+-[rf]{1,2}/,
    severity: 'critical',
  },
  {
    id: 'OC-003-redirection',
    label: 'Shell output redirection to sensitive paths in cron payload',
    // e.g. > /etc/passwd or >> ~/.ssh/authorized_keys
    regex: />>?\s*(?:\/etc\/|~\/\.ssh\/|\/root\/|\/proc\/)/,
    severity: 'critical',
  },
  {
    id: 'OC-003-curl-pipe',
    label: 'Curl/wget pipe to shell in cron payload',
    regex: /(?:curl|wget)\s[^\n]*\|\s*(?:bash|sh|zsh|python|ruby|node)/,
    severity: 'critical',
  },
  {
    id: 'OC-003-eval',
    label: 'eval of external input in cron payload',
    regex: /\beval\s*\(/,
    severity: 'high',
  },
  {
    id: 'OC-003-env-exfil',
    label: 'Potential env variable exfiltration in cron payload',
    // e.g. $HOME, $PATH etc. in curl/wget context
    regex: /(?:curl|wget|fetch)\s[^\n]*\$(?:HOME|PATH|USER|SHELL|LOGNAME|[A-Z_]{4,})/,
    severity: 'high',
  },
];

// ─── Main Scanner ─────────────────────────────────────────────────────────────

export const openclawConfigAuditor: ScannerModule = {
  name: 'OpenClaw Config Auditor',
  description: 'Scans OpenClaw agent config files for API key leakage, overly broad tool permissions, unsafe cron payloads, and unencrypted channel tokens',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // 1. Collect files to scan from the target path
    const allFiles = await findConfigFiles(targetPath, options?.exclude, options?.includeVendored, options?.agentshieldIgnorePatterns);

    const configFiles = allFiles.filter(f => isOpenClawConfigFile(f));
    const cronFiles = allFiles.filter(f => isOpenClawCronFile(f));

    // 2. Also include ~/.openclaw/openclaw.json and ~/.openclaw/cron/jobs.json
    //    if the target path is NOT already the openclaw directory
    const homedir = process.env.HOME || process.env.USERPROFILE || '';
    const openclawDir = path.join(homedir, '.openclaw');
    const wellKnownConfig = path.join(openclawDir, 'openclaw.json');
    const wellKnownCron = path.join(openclawDir, 'cron', 'jobs.json');
    const wellKnownAuthProfiles = path.join(openclawDir, 'agents', 'main', 'agent', 'auth-profiles.json');

    const extraConfigs: string[] = [];
    const extraCrons: string[] = [];

    if (!targetPath.startsWith(openclawDir)) {
      if (fs.existsSync(wellKnownConfig) && !configFiles.includes(wellKnownConfig)) {
        extraConfigs.push(wellKnownConfig);
      }
      if (fs.existsSync(wellKnownAuthProfiles) && !configFiles.includes(wellKnownAuthProfiles)) {
        extraConfigs.push(wellKnownAuthProfiles);
      }
      if (fs.existsSync(wellKnownCron) && !cronFiles.includes(wellKnownCron)) {
        extraCrons.push(wellKnownCron);
      }
    }

    const allConfigFiles = [...configFiles, ...extraConfigs];
    const allCronFiles = [...cronFiles, ...extraCrons];

    // 3. Audit config files
    for (const file of allConfigFiles) {
      try {
        const content = readFileContent(file);
        if (isJsonFile(file)) {
          const parsed = tryParseJson(content);
          if (parsed && typeof parsed === 'object') {
            findings.push(...auditApiKeys(content, file));
            findings.push(...auditToolPermissions(parsed as Record<string, unknown>, file));
            findings.push(...auditChannelTokens(content, file));
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    // 4. Audit cron files
    for (const file of allCronFiles) {
      try {
        const content = readFileContent(file);
        if (isJsonFile(file)) {
          const parsed = tryParseJson(content);
          if (parsed && typeof parsed === 'object') {
            findings.push(...auditCronPayloads(parsed as Record<string, unknown>, file));
            // Also check cron file for channel tokens (delivery tokens)
            findings.push(...auditChannelTokens(content, file));
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    // 5. Deduplicate by (id, file)
    const seen = new Set<string>();
    const deduped = findings.filter(f => {
      const key = `${f.id}::${f.file}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // All config-based findings are definite
    for (const f of deduped) f.confidence = 'definite';

    return {
      scanner: 'OpenClaw Config Auditor',
      findings: deduped,
      scannedFiles: allConfigFiles.length + allCronFiles.length,
      duration: Date.now() - start,
    };
  },
};

// ─── API Key Detection ────────────────────────────────────────────────────────

export function auditApiKeys(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of API_KEY_PATTERNS) {
    if (pattern.regex.test(content)) {
      // Extract a snippet (mask the key)
      const match = content.match(pattern.regex);
      const snippet = match ? maskSecret(match[0]) : '(detected)';

      findings.push({
        id: pattern.id,
        scanner: 'openclaw-config-auditor',
        severity: pattern.severity,
        title: `Hardcoded ${pattern.label} detected in config`,
        description: `A ${pattern.label} was found directly in the configuration file: ${snippet}. Hardcoded secrets can be extracted by anyone with file access or who compromises the file.`,
        file: filePath,
        recommendation: 'Remove API keys from config files. Use environment variables (process.env.API_KEY) or a secure secrets manager. Reference keys by variable name rather than value.',
      });
    }
  }

  return findings;
}

function maskSecret(s: string): string {
  if (s.length <= 8) return '****';
  return s.substring(0, 6) + '...' + s.substring(s.length - 4);
}

// ─── Tool Permission Detection ────────────────────────────────────────────────

export function auditToolPermissions(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Check exec tool security level
  const tools = config.tools as Record<string, unknown> | undefined;
  if (tools && typeof tools === 'object') {
    findings.push(...checkToolsSecurity(tools, filePath, 'tools'));
  }

  // Check per-agent tool overrides
  const agents = config.agents as Record<string, unknown> | undefined;
  if (agents && typeof agents === 'object') {
    for (const [agentName, agentConfig] of Object.entries(agents)) {
      if (typeof agentConfig !== 'object' || agentConfig === null) continue;
      const agentTools = (agentConfig as Record<string, unknown>).tools as Record<string, unknown> | undefined;
      if (agentTools) {
        findings.push(...checkToolsSecurity(agentTools, filePath, `agents.${agentName}.tools`));
      }
    }
  }

  // Check for mcpServers with full access (tool-level security override)
  const mcpServers = (config.mcpServers || config.mcp_servers) as Record<string, unknown> | undefined;
  if (mcpServers && typeof mcpServers === 'object') {
    for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
      if (typeof serverConfig !== 'object' || serverConfig === null) continue;
      const sc = serverConfig as Record<string, unknown>;
      if (sc.security === 'full') {
        findings.push({
          id: `OC-002-mcp-full-${serverName}`,
          scanner: 'openclaw-config-auditor',
          severity: 'high',
          title: `MCP server "${serverName}" has unrestricted security mode`,
          description: `The MCP server "${serverName}" is configured with security: "full", which grants the agent unrestricted tool access. This expands the attack surface significantly.`,
          file: filePath,
          recommendation: 'Change security from "full" to "allowlist" and explicitly list the tools/operations the agent needs.',
        });
      }
    }
  }

  return findings;
}

function checkToolsSecurity(
  tools: Record<string, unknown>,
  filePath: string,
  toolPath: string
): Finding[] {
  const findings: Finding[] = [];

  // Check exec security setting
  const exec = tools.exec as Record<string, unknown> | undefined;
  if (exec && typeof exec === 'object') {
    const security = exec.security as string | undefined;
    if (security === 'full') {
      findings.push({
        id: `OC-002-exec-full`,
        scanner: 'openclaw-config-auditor',
        severity: 'high',
        title: 'Exec tool has unrestricted security mode (security: "full")',
        description: `The exec tool at "${toolPath}.exec" is configured with security: "full", granting the agent unrestricted shell command execution. If the agent is compromised or manipulated, this allows arbitrary code execution on the host.`,
        file: filePath,
        recommendation: 'Change exec.security from "full" to "allowlist" and define an explicit allowlist of permitted commands. Consider using "deny" mode for high-risk commands.',
      });
    }

    // Also check for wildcard allowlist
    const allowlist = exec.allowlist as unknown[] | undefined;
    if (Array.isArray(allowlist) && allowlist.includes('*')) {
      findings.push({
        id: `OC-002-exec-wildcard`,
        scanner: 'openclaw-config-auditor',
        severity: 'high',
        title: 'Exec tool allowlist contains wildcard (*)',
        description: `The exec tool at "${toolPath}.exec" has a wildcard "*" in its allowlist, which effectively grants unrestricted command execution.`,
        file: filePath,
        recommendation: 'Replace the wildcard with an explicit list of permitted commands.',
      });
    }
  }

  // Check browser tool security
  const browser = tools.browser as Record<string, unknown> | undefined;
  if (browser && typeof browser === 'object') {
    const security = browser.security as string | undefined;
    if (security === 'full') {
      findings.push({
        id: `OC-002-browser-full`,
        scanner: 'openclaw-config-auditor',
        severity: 'medium',
        title: 'Browser tool has unrestricted security mode',
        description: `The browser tool at "${toolPath}.browser" is configured with security: "full". This allows unrestricted web browsing which increases the prompt injection attack surface.`,
        file: filePath,
        recommendation: 'Consider restricting browser access to a domain allowlist or setting security to "allowlist".',
      });
    }
  }

  // Check top-level security field
  const topSecurity = tools.security as string | undefined;
  if (topSecurity === 'full') {
    findings.push({
      id: `OC-002-tools-full`,
      scanner: 'openclaw-config-auditor',
      severity: 'high',
      title: `Tool security set to "full" at ${toolPath}`,
      description: `The tools section at "${toolPath}" has security: "full" which grants unrestricted access to all tool capabilities.`,
      file: filePath,
      recommendation: 'Set security to "allowlist" and enumerate the specific tool capabilities required.',
    });
  }

  return findings;
}

// ─── Cron Payload Injection Detection ────────────────────────────────────────

export function auditCronPayloads(config: Record<string, unknown>, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Handle both jobs array (cron/jobs.json) and top-level cron config
  const jobs = extractCronJobs(config);

  for (const job of jobs) {
    const jobId = job.id || job.name || 'unknown';
    const payload = job.payload;

    if (!payload || typeof payload !== 'object') continue;
    const p = payload as Record<string, unknown>;

    // Get the message text to scan
    const messages: string[] = [];
    if (typeof p.message === 'string') messages.push(p.message);
    if (typeof p.prompt === 'string') messages.push(p.prompt);
    if (typeof p.content === 'string') messages.push(p.content);
    if (Array.isArray(p.messages)) {
      for (const m of p.messages) {
        if (typeof m === 'string') messages.push(m);
        if (typeof m === 'object' && m !== null) {
          const mc = m as Record<string, unknown>;
          if (typeof mc.content === 'string') messages.push(mc.content);
        }
      }
    }

    for (const msg of messages) {
      for (const injPattern of SHELL_INJECTION_PATTERNS) {
        if (injPattern.regex.test(msg)) {
          const match = msg.match(injPattern.regex);
          const snippet = match ? match[0].substring(0, 80) : '(detected)';

          findings.push({
            id: `${injPattern.id}-${jobId}`,
            scanner: 'openclaw-config-auditor',
            severity: injPattern.severity,
            title: `Cron job "${jobId}": ${injPattern.label}`,
            description: `The cron job payload for "${jobId}" contains a pattern that may indicate shell injection risk: \`${snippet}\`. If cron payload messages are constructed from external input, this could allow arbitrary command execution.`,
            file: filePath,
            recommendation: 'Ensure cron payload messages are static strings not built from user input. Avoid shell metacharacters in agent instructions. If dynamic content is needed, sanitize inputs strictly.',
          });
        }
      }
    }

    // Check for suspicious URLs in cron payloads (potential data exfiltration endpoint)
    for (const msg of messages) {
      const exfilUrl = /https?:\/\/[^\s"']+(?:exfil|webhook|c2|ngrok|tunnel|burp)[^\s"']*/i;
      if (exfilUrl.test(msg)) {
        const match = msg.match(exfilUrl);
        findings.push({
          id: `OC-003-exfil-url-${jobId}`,
          scanner: 'openclaw-config-auditor',
          severity: 'high',
          title: `Cron job "${jobId}": suspicious exfiltration URL in payload`,
          description: `The cron job payload for "${jobId}" references a URL that may indicate data exfiltration: ${match?.[0].substring(0, 80)}`,
          file: filePath,
          recommendation: 'Review cron payload URLs. Remove any references to external webhook endpoints, tunneling services, or C2 infrastructure.',
        });
      }
    }
  }

  return findings;
}

function extractCronJobs(config: Record<string, unknown>): Array<Record<string, unknown>> {
  const jobs: Array<Record<string, unknown>> = [];

  // cron/jobs.json format: { version: 1, jobs: [...] }
  if (Array.isArray(config.jobs)) {
    for (const job of config.jobs) {
      if (typeof job === 'object' && job !== null) {
        jobs.push(job as Record<string, unknown>);
      }
    }
  }

  // top-level openclaw.json cron section
  const cron = config.cron as Record<string, unknown> | undefined;
  if (cron && typeof cron === 'object') {
    if (Array.isArray(cron.jobs)) {
      for (const job of cron.jobs) {
        if (typeof job === 'object' && job !== null) {
          jobs.push(job as Record<string, unknown>);
        }
      }
    }
    if (Array.isArray(cron.entries)) {
      for (const entry of cron.entries) {
        if (typeof entry === 'object' && entry !== null) {
          jobs.push(entry as Record<string, unknown>);
        }
      }
    }
  }

  return jobs;
}

// ─── Channel Token Detection ──────────────────────────────────────────────────

export function auditChannelTokens(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];

  // Skip credential storage files — they're expected to have tokens
  // (auth-profiles.json, auth.json are expected credential stores)
  const basename = path.basename(filePath).toLowerCase();
  const isCredentialFile = basename === 'auth-profiles.json' || basename === 'auth.json';

  if (isCredentialFile) {
    // Still flag plaintext tokens in credential files, but downgrade severity
    // since their presence is expected but should use encryption
    for (const pattern of CHANNEL_TOKEN_PATTERNS) {
      if (pattern.regex.test(content)) {
        const match = content.match(pattern.regex);
        const snippet = match ? maskSecret(match[0]) : '(detected)';
        findings.push({
          id: `${pattern.id}-cred-file`,
          scanner: 'openclaw-config-auditor',
          severity: 'medium',
          title: `${pattern.label} stored in plaintext credential file`,
          description: `A ${pattern.label} was found in plaintext in a credential file (${path.basename(filePath)}): ${snippet}. Credential files should be encrypted at rest.`,
          file: filePath,
          recommendation: 'Enable filesystem encryption (FileVault on macOS) and restrict file permissions to 600. Consider using a keychain or secrets manager to store tokens.',
        });
      }
    }
    return findings;
  }

  // For all other config files, plaintext tokens are high severity
  for (const pattern of CHANNEL_TOKEN_PATTERNS) {
    if (pattern.regex.test(content)) {
      const match = content.match(pattern.regex);
      const snippet = match ? maskSecret(match[0]) : '(detected)';
      findings.push({
        id: `${pattern.id}-config`,
        scanner: 'openclaw-config-auditor',
        severity: 'high',
        title: `${pattern.label} found in plaintext config`,
        description: `A ${pattern.label} was found in plaintext in the configuration file: ${snippet}. Hardcoded tokens can be extracted by anyone with file access or who compromises the config.`,
        file: filePath,
        recommendation: 'Move tokens to environment variables (e.g., TELEGRAM_BOT_TOKEN) and reference them from config. Use OS keychain or a secrets manager for secure storage.',
      });
    }
  }

  return findings;
}
