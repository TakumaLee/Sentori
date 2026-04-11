import * as fs from 'fs';
import * as path from 'path';
import { z } from 'zod';
import { Scanner, ScannerOptions, ScanResult, Finding, Severity } from '../types';
import { walkFiles } from '../utils/file-walker';

const HYGIENE_SCAN_EXTENSIONS = new Set([
  '.md', '.sh', '.py', '.js', '.ts', '.yaml', '.yml', '.json', '.txt', '.plist',
  '.env', '.cfg', '.conf', '.ini', '.toml',
]);

/** Extra filenames to scan that have no real extension (e.g. `.env`). */
const HYGIENE_EXTRA_FILENAMES = new Set(['.env', '.env.local', '.env.production', '.env.development']);

// --- Types ---

export type CheckStatus = 'PASS' | 'FAIL' | 'WARN';

export interface HygieneFinding {
  checkName: string;
  severity: Severity;
  status: CheckStatus;
  description: string;
  recommendation: string;
}

export interface HygieneReport {
  findings: HygieneFinding[];
  score: number;
}

// --- Check interface ---

interface HygieneCheck {
  name: string;
  severity: Severity;
  weight: number;
  run(ctx: CheckContext): HygieneFinding;
}

export interface AgentConfig {
  fileAccess?: string[] | string;
  shellAccess?: { enabled?: boolean; allowlist?: string[] } | string;
  browserProfile?: string;
  costLimits?: { dailyLimit?: number; monthlyLimit?: number; hardLimit?: number };
  trading?: {
    enabled?: boolean;
    simulationMode?: boolean;
    singleTradeLimit?: number;
    dailyLossLimit?: number;
    manualConfirmation?: boolean;
  };
  monitoring?: {
    logging?: boolean;
    anomalyDetection?: boolean;
    killSwitch?: boolean;
    autoShutdown?: boolean;
  };
  systemPrompt?: string;
  promptDefenses?: {
    identityLock?: boolean;
    inputSanitization?: boolean;
    outputGuards?: boolean;
  };
  [key: string]: unknown;
}

// Zod schema for AgentConfig — validates structure before use to prevent
// downstream crashes from malformed agent config files in scanned projects.
const AgentConfigSchema = z.object({
  fileAccess: z.union([z.array(z.string()), z.string()]).optional(),
  shellAccess: z.union([
    z.object({ enabled: z.boolean().optional(), allowlist: z.array(z.string()).optional() }),
    z.string(),
  ]).optional(),
  browserProfile: z.string().optional(),
  costLimits: z.object({
    dailyLimit: z.number().optional(),
    monthlyLimit: z.number().optional(),
    hardLimit: z.number().optional(),
  }).optional(),
  trading: z.object({
    enabled: z.boolean().optional(),
    simulationMode: z.boolean().optional(),
    singleTradeLimit: z.number().optional(),
    dailyLossLimit: z.number().optional(),
    manualConfirmation: z.boolean().optional(),
  }).optional(),
  monitoring: z.object({
    logging: z.boolean().optional(),
    anomalyDetection: z.boolean().optional(),
    killSwitch: z.boolean().optional(),
    autoShutdown: z.boolean().optional(),
  }).optional(),
  systemPrompt: z.string().optional(),
  promptDefenses: z.object({
    identityLock: z.boolean().optional(),
    inputSanitization: z.boolean().optional(),
    outputGuards: z.boolean().optional(),
  }).optional(),
}).passthrough();

interface CheckContext {
  targetDir: string;
  config: AgentConfig;
  fileContents: Array<{ relativePath: string; content: string }>;
}

// --- Credential patterns ---

const CREDENTIAL_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /(?<![a-zA-Z])sk-[a-zA-Z0-9]{20,}/g, name: 'OpenAI API key' },
  { pattern: /(?<![a-zA-Z])sk-ant-[a-zA-Z0-9\-_]{20,}/g, name: 'Anthropic API key' },
  { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key ID' },
  { pattern: /ghp_[a-zA-Z0-9]{36,}/g, name: 'GitHub personal access token' },
  { pattern: /gho_[a-zA-Z0-9]{36,}/g, name: 'GitHub OAuth token' },
  { pattern: /github_pat_[a-zA-Z0-9_]{22,}/g, name: 'GitHub fine-grained PAT' },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, name: 'Stripe secret key' },
  { pattern: /sk_test_[a-zA-Z0-9]{24,}/g, name: 'Stripe test key' },
  { pattern: /xoxb-[0-9]{10,}-[a-zA-Z0-9]{20,}/g, name: 'Slack bot token' },
  { pattern: /xoxp-[0-9]{10,}-[a-zA-Z0-9]{20,}/g, name: 'Slack user token' },
  { pattern: /(?:^|[^a-zA-Z0-9])((?:API|SECRET|AUTH|ACCESS|PRIVATE|SIGNING|ENCRYPTION|DATABASE|DB|REDIS|MONGO|SMTP|MAIL|AWS|AZURE|GCP|CLOUD|SERVICE|CLIENT|WEBHOOK|HF)[-_]?(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)\s*[:=]\s*['"]?[a-zA-Z0-9\-_./+]{8,})['"]?/gim, name: 'Generic secret assignment' },
];

// --- Work app indicators ---

const WORK_APP_PATHS_MACOS = [
  '/Applications/Slack.app',
  '/Applications/Microsoft Teams.app',
  '/Applications/Microsoft Outlook.app',
  '/Applications/1Password.app',
  '/Applications/1Password 7.app',
];

const VPN_CONFIG_PATHS = [
  '/etc/vpnc',
  '/etc/openvpn',
];

// --- Convention filenames ---

const CONVENTION_FILES = [
  'HEARTBEAT.md',
  'README.md',
  'AGENTS.md',
  'SOUL.md',
  'CLAUDE.md',
  'COPILOT.md',
];

// --- Checks ---

function checkEnvironmentIsolation(ctx: CheckContext): HygieneFinding {
  const found: string[] = [];
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';

  for (const appPath of WORK_APP_PATHS_MACOS) {
    if (fs.existsSync(appPath)) {
      found.push(path.basename(appPath));
    }
  }

  for (const vpnPath of VPN_CONFIG_PATHS) {
    if (fs.existsSync(vpnPath)) {
      found.push('VPN config: ' + vpnPath);
    }
  }

  // Check for IDE projects outside sandbox
  const ideConfigDirs = ['.vscode', '.idea'];
  if (homeDir) {
    for (const ide of ideConfigDirs) {
      const p = path.join(homeDir, ide);
      if (fs.existsSync(p)) {
        found.push('IDE config: ~/' + ide);
      }
    }
  }

  if (found.length > 0) {
    return {
      checkName: 'Environment Isolation',
      severity: 'high',
      status: 'FAIL',
      description: `Agent runs on primary workstation. Detected: ${found.join(', ')}`,
      recommendation: 'Run agent in an isolated VM, container, or dedicated machine without personal/work applications.',
    };
  }

  return {
    checkName: 'Environment Isolation',
    severity: 'high',
    status: 'PASS',
    description: 'No common work applications detected on this host.',
    recommendation: 'Continue running agent in an isolated environment.',
  };
}

function checkFileAccessScope(ctx: CheckContext): HygieneFinding {
  const access = ctx.config.fileAccess;

  if (!access) {
    return {
      checkName: 'File Access Scope',
      severity: 'high',
      status: 'WARN',
      description: 'No file access configuration found. Access scope is unclear.',
      recommendation: 'Explicitly configure file access to a sandboxed directory.',
    };
  }

  const accessList = Array.isArray(access) ? access : [access];
  const dangerous = accessList.filter(
    (a) => a === '<all>' || a === '/' || a === '~' || a === '*'
  );

  if (dangerous.length > 0) {
    return {
      checkName: 'File Access Scope',
      severity: 'high',
      status: 'FAIL',
      description: `Unrestricted file system access detected: ${dangerous.join(', ')}`,
      recommendation: 'Restrict file access to the agent workspace directory only.',
    };
  }

  return {
    checkName: 'File Access Scope',
    severity: 'high',
    status: 'PASS',
    description: 'File access is scoped to specific directories.',
    recommendation: 'Maintain restrictive file access policies.',
  };
}

function checkShellAccess(ctx: CheckContext): HygieneFinding {
  const shell = ctx.config.shellAccess;

  if (!shell) {
    return {
      checkName: 'Shell/Exec Access',
      severity: 'high',
      status: 'WARN',
      description: 'No shell access configuration found.',
      recommendation: 'Explicitly configure shell access with an allowlist of permitted commands.',
    };
  }

  if (typeof shell === 'string') {
    if (shell === 'full' || shell === 'unrestricted') {
      return {
        checkName: 'Shell/Exec Access',
        severity: 'high',
        status: 'FAIL',
        description: 'Shell execution is fully open with no restrictions.',
        recommendation: 'Configure an allowlist of permitted commands.',
      };
    }
  } else if (typeof shell === 'object') {
    if (shell.enabled !== false && (!shell.allowlist || shell.allowlist.length === 0)) {
      return {
        checkName: 'Shell/Exec Access',
        severity: 'high',
        status: 'FAIL',
        description: 'Shell execution is enabled without an allowlist.',
        recommendation: 'Define an allowlist of permitted shell commands.',
      };
    }
  }

  return {
    checkName: 'Shell/Exec Access',
    severity: 'high',
    status: 'PASS',
    description: 'Shell access is configured with restrictions.',
    recommendation: 'Regularly review the shell command allowlist.',
  };
}

/** Placeholder patterns that should NOT trigger credential alerts */
const PLACEHOLDER_RE = /^(?:<[^>]+>|your[_-]|xxx|placeholder|example|changeme|replace[_-]?me|TODO|FIXME|DEMO|\$\{|%s|hf_your)/i;

/** Patterns that indicate env var reading (not hardcoded secrets) */
const ENV_VAR_READ_RE = /(?:os\.environ|os\.getenv|process\.env|getenv\(|ENV\[|env\.|System\.getenv|\$\{?\w+_(?:KEY|TOKEN|SECRET))/;

/** File extensions that are documentation, not executable code */
const DOC_EXTS_CRED = new Set(['.md', '.txt', '.rst', '.adoc', '.example']);

function checkCredentialExposure(ctx: CheckContext): HygieneFinding {
  const exposures: string[] = [];

  for (const file of ctx.fileContents) {
    const ext = file.relativePath.replace(/.*\./, '.').toLowerCase();
    const isDoc = DOC_EXTS_CRED.has(ext) || file.relativePath.endsWith('.example');

    for (const { pattern, name } of CREDENTIAL_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      let found = false;
      while ((match = regex.exec(file.content)) !== null) {
        const value = match[0];
        const secretPart = value.replace(/^[^=:]+[=:]\s*['"]?/, '');
        // Skip obvious placeholder values
        if (PLACEHOLDER_RE.test(secretPart)) continue;
        // Skip env var reading patterns (os.environ.get, process.env, etc.)
        // — these read from env at runtime, not hardcoded secrets
        const lineStart = file.content.lastIndexOf('\n', match.index) + 1;
        const line = file.content.substring(lineStart, file.content.indexOf('\n', match.index + 1));
        if (ENV_VAR_READ_RE.test(line)) continue;
        // In documentation files, skip placeholder-like values
        if (isDoc) {
          if (/^[x]{4,}$/i.test(secretPart) || /xxx/i.test(secretPart)) continue;
        }
        found = true;
        break;
      }
      if (found) {
        exposures.push(`${name} in ${file.relativePath}`);
      }
    }
  }

  if (exposures.length > 0) {
    return {
      checkName: 'Credential Exposure',
      severity: 'critical',
      status: 'FAIL',
      description: `Found ${exposures.length} potential credential(s): ${exposures.slice(0, 5).join('; ')}${exposures.length > 5 ? ` (+${exposures.length - 5} more)` : ''}`,
      recommendation: 'Remove all hardcoded credentials. Use a secrets manager or environment variables injected at runtime.',
    };
  }

  return {
    checkName: 'Credential Exposure',
    severity: 'critical',
    status: 'PASS',
    description: 'No exposed credentials detected in scanned files.',
    recommendation: 'Continue using secure credential management.',
  };
}

function checkBrowserIsolation(ctx: CheckContext): HygieneFinding {
  const profile = ctx.config.browserProfile;

  if (!profile) {
    return {
      checkName: 'Browser Profile Isolation',
      severity: 'medium',
      status: 'WARN',
      description: 'No browser profile configuration found.',
      recommendation: 'Configure agent to use a dedicated, isolated browser profile.',
    };
  }

  const lp = profile.toLowerCase();
  if (lp === 'default' || lp === 'personal' || lp === 'main') {
    return {
      checkName: 'Browser Profile Isolation',
      severity: 'medium',
      status: 'FAIL',
      description: `Agent uses non-isolated browser profile: "${profile}". May have access to logged-in sessions.`,
      recommendation: 'Create a dedicated browser profile for the agent with no logged-in sessions.',
    };
  }

  return {
    checkName: 'Browser Profile Isolation',
    severity: 'medium',
    status: 'PASS',
    description: `Agent uses browser profile: "${profile}".`,
    recommendation: 'Ensure the browser profile has no persistent logged-in sessions.',
  };
}

function checkCostControls(ctx: CheckContext): HygieneFinding {
  const limits = ctx.config.costLimits;

  if (!limits) {
    return {
      checkName: 'Cost Controls',
      severity: 'medium',
      status: 'FAIL',
      description: 'No cost/spending limits configured.',
      recommendation: 'Set daily and monthly spending limits with a hard cap.',
    };
  }

  if (!limits.hardLimit && limits.hardLimit !== 0) {
    return {
      checkName: 'Cost Controls',
      severity: 'medium',
      status: 'WARN',
      description: 'Soft limits exist but no hard spending limit is set.',
      recommendation: 'Add a hardLimit that auto-stops the agent when reached.',
    };
  }

  return {
    checkName: 'Cost Controls',
    severity: 'medium',
    status: 'PASS',
    description: `Hard spending limit set at ${limits.hardLimit}.`,
    recommendation: 'Review spending limits periodically.',
  };
}

function checkTradingSafeguards(ctx: CheckContext): HygieneFinding {
  const trading = ctx.config.trading;

  if (!trading || !trading.enabled) {
    return {
      checkName: 'Trading/Financial Safeguards',
      severity: 'high',
      status: 'PASS',
      description: 'No trading capabilities detected or trading is disabled.',
      recommendation: 'If adding trading capabilities, enable all safeguards.',
    };
  }

  const issues: string[] = [];
  if (!trading.simulationMode) issues.push('simulation mode not default');
  if (!trading.singleTradeLimit && trading.singleTradeLimit !== 0) issues.push('no single-trade limit');
  if (!trading.dailyLossLimit && trading.dailyLossLimit !== 0) issues.push('no daily loss limit');
  if (!trading.manualConfirmation) issues.push('no manual confirmation required');

  if (issues.length > 0) {
    return {
      checkName: 'Trading/Financial Safeguards',
      severity: 'high',
      status: issues.length >= 3 ? 'FAIL' : 'WARN',
      description: `Trading is enabled with missing safeguards: ${issues.join(', ')}`,
      recommendation: 'Enable simulation mode by default, set trade/loss limits, and require manual confirmation for real trades.',
    };
  }

  return {
    checkName: 'Trading/Financial Safeguards',
    severity: 'high',
    status: 'PASS',
    description: 'Trading safeguards are properly configured.',
    recommendation: 'Regularly review trading limits and keep simulation mode as default.',
  };
}

function checkConventionFileSquatting(_ctx: CheckContext): HygieneFinding {
  const atRisk = CONVENTION_FILES.filter((f) => f.endsWith('.md'));
  // .md is Moldova TLD — these filenames could resolve as URLs
  const squattable = atRisk.map((f) => f.replace(/\.md$/, '.md'));

  return {
    checkName: 'Convention File Squatting',
    severity: 'medium',
    status: 'WARN',
    description: `Convention files with .md extension could resolve as Moldova TLD URLs: ${squattable.join(', ')}. If the agent framework resolves local filenames as URLs, this is exploitable.`,
    recommendation: 'Ensure agent framework does not perform URL resolution on local convention filenames. Consider using non-TLD extensions.',
  };
}

function checkPromptInjectionDefenses(ctx: CheckContext): HygieneFinding {
  const defenses = ctx.config.promptDefenses;
  const prompt = ctx.config.systemPrompt || '';

  const hasIdentityLock = defenses?.identityLock || /identity.?lock|do not change.?identity|you are always/i.test(prompt);
  const hasInputSanitization = defenses?.inputSanitization || /sanitiz|filter.?input|input.?valid/i.test(prompt);
  const hasOutputGuards = defenses?.outputGuards || /output.?guard|do not reveal.?system|never.?disclose/i.test(prompt);

  const missing: string[] = [];
  if (!hasIdentityLock) missing.push('identity lock');
  if (!hasInputSanitization) missing.push('input sanitization');
  if (!hasOutputGuards) missing.push('output guards');

  if (missing.length === 3) {
    return {
      checkName: 'Prompt Injection Defenses',
      severity: 'high',
      status: 'FAIL',
      description: 'No prompt injection defenses detected.',
      recommendation: 'Add identity lock rules, input sanitization, and output guards to the system prompt/config.',
    };
  }

  if (missing.length > 0) {
    return {
      checkName: 'Prompt Injection Defenses',
      severity: 'high',
      status: 'WARN',
      description: `Missing prompt injection defenses: ${missing.join(', ')}`,
      recommendation: `Add the following defenses: ${missing.join(', ')}.`,
    };
  }

  return {
    checkName: 'Prompt Injection Defenses',
    severity: 'high',
    status: 'PASS',
    description: 'Prompt injection defenses are configured.',
    recommendation: 'Test defenses regularly with adversarial prompts.',
  };
}

function checkMonitoringKillSwitch(ctx: CheckContext): HygieneFinding {
  const mon = ctx.config.monitoring;

  if (!mon) {
    return {
      checkName: 'Monitoring & Kill Switch',
      severity: 'medium',
      status: 'FAIL',
      description: 'No monitoring or kill switch configuration found.',
      recommendation: 'Enable activity logging, anomaly detection, and an auto-shutdown kill switch.',
    };
  }

  const missing: string[] = [];
  if (!mon.logging) missing.push('activity logging');
  if (!mon.anomalyDetection) missing.push('anomaly detection');
  if (!mon.killSwitch && !mon.autoShutdown) missing.push('kill switch / auto-shutdown');

  if (missing.length > 0) {
    return {
      checkName: 'Monitoring & Kill Switch',
      severity: 'medium',
      status: missing.length >= 2 ? 'FAIL' : 'WARN',
      description: `Missing monitoring capabilities: ${missing.join(', ')}`,
      recommendation: `Enable: ${missing.join(', ')}.`,
    };
  }

  return {
    checkName: 'Monitoring & Kill Switch',
    severity: 'medium',
    status: 'PASS',
    description: 'Monitoring and kill switch are configured.',
    recommendation: 'Test kill switch regularly to ensure it works.',
  };
}

// --- Score calculation ---

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 20,
  high: 15,
  medium: 8,
  info: 3,
};

const STATUS_MULTIPLIER: Record<CheckStatus, number> = {
  PASS: 0,
  WARN: 0.5,
  FAIL: 1,
};

export function calculateHygieneScore(findings: HygieneFinding[]): number {
  if (findings.length === 0) return 100;

  const totalWeight = findings.reduce((sum, f) => sum + SEVERITY_WEIGHTS[f.severity], 0);
  const deductions = findings.reduce(
    (sum, f) => sum + SEVERITY_WEIGHTS[f.severity] * STATUS_MULTIPLIER[f.status],
    0
  );

  const score = Math.round(Math.max(0, Math.min(100, ((totalWeight - deductions) / totalWeight) * 100)));
  return score;
}

// --- Config loading ---

const CONFIG_FILENAMES = [
  'agent.json',
  'agent.yaml',
  'agent.yml',
  'agent-config.json',
  'sentori.json',
  '.agentrc.json',
];

export function loadAgentConfig(targetDir: string): AgentConfig {
  for (const name of CONFIG_FILENAMES) {
    const p = path.join(targetDir, name);
    if (fs.existsSync(p)) {
      let raw: unknown;
      try {
        raw = JSON.parse(fs.readFileSync(p, 'utf-8'));
      } catch (err) {
        process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'HygieneAuditor', file: p, error: 'agent config JSON parse failed — skipping', message: String(err) }) + '\n');
        continue;
      }
      const result = AgentConfigSchema.safeParse(raw);
      if (!result.success) {
        // Fall back to the raw parsed object so scanning still runs; the schema
        // adds defense-in-depth but should not silently disable all hygiene checks.
        process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'HygieneAuditor', file: p, error: 'agent config schema validation failed — falling back to raw config', issues: result.error.issues }) + '\n');
        return raw as AgentConfig;
      }
      return result.data as AgentConfig;
    }
  }
  return {};
}

// --- Extra file collection (dotfiles like .env) ---

function collectExtraFiles(dir: string): Array<{ relativePath: string; content: string }> {
  const extras: Array<{ relativePath: string; content: string }> = [];

  function walk(currentDir: string): void {
    if (!fs.existsSync(currentDir)) return;
    let items: fs.Dirent[];
    try {
      items = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      if (item.isDirectory()) {
        if (item.name === 'node_modules' || item.name === '.git') continue;
        walk(fullPath);
      } else if (item.isFile() && HYGIENE_EXTRA_FILENAMES.has(item.name)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          extras.push({ relativePath: path.relative(dir, fullPath), content });
        } catch {
          // skip
        }
      }
    }
  }

  walk(dir);
  return extras;
}

// --- Scanner ---

export class HygieneAuditor implements Scanner {
  name = 'HygieneAuditor';
  description = 'Audits AI agent deployment environment for security hygiene best practices';

  private checks: Array<(ctx: CheckContext) => HygieneFinding> = [
    checkEnvironmentIsolation,
    checkFileAccessScope,
    checkShellAccess,
    checkCredentialExposure,
    checkBrowserIsolation,
    checkCostControls,
    checkTradingSafeguards,
    checkConventionFileSquatting,
    checkPromptInjectionDefenses,
    checkMonitoringKillSwitch,
  ];

  async scan(targetDir: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const config = loadAgentConfig(targetDir);
    const files = walkFiles(targetDir, { extensions: HYGIENE_SCAN_EXTENSIONS, includeVendored: options?.includeVendored, exclude: options?.exclude, sentoriIgnorePatterns: options?.sentoriIgnorePatterns, includeWorkspaceProjects: options?.includeWorkspaceProjects });
    const fileContents = [
      ...files.map((f) => ({ relativePath: f.relativePath, content: f.content })),
      ...collectExtraFiles(targetDir),
    ];

    const ctx: CheckContext = { targetDir, config, fileContents };
    const hygieneFindings = this.checks.map((check) => check(ctx));

    // Convert to standard Finding format
    const findings: Finding[] = hygieneFindings
      .filter((hf) => hf.status !== 'PASS')
      .map((hf) => ({
        id: `HYGIENE-${hf.checkName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
        scanner: this.name,
        rule: `HYGIENE-${hf.checkName.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
        severity: hf.severity,
        title: hf.checkName,
        description: `[${hf.status}] ${hf.description}`,
        file: 'deployment-environment',
        line: 0,
        message: `[${hf.status}] ${hf.description}`,
        evidence: hf.recommendation,
        recommendation: hf.recommendation,
      }));

    return {
      scanner: this.name,
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  }

  /**
   * Run the audit and return a detailed hygiene report with score.
   */
  async audit(targetDir: string): Promise<HygieneReport> {
    const config = loadAgentConfig(targetDir);
    const files = walkFiles(targetDir, { extensions: HYGIENE_SCAN_EXTENSIONS });
    const fileContents = [
      ...files.map((f) => ({ relativePath: f.relativePath, content: f.content })),
      ...collectExtraFiles(targetDir),
    ];

    const ctx: CheckContext = { targetDir, config, fileContents };
    const findings = this.checks.map((check) => check(ctx));
    const score = calculateHygieneScore(findings);

    return { findings, score };
  }
}
