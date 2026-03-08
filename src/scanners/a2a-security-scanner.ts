import * as https from 'node:https';
import * as http from 'node:http';
import * as fs from 'node:fs';
import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';

/**
 * A2A Security Scanner
 *
 * Fetches and audits Google A2A (Agent-to-Agent) protocol agent cards
 * (/.well-known/agent.json) for insecure configurations.
 *
 * Detection targets:
 *  - Missing or weak authentication
 *  - Overly broad capability scopes
 *  - Untrusted inputModes
 *  - HTTP (non-HTTPS) endpoints
 */

// ─── Types (A2A Agent Card schema) ───────────────────────────────────────────

interface A2AAgentCard {
  name?: string;
  url?: string;
  version?: string;
  capabilities?: A2ACapabilities;
  authentication?: A2AAuthentication | A2AAuthentication[];
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  skills?: A2ASkill[];
  [key: string]: unknown;
}

interface A2ACapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
  [key: string]: unknown;
}

interface A2AAuthentication {
  schemes?: string[];
  credentials?: unknown;
  [key: string]: unknown;
}

interface A2ASkill {
  id?: string;
  name?: string;
  inputModes?: string[];
  outputModes?: string[];
  tags?: string[];
  [key: string]: unknown;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SCANNER_NAME = 'A2A Security Scanner';
const SCANNER_ID = 'a2a-security-scanner';

/**
 * InputModes that can carry executable payloads or are high-risk
 * for prompt injection / code execution.
 */
const HIGH_RISK_INPUT_MODES = [
  'application/javascript',
  'application/x-javascript',
  'text/javascript',
  'application/x-python',
  'application/x-sh',
  'text/x-sh',
  'application/x-shellscript',
  'application/octet-stream',
  'application/x-executable',
];

/**
 * Capability fields that indicate broad / privileged access.
 * Warn when all three are enabled simultaneously.
 */
const BROAD_CAPABILITY_COMBO = ['streaming', 'pushNotifications', 'stateTransitionHistory'] as const;

// ─── HTTP fetch helper ────────────────────────────────────────────────────────

function fetchUrl(url: string, timeoutMs = 8000): Promise<string> {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https://') ? https : http;
    const req = (mod as typeof https).get(url, { timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request to ${url} timed out after ${timeoutMs}ms`));
    });
  });
}

// ─── Agent card resolution ────────────────────────────────────────────────────

/**
 * Resolve an agent card from:
 *  1. A JSON file path on disk
 *  2. A bare hostname/URL (appends /.well-known/agent.json if missing)
 */
async function resolveAgentCard(input: string): Promise<{ card: A2AAgentCard; source: string; isHttp: boolean }> {
  // File path: starts with / or ./ or is an existing file
  const isFilePath = input.startsWith('/') || input.startsWith('./') || input.startsWith('../');
  if (isFilePath || fs.existsSync(input)) {
    const raw = fs.readFileSync(input, 'utf8');
    const card = JSON.parse(raw) as A2AAgentCard;
    return { card, source: input, isHttp: false };
  }

  // URL: normalize
  let url = input;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  // Append well-known path if not already present
  if (!url.includes('agent.json') && !url.endsWith('/')) {
    url = url.replace(/\/?$/, '/.well-known/agent.json');
  }

  const raw = await fetchUrl(url);
  const card = JSON.parse(raw) as A2AAgentCard;
  return { card, source: url, isHttp: url.startsWith('http://') };
}

// ─── Audit functions ──────────────────────────────────────────────────────────

function auditAuthentication(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  const auth = card.authentication;

  // Missing authentication entirely
  if (auth === undefined || auth === null) {
    findings.push({
      id: 'A2A-001',
      scanner: SCANNER_ID,
      severity: 'critical',
      rule: 'missing-authentication',
      title: 'Agent card has no authentication configured',
      description: 'The agent card does not declare any authentication schemes. Without authentication, any caller can interact with this agent.',
      file: source,
      recommendation: 'Add an "authentication" field with at least one scheme (e.g., Bearer token, OAuth2). See the A2A protocol specification §5.3.',
    });
    return findings;
  }

  const authList: A2AAuthentication[] = Array.isArray(auth) ? auth : [auth];

  for (const entry of authList) {
    const schemes = entry.schemes ?? [];

    // Empty scheme list
    if (schemes.length === 0) {
      findings.push({
        id: 'A2A-001-empty',
        scanner: SCANNER_ID,
        severity: 'critical',
        rule: 'empty-auth-schemes',
        title: 'Authentication block is present but has no schemes',
        description: 'The "authentication" field exists but the "schemes" array is empty. This provides no actual protection.',
        file: source,
        recommendation: 'Specify at least one authentication scheme such as "Bearer" or "OAuth2".',
      });
    }

    // None / anonymous auth
    if (schemes.some((s: string) => /^none$/i.test(s) || /^anonymous$/i.test(s))) {
      findings.push({
        id: 'A2A-002',
        scanner: SCANNER_ID,
        severity: 'high',
        rule: 'anonymous-auth-scheme',
        title: 'Agent card permits anonymous (no-auth) access',
        description: `Authentication scheme includes "none" or "anonymous", allowing unauthenticated callers to invoke the agent.`,
        file: source,
        recommendation: 'Remove the anonymous scheme unless public read-only access is intentional and the agent has no sensitive capabilities.',
      });
    }

    // Basic auth over non-TLS is caught in the HTTP endpoint check; warn here too
    if (schemes.some((s: string) => /^basic$/i.test(s))) {
      findings.push({
        id: 'A2A-003',
        scanner: SCANNER_ID,
        severity: 'medium',
        rule: 'basic-auth-scheme',
        title: 'Agent uses HTTP Basic authentication',
        description: 'HTTP Basic authentication transmits credentials in base64 (not encrypted). It is only safe over HTTPS.',
        file: source,
        recommendation: 'Prefer Bearer token or OAuth2. If Basic auth is required, ensure all endpoints use HTTPS.',
      });
    }
  }

  return findings;
}

function auditEndpoints(card: A2AAgentCard, sourceIsHttp: boolean, source: string): Finding[] {
  const findings: Finding[] = [];

  // Top-level url
  const topUrl = typeof card.url === 'string' ? card.url : null;
  if (topUrl && topUrl.startsWith('http://')) {
    findings.push({
      id: 'A2A-004',
      scanner: SCANNER_ID,
      severity: 'critical',
      rule: 'http-endpoint',
      title: 'Agent card declares an HTTP (non-HTTPS) endpoint',
      description: `The agent's primary URL is "${topUrl}", which uses plain HTTP. All traffic including authentication tokens is transmitted unencrypted.`,
      file: source,
      recommendation: 'Replace the HTTP URL with an HTTPS URL. Never expose agent endpoints over plain HTTP in production.',
    });
  }

  // The card was fetched over HTTP itself
  if (sourceIsHttp) {
    findings.push({
      id: 'A2A-005',
      scanner: SCANNER_ID,
      severity: 'critical',
      rule: 'http-card-fetch',
      title: 'Agent card served over HTTP (not HTTPS)',
      description: `The agent card at "${source}" was retrieved over HTTP. An attacker can intercept and tamper with the card in transit (MITM).`,
      file: source,
      recommendation: 'Serve the agent card exclusively over HTTPS with a valid TLS certificate.',
    });
  }

  // Scan skill-level URLs if present
  if (Array.isArray(card.skills)) {
    for (const skill of card.skills) {
      const skillUrl = typeof (skill as Record<string, unknown>).url === 'string'
        ? (skill as Record<string, unknown>).url as string
        : null;
      if (skillUrl && skillUrl.startsWith('http://')) {
        const skillId = skill.id ?? skill.name ?? 'unknown';
        findings.push({
          id: `A2A-004-skill-${skillId}`,
          scanner: SCANNER_ID,
          severity: 'high',
          rule: 'http-skill-endpoint',
          title: `Skill "${skillId}" declares an HTTP endpoint`,
          description: `Skill "${skillId}" has URL "${skillUrl}" using plain HTTP.`,
          file: source,
          recommendation: 'Replace HTTP with HTTPS for all skill endpoints.',
        });
      }
    }
  }

  return findings;
}

function auditCapabilities(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];
  const caps = card.capabilities;
  if (!caps || typeof caps !== 'object') return findings;

  // All three broad capabilities enabled at once → elevated attack surface
  const allBroad = BROAD_CAPABILITY_COMBO.every(k => caps[k] === true);
  if (allBroad) {
    findings.push({
      id: 'A2A-006',
      scanner: SCANNER_ID,
      severity: 'high',
      rule: 'broad-capability-scope',
      title: 'Agent card enables maximum capability scope (streaming + push + history)',
      description: 'All three advanced capabilities (streaming, pushNotifications, stateTransitionHistory) are enabled. This maximises the attack surface: push notifications can be abused for callback exfiltration, and state history can leak sensitive interaction data.',
      file: source,
      recommendation: 'Enable only the capabilities your agent actually requires. Disable pushNotifications and stateTransitionHistory unless explicitly needed.',
    });
  }

  // Push notifications alone — medium risk if no auth
  if (caps.pushNotifications === true) {
    findings.push({
      id: 'A2A-007',
      scanner: SCANNER_ID,
      severity: 'medium',
      rule: 'push-notifications-enabled',
      title: 'Agent card enables push notifications',
      description: 'Push notifications allow the agent to initiate outbound callbacks to caller-supplied URLs, which can be abused for SSRF or data exfiltration.',
      file: source,
      recommendation: 'Ensure push notification target URLs are validated and allowlisted. Require authentication on notification endpoints.',
    });
  }

  return findings;
}

function auditInputModes(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  // Collect all inputModes from top-level and skills
  const allModes: Array<{ mode: string; context: string }> = [];

  if (Array.isArray(card.defaultInputModes)) {
    for (const m of card.defaultInputModes) {
      allModes.push({ mode: String(m), context: 'defaultInputModes' });
    }
  }

  if (Array.isArray(card.skills)) {
    for (const skill of card.skills) {
      const skillId = skill.id ?? skill.name ?? 'unknown';
      if (Array.isArray(skill.inputModes)) {
        for (const m of skill.inputModes) {
          allModes.push({ mode: String(m), context: `skill:${skillId}` });
        }
      }
    }
  }

  for (const { mode, context } of allModes) {
    const modeLC = mode.toLowerCase();

    // Executable / code input modes
    if (HIGH_RISK_INPUT_MODES.some(r => modeLC === r)) {
      findings.push({
        id: `A2A-008-${mode.replace(/[^a-z0-9]/gi, '_')}`,
        scanner: SCANNER_ID,
        severity: 'high',
        rule: 'high-risk-input-mode',
        title: `Unsafe inputMode accepted: "${mode}"`,
        description: `The agent accepts "${mode}" in [${context}]. This MIME type can carry executable code and significantly increases the risk of code injection or remote execution via crafted inputs.`,
        file: source,
        recommendation: `Remove "${mode}" from accepted inputModes. Accept only the minimum content types the agent requires (e.g., "text/plain", "application/json").`,
      });
    }

    // Wildcard inputMode
    if (mode === '*' || mode === '*/*') {
      findings.push({
        id: 'A2A-009',
        scanner: SCANNER_ID,
        severity: 'high',
        rule: 'wildcard-input-mode',
        title: 'Wildcard inputMode (*) accepts any content type',
        description: `The agent advertises "${mode}" as an accepted inputMode in [${context}], meaning it will process any content type including executable formats.`,
        file: source,
        recommendation: 'Replace the wildcard with an explicit allowlist of safe MIME types.',
      });
    }
  }

  return findings;
}

// ─── Scanner entry point ──────────────────────────────────────────────────────

/**
 * When invoked as a directory scanner, look for local agent.json files.
 * When targetPath looks like a URL or explicit file path, resolve it directly.
 */
export const a2aSecurityScanner: ScannerModule = {
  name: SCANNER_NAME,
  description: 'Audits A2A protocol agent cards (/.well-known/agent.json) for missing authentication, overly broad capabilities, unsafe inputModes, and HTTP endpoints',

  async scan(targetPath: string, _options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    let scannedFiles = 0;

    // Determine input type
    const isUrl = targetPath.startsWith('http://') || targetPath.startsWith('https://') ||
      (!targetPath.startsWith('/') && !targetPath.startsWith('.') && !fs.existsSync(targetPath) && !targetPath.includes('/'));
    const isExplicitFile = targetPath.endsWith('.json') && (targetPath.startsWith('/') || targetPath.startsWith('.') || fs.existsSync(targetPath));
    const isDirectory = !isUrl && !isExplicitFile && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();

    const targets: string[] = [];

    if (isUrl || isExplicitFile) {
      targets.push(targetPath);
    } else if (isDirectory) {
      // Walk directory looking for agent.json / agent-card.json files
      const queue = [targetPath];
      while (queue.length > 0) {
        const dir = queue.shift()!;
        let entries: fs.Dirent[];
        try {
          entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
          continue;
        }
        for (const entry of entries) {
          if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue;
          const full = `${dir}/${entry.name}`;
          if (entry.isDirectory()) {
            queue.push(full);
          } else if (entry.isFile() && (entry.name === 'agent.json' || entry.name === 'agent-card.json')) {
            targets.push(full);
          }
        }
      }
    }

    for (const target of targets) {
      try {
        const { card, source, isHttp } = await resolveAgentCard(target);
        scannedFiles++;

        const cardFindings = [
          ...auditAuthentication(card, source),
          ...auditEndpoints(card, isHttp, source),
          ...auditCapabilities(card, source),
          ...auditInputModes(card, source),
        ];

        // All config-based findings are definite
        for (const f of cardFindings) f.confidence = 'definite';
        findings.push(...cardFindings);
      } catch (err) {
        // Unreachable / unparseable targets are silently skipped
        // (consistent with other scanners in this codebase)
      }
    }

    return {
      scanner: SCANNER_NAME,
      findings,
      scannedFiles,
      duration: Date.now() - start,
    };
  },
};
