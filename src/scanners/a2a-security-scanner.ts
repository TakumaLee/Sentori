import * as https from 'node:https';
import * as http from 'node:http';
import * as fs from 'node:fs';
import { z } from 'zod';
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
  provider?: { organization?: string; url?: string; [key: string]: unknown };
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

// ─── Zod schema for runtime validation of A2AAgentCard ───────────────────────

const A2AAgentCardSchema = z.object({
  name: z.string().optional(),
  url: z.string().optional(),
  version: z.string().optional(),
  provider: z.object({
    organization: z.string().optional(),
    url: z.string().optional(),
  }).passthrough().optional(),
  capabilities: z.object({
    streaming: z.boolean().optional(),
    pushNotifications: z.boolean().optional(),
    stateTransitionHistory: z.boolean().optional(),
  }).passthrough().optional(),
  authentication: z.union([
    z.null(),
    z.object({ schemes: z.array(z.string()).optional(), credentials: z.unknown().optional() }).passthrough(),
    z.array(z.object({ schemes: z.array(z.string()).optional(), credentials: z.unknown().optional() }).passthrough()),
  ]).optional(),
  defaultInputModes: z.array(z.string()).optional(),
  defaultOutputModes: z.array(z.string()).optional(),
  skills: z.array(z.object({
    id: z.string().optional(),
    name: z.string().optional(),
    inputModes: z.array(z.string()).optional(),
    outputModes: z.array(z.string()).optional(),
    tags: z.array(z.string()).optional(),
  }).passthrough()).optional(),
}).passthrough();

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

/**
 * Auth schemes that provide token freshness (exp/iat/jti) and resist replay attacks.
 * API Key and Basic auth have no built-in replay prevention.
 */
const REPLAY_RESISTANT_SCHEMES = ['oauth2', 'openidconnect', 'oidc', 'jwt', 'bearer'];

/**
 * Skill tags that claim elevated or unrestricted capabilities.
 * A2A does not cryptographically bind declared capabilities — these are self-asserted.
 */
const DANGEROUS_SKILL_TAGS = [
  'admin', 'administrator', 'root', 'sudo', 'superuser', 'privileged',
  'elevated', 'system', 'unrestricted', 'bypass', 'override', 'execute',
  'shell', 'arbitrary', 'full-access', 'god-mode', 'superadmin',
];

/**
 * Output MIME types that can carry executable payloads.
 * A malicious agent returning these types can trigger code execution in the caller.
 */
const HIGH_RISK_OUTPUT_MODES = [
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

// ─── HTTP fetch helper ────────────────────────────────────────────────────────

// Maximum body size for a fetched agent card: 1 MB. Agent cards are small JSON
// documents; capping prevents memory exhaustion from unbounded responses.
const FETCH_MAX_BYTES = 1 * 1024 * 1024;

function fetchUrl(url: string, timeoutMs = 8000, maxRedirects = 3): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn: () => void): void => {
      if (!settled) { settled = true; fn(); }
    };

    const attempt = (currentUrl: string, hopsLeft: number): void => {
      const mod = currentUrl.startsWith('https://') ? https : http;
      const req = (mod as typeof https).get(currentUrl, { timeout: timeoutMs }, (res) => {
        const status = res.statusCode ?? 0;
        // Follow 301/302/303/307/308 redirects
        if ((status === 301 || status === 302 || status === 303 || status === 307 || status === 308) && res.headers.location) {
          res.resume(); // drain response to free the socket
          if (hopsLeft <= 0) {
            done(() => reject(new Error(`Too many redirects fetching ${url}`)));
            return;
          }
          // Resolve relative redirect URLs against the current URL
          let next = res.headers.location;
          if (!next.startsWith('http://') && !next.startsWith('https://')) {
            const base = new URL(currentUrl);
            next = new URL(next, base).toString();
          }
          attempt(next, hopsLeft - 1);
          return;
        }

        // Enforce response size cap via Content-Length header if present.
        const contentLength = parseInt(res.headers['content-length'] ?? '0', 10);
        if (contentLength > FETCH_MAX_BYTES) {
          res.resume(); // drain to free the socket
          done(() => reject(new Error(`Agent card response too large (Content-Length: ${contentLength} bytes) from ${currentUrl}`)));
          return;
        }

        const chunks: Buffer[] = [];
        let totalBytes = 0;

        res.on('data', (chunk: Buffer) => {
          totalBytes += chunk.length;
          if (totalBytes > FETCH_MAX_BYTES) {
            res.resume(); // drain remaining data
            done(() => reject(new Error(`Agent card response too large (> ${FETCH_MAX_BYTES} bytes) from ${currentUrl}`)));
            return;
          }
          chunks.push(chunk);
        });

        res.on('end', () => {
          done(() => resolve(Buffer.concat(chunks).toString('utf8')));
        });

        res.on('error', (err) => {
          done(() => reject(err));
        });
      });

      req.on('error', (err) => {
        done(() => reject(err));
      });

      req.on('timeout', () => {
        req.destroy();
        done(() => reject(new Error(`Request to ${currentUrl} timed out after ${timeoutMs}ms`)));
      });
    };

    attempt(url, maxRedirects);
  });
}

// ─── Agent card resolution ────────────────────────────────────────────────────

/**
 * Resolve an agent card from:
 *  1. A JSON file path on disk
 *  2. A bare hostname/URL (appends /.well-known/agent.json if missing)
 */
async function resolveAgentCard(input: string): Promise<{ card: A2AAgentCard; source: string; isHttp: boolean; isFetchedUrl: boolean }> {
  // File path: starts with / or ./ or is an existing file
  const isFilePath = input.startsWith('/') || input.startsWith('./') || input.startsWith('../');
  if (isFilePath || fs.existsSync(input)) {
    const raw = fs.readFileSync(input, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      process.stderr.write(JSON.stringify({ level: 'error', scanner: 'A2ASecurityScanner', source: input, error: 'JSON parse failed', message: String(err) }) + '\n');
      throw new Error(`Invalid JSON in agent card file "${input}": ${String(err)}`);
    }
    const result = A2AAgentCardSchema.safeParse(parsed);
    if (!result.success) {
      process.stderr.write(JSON.stringify({ level: 'error', scanner: 'A2ASecurityScanner', source: input, error: 'Agent card schema validation failed', issues: result.error.issues }) + '\n');
      throw new Error(`Invalid agent card structure in "${input}": schema validation failed`);
    }
    return { card: result.data as A2AAgentCard, source: input, isHttp: false, isFetchedUrl: false };
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
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(JSON.stringify({ level: 'error', scanner: 'A2ASecurityScanner', source: url, error: 'JSON parse failed', message: String(err) }) + '\n');
    throw new Error(`Invalid JSON in agent card response from "${url}": ${String(err)}`);
  }
  const result = A2AAgentCardSchema.safeParse(parsed);
  if (!result.success) {
    process.stderr.write(JSON.stringify({ level: 'error', scanner: 'A2ASecurityScanner', source: url, error: 'Agent card schema validation failed', issues: result.error.issues }) + '\n');
    throw new Error(`Invalid agent card structure from "${url}": schema validation failed`);
  }
  return { card: result.data as A2AAgentCard, source: url, isHttp: url.startsWith('http://'), isFetchedUrl: true };
}

// ─── Audit functions ──────────────────────────────────────────────────────────

export function auditAuthentication(card: A2AAgentCard, source: string): Finding[] {
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

export function auditEndpoints(card: A2AAgentCard, sourceIsHttp: boolean, source: string): Finding[] {
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

export function auditCapabilities(card: A2AAgentCard, source: string): Finding[] {
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

export function auditInputModes(card: A2AAgentCard, source: string): Finding[] {
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

// ─── New threat vector audit functions ───────────────────────────────────────

/**
 * A2A-010: Missing Agent Card Signing
 *
 * The A2A spec §8.4 defines optional JWS signing (RFC 7515) + JCS canonicalization
 * (RFC 8785) for agent cards. Without a verifiable signature or JWKS endpoint, any
 * attacker with network access can serve a forged agent card from /.well-known/agent.json.
 *
 * Attack path: Attacker registers a lookalike domain → serves unsigned forged card →
 * orchestrators accept it and route tasks to the malicious agent.
 */
export function auditCardIntegrity(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  const hasJwksUri = typeof (card as Record<string, unknown>)['jwks_uri'] === 'string';
  const hasPublicKey = (card as Record<string, unknown>)['publicKey'] !== undefined;
  const hasSignature = typeof (card as Record<string, unknown>)['signature'] === 'string';

  if (!hasJwksUri && !hasPublicKey && !hasSignature) {
    findings.push({
      id: 'A2A-010',
      scanner: SCANNER_ID,
      severity: 'critical',
      rule: 'missing-card-signing',
      title: 'Agent card lacks cryptographic signing or JWKS endpoint',
      description:
        'No "jwks_uri", "publicKey", or "signature" field found. Per the A2A spec §8.4, cards ' +
        'SHOULD be signed with JWS (RFC 7515) using JCS canonicalization (RFC 8785). Without a ' +
        'verifiable signature, any attacker serving content at /.well-known/agent.json can ' +
        'impersonate a trusted agent — orchestrators have no protocol-level means to detect ' +
        'the forgery.',
      file: source,
      recommendation:
        'Add a "jwks_uri" field pointing to your JWKS endpoint, or include a JWS signature of ' +
        'the canonicalized card using the agent\'s private key. See A2A spec §8.4. ' +
        'Orchestrators should reject unsigned cards from untrusted origins.',
      confidence: 'definite',
    });
  }

  return findings;
}

/**
 * A2A-011: URL Identity Mismatch (Agent Identity Spoofing)
 *
 * The agent card's "url" field is self-declared with no CA-style binding (issue #1672 in the
 * A2A project is still open). When the declared URL host differs from the fetch origin,
 * it indicates either a MITM redirect or a malicious agent publishing a forged card that
 * claims to be a different trusted agent.
 *
 * Attack path: Attacker performs DNS spoofing or BGP hijack → card served from
 * attacker's IP → card.url points to legitimate agent → orchestrator routes sensitive
 * tasks to attacker infrastructure.
 */
export function auditUrlIdentity(card: A2AAgentCard, source: string, isFetchedUrl: boolean): Finding[] {
  const findings: Finding[] = [];

  if (!isFetchedUrl || typeof card.url !== 'string') return findings;

  try {
    const cleanSource = source.replace(/\/.well-known\/agent\.json$/, '');
    const fetchedHost = new URL(cleanSource).hostname;
    const cardUrlHost = new URL(card.url).hostname;

    const getRootDomain = (host: string): string => {
      const parts = host.split('.');
      return parts.length >= 2 ? parts.slice(-2).join('.') : host;
    };

    if (getRootDomain(fetchedHost) !== getRootDomain(cardUrlHost)) {
      findings.push({
        id: 'A2A-011',
        scanner: SCANNER_ID,
        severity: 'critical',
        rule: 'url-identity-mismatch',
        title: `Agent card URL host mismatch: fetched from "${fetchedHost}" but declares "${cardUrlHost}"`,
        description:
          `The agent card was retrieved from "${fetchedHost}" but declares its canonical URL ` +
          `as "${card.url}" (host: "${cardUrlHost}"). This mismatch is a strong indicator of ` +
          `either a MITM attack redirecting agent card requests to a malicious host, or a ` +
          `misconfigured agent advertising another agent\'s endpoint. The A2A spec has no ` +
          `mandatory hostname-binding — the "url" field is self-asserted (see issue #1672).`,
        file: source,
        recommendation:
          'The "url" field MUST match the origin from which the card is served. Investigate ' +
          'whether the card is proxied through an untrusted intermediary. Orchestrators should ' +
          'reject cards where the declared URL host differs from the fetch origin.',
        confidence: 'definite',
      });
    }
  } catch {
    // URL parsing failure — skip silently
  }

  return findings;
}

/**
 * A2A-012: Missing Provider Trust Anchor
 *
 * The A2A spec §4.2 defines the "provider" object (organization, url) as the declarative
 * trust anchor for an agent. Without it, there is no accountability field — callers cannot
 * determine who operates the agent, making social engineering and impersonation easier.
 *
 * While not a directly exploitable vulnerability, missing provider metadata removes a
 * defensive layer that orchestrators can use for access control policies.
 */
export function auditProviderTrust(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  if (card.provider === undefined || card.provider === null) {
    findings.push({
      id: 'A2A-012',
      scanner: SCANNER_ID,
      severity: 'medium',
      rule: 'missing-provider-trust',
      title: 'Agent card declares no provider (missing trust anchor)',
      description:
        'The agent card omits the "provider" field (organization name + URL). Without a ' +
        'declared provider, there is no trust anchor — orchestrators cannot determine who ' +
        'is responsible for the agent. This aids impersonation attacks: a forged card is ' +
        'indistinguishable from a legitimate one when neither declares a provider. ' +
        'The A2A spec §4.2 defines "provider" as an accountability mechanism.',
      file: source,
      recommendation:
        'Add a "provider" field with "organization" (your organization name) and "url" ' +
        '(your homepage). Orchestrators should enforce allowlists based on provider.organization.',
      confidence: 'definite',
    });
  }

  return findings;
}

/**
 * A2A-013: Replay-Vulnerable Authentication Scheme
 *
 * The A2A spec does not mandate anti-replay controls (no nonce, no mandatory jti validation,
 * no token blacklist). Static credential schemes (API Key, Basic auth) cannot be invalidated
 * after capture and provide zero replay protection. A single intercepted request can be
 * replayed indefinitely to invoke arbitrary tasks.
 *
 * Attack path: Network sniffing / log exposure → attacker captures API key →
 * replays requests with arbitrary task payloads.
 *
 * Only fires when authentication is declared (missing auth is already A2A-001).
 */
export function auditReplayProtection(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  const auth = card.authentication;
  if (auth === undefined || auth === null) return findings;

  const authList: A2AAuthentication[] = Array.isArray(auth) ? auth : [auth];
  const allSchemes = authList.flatMap(a =>
    (a.schemes ?? []).map((s: string) => s.toLowerCase())
  );

  if (allSchemes.length === 0) return findings;

  const hasReplayResistantScheme = allSchemes.some(s =>
    REPLAY_RESISTANT_SCHEMES.some(r => s.includes(r))
  );

  if (!hasReplayResistantScheme) {
    findings.push({
      id: 'A2A-013',
      scanner: SCANNER_ID,
      severity: 'high',
      rule: 'replay-vulnerable-auth',
      title: `Authentication scheme(s) [${allSchemes.join(', ')}] provide no replay protection`,
      description:
        `The declared scheme(s) (${allSchemes.join(', ')}) are static credentials with no ` +
        `built-in freshness mechanism. Unlike OAuth2/JWT (which carry "exp", "iat", "jti" ` +
        `claims), static API keys and Basic auth cannot be scoped to a single request or ` +
        `invalidated after capture. The A2A spec §13 notes replay risk but does not mandate ` +
        `nonces or jti blacklisting. A captured credential can invoke arbitrary tasks indefinitely.`,
      file: source,
      recommendation:
        'Replace static credentials with OAuth2 or OpenID Connect. Mandate short-lived access ' +
        'tokens (exp ≤ 15 min). Implement server-side "jti" claim validation with a nonce ' +
        'blacklist to prevent request replay. See A2A spec §7.',
      confidence: 'definite',
    });
  }

  return findings;
}

/**
 * A2A-014: Capability Escalation via Dangerous Skill Tags
 *
 * The A2A spec §4.3 defines skill "tags" as descriptive metadata. Tags are entirely
 * self-declared with no cryptographic binding to actual server behavior (discussion #1404
 * proposes capability-based authorization but is not yet in the spec). A malicious or
 * compromised agent can advertise elevated privilege tags to manipulate orchestrators
 * into granting it elevated access, deferring to it, or routing sensitive tasks to it.
 *
 * Attack path: Attacker deploys agent with "admin" / "privileged" tags →
 * orchestrator grants elevated permissions → attacker accesses restricted resources.
 */
export function auditCapabilityEscalation(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  if (!Array.isArray(card.skills)) return findings;

  for (const skill of card.skills) {
    const skillId = skill.id ?? skill.name ?? 'unknown';
    const tags = Array.isArray(skill.tags)
      ? skill.tags.map((t: unknown) => String(t).toLowerCase())
      : [];

    const dangerous = tags.filter(t =>
      DANGEROUS_SKILL_TAGS.some(d => t === d || t.includes(d))
    );

    if (dangerous.length > 0) {
      findings.push({
        id: `A2A-014-${String(skillId).replace(/[^a-z0-9]/gi, '_')}`,
        scanner: SCANNER_ID,
        severity: 'high',
        rule: 'capability-escalation-risk',
        title: `Skill "${skillId}" declares elevated-privilege tags: [${dangerous.join(', ')}]`,
        description:
          `Skill "${skillId}" advertises tags [${dangerous.join(', ')}] that claim elevated or ` +
          `unrestricted capabilities. The A2A spec does not cryptographically bind declared ` +
          `capabilities to actual server behavior — these are entirely self-asserted. A malicious ` +
          `agent can advertise false privilege tags to manipulate orchestrators into granting ` +
          `it elevated access or routing sensitive tasks it should not receive.`,
        file: source,
        recommendation:
          `Audit what permissions this skill actually requires. Remove privilege-indicating tags ` +
          `unless they accurately reflect implemented scope. Orchestrators must NOT grant elevated ` +
          `access based solely on self-declared tags — enforce external authorization policies.`,
        confidence: 'definite',
      });
    }
  }

  return findings;
}

/**
 * A2A-015: Task Result Manipulation via Unsafe Output Modes
 *
 * A2A agents can declare their output MIME types via "defaultOutputModes" and per-skill
 * "outputModes". When a skill or agent advertises executable output types (JavaScript,
 * Python, shell scripts, binaries), a compromised intermediary agent can return executable
 * payloads as "task results" that downstream systems may execute or process without validation.
 *
 * Wildcard output modes are equally dangerous: they allow returning any content type.
 *
 * Attack path: Compromised agent M (in an agent chain) returns application/javascript
 * as a task result, caller processes it as executable, RCE.
 */
export function auditOutputModes(card: A2AAgentCard, source: string): Finding[] {
  const findings: Finding[] = [];

  const allModes: Array<{ mode: string; context: string }> = [];

  if (Array.isArray(card.defaultOutputModes)) {
    for (const m of card.defaultOutputModes) {
      allModes.push({ mode: String(m), context: 'defaultOutputModes' });
    }
  }

  if (Array.isArray(card.skills)) {
    for (const skill of card.skills) {
      const skillId = skill.id ?? skill.name ?? 'unknown';
      if (Array.isArray(skill.outputModes)) {
        for (const m of skill.outputModes) {
          allModes.push({ mode: String(m), context: `skill:${skillId}` });
        }
      }
    }
  }

  for (const { mode, context } of allModes) {
    const modeLC = mode.toLowerCase();

    if (HIGH_RISK_OUTPUT_MODES.some(r => modeLC === r)) {
      findings.push({
        id: `A2A-015-${mode.replace(/[^a-z0-9]/gi, '_')}`,
        scanner: SCANNER_ID,
        severity: 'high',
        rule: 'high-risk-output-mode',
        title: `Unsafe outputMode declared: "${mode}" — task result manipulation risk`,
        description:
          `The agent declares "${mode}" as an output mode in [${context}]. This MIME type can ` +
          `carry executable code. A compromised or malicious agent in an agent chain can return ` +
          `executable content as a task result. Systems that process the response without ` +
          `MIME-type validation may execute the attacker-controlled payload.`,
        file: source,
        recommendation:
          `Remove "${mode}" from outputModes. Restrict outputs to safe types (e.g., ` +
          `"text/plain", "application/json"). Callers should validate the Content-Type of ` +
          `task results and refuse to process executable types.`,
        confidence: 'definite',
      });
    }

    if (mode === '*' || mode === '*/*') {
      findings.push({
        id: 'A2A-016',
        scanner: SCANNER_ID,
        severity: 'high',
        rule: 'wildcard-output-mode',
        title: `Wildcard outputMode ("${mode}") allows returning any content type`,
        description:
          `The agent advertises "${mode}" as an output mode in [${context}], meaning it may ` +
          `return any content type including executable formats. Task result manipulation is ` +
          `trivial — a compromised intermediary agent can return executable payloads that ` +
          `callers may process without validation. The A2A spec provides no built-in artifact ` +
          `signing or content-type enforcement on task results.`,
        file: source,
        recommendation:
          'Replace the wildcard with an explicit allowlist of safe output MIME types. ' +
          'Implement output type validation at the caller side.',
        confidence: 'definite',
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
  description: 'Audits A2A protocol agent cards (/.well-known/agent.json) for missing authentication, HTTP endpoints, broad capabilities, unsafe input/output modes, missing card signing, URL identity mismatch, replay-vulnerable auth, capability escalation via skill tags, and missing provider trust anchor',

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
        const { card, source, isHttp, isFetchedUrl } = await resolveAgentCard(target);
        scannedFiles++;

        const cardFindings = [
          ...auditAuthentication(card, source),
          ...auditEndpoints(card, isHttp, source),
          ...auditCapabilities(card, source),
          ...auditInputModes(card, source),
          // New threat vectors
          ...auditCardIntegrity(card, source),
          ...auditUrlIdentity(card, source, isFetchedUrl),
          ...auditProviderTrust(card, source),
          ...auditReplayProtection(card, source),
          ...auditCapabilityEscalation(card, source),
          ...auditOutputModes(card, source),
        ];

        // All config-based findings are definite
        for (const f of cardFindings) f.confidence = 'definite';
        findings.push(...cardFindings);
      } catch (err) {
        // Emit an info finding so the user knows a target was unreachable / unparseable
        const reason = err instanceof Error ? err.message : String(err);
        findings.push({
          id: 'A2A-000',
          scanner: SCANNER_ID,
          severity: 'info',
          rule: 'target-unreachable',
          title: `Could not fetch or parse agent card: ${target}`,
          description: `The target "${target}" was skipped because it could not be fetched or parsed. Reason: ${reason}`,
          file: target,
          recommendation: 'Verify the target URL or file path is reachable and contains valid JSON.',
          confidence: 'definite',
        });
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
