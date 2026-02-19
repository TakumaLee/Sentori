import { ScannerModule, ScanResult, Finding, ScanContext, ScannerOptions } from '../types';
import { findPromptFiles, readFileContent, isTestOrDocFile, isCredentialManagementFile, isSentoriTestFile, isSentoriSourceFile, isMarkdownFile, isInCommentOrCodeBlock, isTestFileForScoring } from '../utils/file-utils';
import { SECRET_PATTERNS, SENSITIVE_PATH_PATTERNS } from '../patterns/injection-patterns';
import { getGitTrackingStatus } from '../utils/git-utils';

export const secretLeakScanner: ScannerModule = {
  name: 'Secret Leak Scanner',
  description: 'Scans system prompts, tool definitions, and configuration files for hardcoded secrets, API keys, tokens, and sensitive paths',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const context = options?.context || 'app';
    const files = await findPromptFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    // Get git tracking status for all files (batch)
    const gitStatus = getGitTrackingStatus(targetPath, files);

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const fileFindings = [
          ...scanForSecrets(content, file),
          ...scanForSensitivePaths(content, file),
          ...scanForHardcodedCredentials(content, file),
        ];

        // Framework context: downgrade credential management files
        if (context === 'framework' && isCredentialManagementFile(file)) {
          for (const f of fileFindings) {
            if (f.severity !== 'info') {
              f.severity = 'info';
              f.description += ' [Credential management module — reading secrets is this module\'s intended function. Verify secrets are not logged or exposed.]';
            }
          }
        }

        // Sentori's own source/test files: pattern definitions, not real secrets
        if (isSentoriTestFile(file)) {
          for (const f of fileFindings) {
            if (f.severity !== 'info') {
              f.severity = 'info';
              f.description += ' [security tool test file — intentional attack sample]';
            }
            f.isTestFile = true;
          }
        } else if (isSentoriSourceFile(file)) {
          for (const f of fileFindings) {
            if (f.severity !== 'info') {
              f.severity = 'info';
              f.description += ' [Sentori source file — pattern definition, not a real secret]';
            }
          }
        } else if (isMarkdownFile(file)) {
          // Markdown files discussing security topics are documentation
          for (const f of fileFindings) {
            if (f.severity === 'critical') f.severity = 'medium';
            else if (f.severity === 'high') f.severity = 'info';
            f.description += ' [markdown file — technical discussion, not a real secret]';
          }
        } else if (isTestOrDocFile(file)) {
          // Downgrade test/doc findings
          for (const f of fileFindings) {
            if (f.severity === 'critical') f.severity = 'medium';
            else if (f.severity === 'high') f.severity = 'info';
            f.description += ' [test/doc file — severity reduced]';
          }
        }

        // Git-tracking aware severity adjustment for API keys / tokens
        const trackingStatus = gitStatus.get(file) || 'unknown';
        for (const f of fileFindings) {
          if (isSecretOrTokenFinding(f) && f.severity === 'critical') {
            if (trackingStatus === 'untracked') {
              // Local config file, not tracked by git — lower risk
              f.severity = 'medium';
              f.description += ' Found in local config (not tracked by git) — ensure file permissions are restricted';
              f.recommendation = 'This secret is in a local file not tracked by git. Ensure file permissions are restricted and consider using a secret manager.';
            } else if (trackingStatus === 'tracked') {
              // Git-tracked — keep CRITICAL
              f.description += ' Found in git-tracked file — this may be exposed in your repository!';
              f.recommendation = 'URGENT: This secret is in a git-tracked file and may be exposed in your repository! Remove it immediately, rotate the credential, and use environment variables or a secret manager.';
            }
          }
        }

        // Mark test file findings for scoring exclusion
        if (isTestFileForScoring(file)) {
          for (const f of fileFindings) {
            f.isTestFile = true;
            if (!f.title!.startsWith('[TEST]')) {
              f.title! = `[TEST] ${f.title!}`;
            }
          }
        }

        findings.push(...fileFindings);
      } catch {
        // Skip unreadable files
      }
    }

    // Confidence: definite — pattern-matched secrets are concrete evidence
    for (const f of findings) f.confidence = 'definite';

    return {
      scanner: 'Secret Leak Scanner',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

export function scanForSecrets(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const secret of SECRET_PATTERNS) {
      if (secret.pattern.test(lines[i])) {
        // Don't flag obvious placeholders
        const line = lines[i];
        if (isPlaceholder(line)) continue;

        // Context-aware severity
        let severity: 'critical' | 'high' | 'medium' | 'info' = 'critical';
        let note = '';

        if (filePath && isPlatformConfigFile(filePath) && PLATFORM_SAFE_SECRET_IDS.has(secret.id)) {
          severity = 'info';
          note = ` [${PLATFORM_CONFIG_NOTE}]`;
        } else if (isDevCredential(lines[i])) {
          severity = 'medium';
          note = ' [common dev value — likely not a real secret]';
        } else if (filePath && isExampleFile(filePath)) {
          severity = 'info';
          note = ' [example/template file — not real secrets]';
        }

        findings.push({
          id: `${secret.id}-${filePath}-${i + 1}`,
          scanner: 'secret-leak-scanner',
          severity,
          title: `Potential secret detected: ${secret.description}`,
          description: `Found pattern matching "${secret.description}" at line ${i + 1}. Value: "${maskValue(lines[i].trim(), 80)}"${note}`,
          file: filePath,
          line: i + 1,
          recommendation: severity === 'critical'
            ? 'Remove hardcoded secrets. Use environment variables, secret managers, or vault services instead.'
            : 'Verify this is not a real secret. If it is, move to environment variables or a secret manager.',
        });
      }
    }
  }

  return findings;
}

export function scanForSensitivePaths(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    for (const pathPattern of SENSITIVE_PATH_PATTERNS) {
      if (pathPattern.pattern.test(lines[i])) {
        // For SP-003 (.env): downgrade prose mentions to info
        let severity: 'critical' | 'high' | 'medium' | 'info' = 'high';
        let note = '';

        // Sensitive paths (e.g. /etc/passwd) in comments or markdown code blocks
        // are documentation/examples, not actual vulnerabilities
        if (isInCommentOrCodeBlock(lines[i])) {
          severity = 'info';
          note = ' [in comment/code block — example reference, not a vulnerability]';
        }
        if (pathPattern.id === 'SP-003') {
          // Check if this is a prose/doc mention vs actual file reference
          const line = lines[i];
          const isProseContext = isEnvProseMention(line);
          if (isProseContext) {
            severity = 'info';
            note = ' [textual mention of .env — not a file path reference]';
          }
        }

        // Downgrade example/template env files
        if (filePath && isEnvExampleFile(filePath)) {
          severity = 'info';
          note = ' [example/template env file — not real secrets]';
        }

        findings.push({
          id: `${pathPattern.id}-${filePath}-${i + 1}`,
          scanner: 'secret-leak-scanner',
          severity,
          title: `Sensitive path reference: ${pathPattern.description}`,
          description: `Found reference to sensitive path at line ${i + 1}: "${lines[i].trim().substring(0, 100)}"${note}`,
          file: filePath,
          line: i + 1,
          recommendation: severity === 'info'
            ? 'This appears to be a documentation reference or example file. Verify no real secrets are exposed.'
            : 'Avoid referencing sensitive system paths in prompts or tool definitions. These paths can be used for social engineering attacks.',
        });
      }
    }
  }

  return findings;
}

/**
 * Check if a line is a prose/documentation mention of .env rather than an actual file path reference.
 * Prose indicators: surrounded by explanatory text, in comments, in markdown, etc.
 */
function isEnvProseMention(line: string): boolean {
  const lower = line.toLowerCase().trim();
  // Prose patterns: explaining what .env is, mentioning it in documentation context
  const proseIndicators = [
    /copy\s+.*\.env/i,
    /create\s+.*\.env/i,
    /rename\s+.*\.env/i,
    /fill\s+in/i,
    /add\s+your/i,
    /set\s+up/i,
    /configure/i,
    /see\s+.*\.env/i,
    /refer\s+to/i,
    /check\s+(the\s+)?\.env/i,
    /store[sd]?\s+in\s+.*\.env/i,
    /use\s+.*\.env/i,
    /loaded?\s+from\s+.*\.env/i,
    /variable/i,
    /environment/i,
    /^[\s*#/-]/,  // Starts with comment/list markers
  ];
  // If line is short and just a path, it's a reference not prose
  if (/^\s*\.env\s*$/.test(line)) return false;
  // If it has prose indicators, it's a documentation mention
  return proseIndicators.some(p => p.test(lower));
}

/**
 * Check if file is a .env example/template that shouldn't contain real secrets.
 */
function isEnvExampleFile(filePath: string): boolean {
  const ENV_EXAMPLE_PATTERNS = [
    /\.env\.example$/i,
    /\.env\.template$/i,
    /\.env\.sample$/i,
    /\.env\.dev$/i,
    /\.env\.staging$/i,
    /\.env\.dist$/i,
  ];
  return ENV_EXAMPLE_PATTERNS.some(p => p.test(filePath));
}

export function scanForHardcodedCredentials(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  // Look for common credential patterns in code
  const credPatterns = [
    { pattern: /(?:username|user)\s*[:=]\s*['"][^'"]{2,}['"]/i, desc: 'Hardcoded username' },
    { pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{2,}['"]/i, desc: 'Hardcoded password' },
    { pattern: /(?:host|hostname|server)\s*[:=]\s*['"](?:\d{1,3}\.){3}\d{1,3}['"]/i, desc: 'Hardcoded IP address' },
    { pattern: /(?:api[_-]?url|endpoint|base[_-]?url)\s*[:=]\s*['"]https?:\/\/[^'"]+['"]/i, desc: 'Hardcoded API endpoint' },
  ];

  for (let i = 0; i < lines.length; i++) {
    if (isPlaceholder(lines[i])) continue;

    for (const cred of credPatterns) {
      if (cred.pattern.test(lines[i])) {
        // Downgrade dev credentials and example files
        let severity: 'critical' | 'high' | 'medium' | 'info' = 'medium';
        let note = '';
        if (isDevCredential(lines[i])) {
          severity = 'info';
          note = ' [common dev value]';
        } else if (filePath && isExampleFile(filePath)) {
          severity = 'info';
          note = ' [example/template file]';
        }

        findings.push({
          id: `HC-${cred.desc.replace(/\s+/g, '-')}-${filePath}-${i + 1}`,
          scanner: 'secret-leak-scanner',
          severity,
          title: cred.desc,
          description: `Found ${cred.desc.toLowerCase()} at line ${i + 1}: "${maskValue(lines[i].trim(), 80)}"${note}`,
          file: filePath,
          line: i + 1,
          recommendation: severity === 'info'
            ? 'This appears to be a development/example value. Ensure it is not used in production.'
            : 'Use environment variables or configuration files outside the repository for credentials.',
        });
      }
    }
  }

  return findings;
}

function isPlaceholder(line: string): boolean {
  const lower = line.toLowerCase();
  const placeholders = [
    'your_', 'xxx', 'placeholder', '<your', 'example',
    'change_me', 'todo', 'fixme', 'replace', 'insert_',
    '${', 'process.env', 'os.environ', 'env.',
    'dummy', 'sample', 'mock', 'fake', 'default',
    'template', 'changeme', 'fill_in', 'put_your',
    '<insert', '<api', '<token', '<key', '<secret',
    '...', 'n/a', 'none', 'null', 'undefined',
  ];
  return placeholders.some(p => lower.includes(p));
}

// Common dev/example passwords and values that aren't real secrets
const DEV_CREDENTIALS = [
  'postgres', 'root', 'admin', 'password', 'test', 'dev',
  'localhost', 'development', 'staging', 'debug', 'demo',
  '123456', 'secret', 'pass', 'guest', 'user', 'default',
  'changeme', 'example', 'foobar', 'qwerty',
];

// Files that typically contain example/template credentials
const EXAMPLE_FILE_PATTERNS = [
  /\.example$/i,
  /\.sample$/i,
  /\.template$/i,
  /\.dist$/i,
  /\.default$/i,
  /example/i,
  /sample/i,
  /template/i,
  /docker-compose.*\.ya?ml$/i,   // dev docker configs
  /\.env\..*$/i,                   // .env.example, .env.local, etc.
];

function isExampleFile(filePath: string): boolean {
  return EXAMPLE_FILE_PATTERNS.some(p => p.test(filePath));
}

// Platform config files where API keys/client IDs are expected and restricted by package/bundle signing
const PLATFORM_CONFIG_PATTERNS = [
  /google-services\.json$/i,
  /GoogleService-Info\.plist$/i,
  /AndroidManifest\.xml$/i,
  /\.xcconfig$/i,
  /Info\.plist$/i,
];

const PLATFORM_CONFIG_NOTE = 'Platform config file — API identifiers are typically safe when restricted by package/bundle signing. Verify restrictions on Google Cloud Console.';

// Secret patterns that are expected in platform config files (API keys, OAuth client IDs)
const PLATFORM_SAFE_SECRET_IDS = new Set([
  'SL-001', // API key assignment
  'SL-013', // Google API key (AIza...)
  'SL-014', // Google OAuth client ID
]);

function isPlatformConfigFile(filePath: string): boolean {
  return PLATFORM_CONFIG_PATTERNS.some(p => p.test(filePath));
}

function isDevCredential(line: string): boolean {
  const lower = line.toLowerCase();
  // Check if the value part matches known dev credentials
  const valueMatch = lower.match(/[:=]\s*['"]?([^'"}\s]+)/);
  if (!valueMatch) return false;
  const value = valueMatch[1].toLowerCase();
  return DEV_CREDENTIALS.some(dev => value === dev || value.startsWith(dev + '_'));
}

/**
 * Check if a finding is related to API keys, tokens, or secrets
 * (as opposed to hardcoded credentials or sensitive paths).
 */
function isSecretOrTokenFinding(finding: Finding): boolean {
  const secretFindingPatterns = [
    /api[_-]?key/i,
    /token/i,
    /secret/i,
    /SL-/,  // Secret Leak pattern IDs
  ];
  return secretFindingPatterns.some(p => p.test(finding.id ?? '') || p.test(finding.title ?? ''));
}

function maskValue(text: string, maxLen: number): string {
  const truncated = text.length > maxLen ? text.substring(0, maxLen) + '...' : text;
  // Mask anything that looks like a secret value
  return truncated.replace(/((?:key|secret|token|password|passwd|pwd)\s*[=:]\s*['"]?)([^'"\s]{4})[^'"\s]*/gi,
    '$1$2****');
}
