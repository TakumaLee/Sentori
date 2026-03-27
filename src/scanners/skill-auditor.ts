import * as path from 'path';
import { ScannerModule, ScanResult, Finding, Severity, ScanContext, ScannerOptions } from '../types';
import { findFiles, readFileContent, isTestOrDocFile, isFrameworkInfraFile, isUserInputFile, isSkillPluginFile, isSentoriTestFile, isSentoriSourceFile, isSecurityToolFile, isMarkdownFile, isTestFileForScoring, applyContextDowngrades } from '../utils/file-utils';

interface SkillPattern {
  id: string;
  category: string;
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
}

const SKILL_PATTERNS: SkillPattern[] = [
  // === Env Exfiltration (SA-001) ===
  {
    id: 'SA-001',
    category: 'env-exfiltration',
    pattern: /process\.env\b[\s\S]{0,200}(?:fetch|axios|http|request|got|node-fetch|urllib|requests)\s*\(/i,
    severity: 'critical',
    title: 'Environment variable access near network call',
    description: 'Environment variables are accessed close to a network call, suggesting possible exfiltration of secrets.',
    recommendation: 'Audit this code path. Environment variables should not be sent to external services. Use allowlists for env access.',
  },
  {
    id: 'SA-001b',
    category: 'env-exfiltration',
    pattern: /(?:fetch|axios|http|request|got|node-fetch|urllib|requests)\s*\([\s\S]{0,200}process\.env/i,
    severity: 'critical',
    title: 'Network call with environment variable data',
    description: 'A network call appears to include environment variable data, which could exfiltrate secrets.',
    recommendation: 'Never send environment variables to external services. Audit and restrict network calls.',
  },
  {
    id: 'SA-001c',
    category: 'env-exfiltration',
    pattern: /(?:os\.environ|os\.getenv)\s*[\[(][\s\S]{0,200}(?:requests|urllib|httpx|aiohttp)\./i,
    severity: 'critical',
    title: 'Python env access near HTTP call',
    description: 'Python environment variable access detected near HTTP library usage.',
    recommendation: 'Audit this code. Ensure environment variables are not being transmitted externally.',
  },

  // === Data Exfiltration (SA-002) ===
  {
    id: 'SA-002',
    category: 'data-exfiltration',
    pattern: /(?:readFile|readFileSync|open)\s*\([\s\S]{0,100}(?:credential|key|token|secret|password|\.ssh|\.aws|\.env)/i,
    severity: 'critical',
    title: 'Reading sensitive file',
    description: 'Code reads files that commonly contain credentials or secrets.',
    recommendation: 'Restrict file access to only necessary paths. Never read credential files in skill/plugin code.',
  },
  {
    id: 'SA-002b',
    category: 'data-exfiltration',
    pattern: /(?:readFile|readFileSync|open)\s*\([\s\S]{0,300}(?:fetch|axios|http|request|got|post)\s*\(/i,
    severity: 'critical',
    title: 'File read followed by network call',
    description: 'File contents are read and then potentially sent over the network.',
    recommendation: 'Audit file read + network call patterns. Sensitive data should never be transmitted externally.',
  },

  // === Suspicious Shell Commands (SA-003) ===
  {
    id: 'SA-003',
    category: 'shell-commands',
    pattern: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\(\s*['"`](?:curl|wget)\b[^'"`]*\|\s*(?:sh|bash|zsh)/i,
    severity: 'critical',
    title: 'Remote code execution via curl/wget pipe to shell',
    description: 'Downloading and executing remote code via curl/wget piped to shell — a classic supply-chain attack vector.',
    recommendation: 'Never pipe remote content directly to a shell. Download, verify integrity, then execute.',
  },
  {
    id: 'SA-003b',
    category: 'shell-commands',
    pattern: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\(\s*['"`][^'"`]*rm\s+-rf\s+[/"]/i,
    severity: 'critical',
    title: 'Destructive rm -rf command',
    description: 'A destructive rm -rf command targeting root or absolute paths was detected.',
    recommendation: 'Remove destructive shell commands. If cleanup is needed, use safe, scoped deletion methods.',
  },
  {
    id: 'SA-003c',
    category: 'shell-commands',
    pattern: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\(\s*['"`][^'"`]*(?:wget|curl)\s+[^'"`]*-O\s*-?\s*[^'"`]*(?:exec|eval|sh|bash)/i,
    severity: 'critical',
    title: 'Download and execute pattern',
    description: 'Detected download-and-execute pattern combining wget/curl with execution.',
    recommendation: 'Never download and immediately execute files. Verify integrity before execution.',
  },
  {
    id: 'SA-003d',
    category: 'shell-commands',
    pattern: /(?:child_process|subprocess|os\.system|commands)/i,
    severity: 'medium',
    title: 'Shell execution capability imported',
    description: 'Shell execution module is imported, which could be used for arbitrary command execution.',
    recommendation: 'Audit all uses of shell execution. Ensure commands are hardcoded and input is never interpolated.',
  },

  // === Hidden Network Calls (SA-004) ===
  {
    id: 'SA-004',
    category: 'hidden-network',
    pattern: /(?:atob|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*(?:,\s*['"]base64['"])?\)/i,
    severity: 'high',
    title: 'Base64 encoded string (potential obfuscated URL)',
    description: 'A long base64-encoded string was found, which could hide an exfiltration endpoint.',
    recommendation: 'Decode and audit all base64 strings. Obfuscated URLs are a red flag for data exfiltration.',
  },
  {
    id: 'SA-004b',
    category: 'hidden-network',
    pattern: /['"]https?:\/\/['"]?\s*\+\s*(?:[\w.]+|['"][^'"]+['"])\s*\+/i,
    severity: 'high',
    title: 'Dynamic URL construction',
    description: 'URL is built dynamically through string concatenation, potentially hiding the true destination.',
    recommendation: 'Use explicit, auditable URLs. Dynamic URL construction can hide malicious endpoints.',
  },
  {
    id: 'SA-004e',
    category: 'hidden-network',
    pattern: /(?:new\s+)?TextDecoder\s*\([\s\S]{0,100}(?:fetch|http|request|axios|url)/i,
    severity: 'high',
    title: 'TextDecoder near network call',
    description: 'TextDecoder is used near network call functionality, potentially decoding obfuscated URLs or payloads.',
    recommendation: 'Audit TextDecoder usage. Ensure decoded content is not used to construct hidden network endpoints.',
  },
  {
    id: 'SA-004c',
    category: 'hidden-network',
    pattern: /(?:String\.fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})\s*[\s\S]{0,50}(?:fetch|http|request|axios)/i,
    severity: 'high',
    title: 'Obfuscated code near network call',
    description: 'Character code obfuscation detected near network call functionality.',
    recommendation: 'Remove code obfuscation. All network endpoints should be clearly visible for audit.',
  },
  {
    id: 'SA-004d',
    category: 'hidden-network',
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURI|unescape)/i,
    severity: 'critical',
    title: 'Eval with decoded content',
    description: 'eval() is called with decoded content, a strong indicator of obfuscated malicious code.',
    recommendation: 'Never use eval() with decoded content. This is a critical security anti-pattern.',
  },

  // === Privilege Escalation (SA-005) ===
  {
    id: 'SA-005',
    category: 'privilege-escalation',
    pattern: /(?:exec|execSync|spawn|system|popen)\s*\(\s*['"`][^'"`]*sudo\b/i,
    severity: 'critical',
    title: 'sudo command execution',
    description: 'Code attempts to run commands with sudo privileges.',
    recommendation: 'Skills/plugins should never require sudo. Redesign to operate within normal user permissions.',
  },
  {
    id: 'SA-005b',
    category: 'privilege-escalation',
    pattern: /chmod\s+777/i,
    severity: 'high',
    title: 'chmod 777 — world-writable permissions',
    description: 'Setting files to chmod 777 makes them readable, writable, and executable by everyone.',
    recommendation: 'Use minimal permissions (e.g., 644 for files, 755 for executables). Never use 777.',
  },
  {
    id: 'SA-005c',
    category: 'privilege-escalation',
    pattern: /(?:setuid|setgid|seteuid|setegid)\s*\(/i,
    severity: 'critical',
    title: 'Privilege elevation via setuid/setgid',
    description: 'Code attempts to change effective user/group ID, which is a privilege escalation vector.',
    recommendation: 'Skills should not change user/group IDs. Remove setuid/setgid calls.',
  },

  // === Filesystem Overreach (SA-006) ===
  {
    id: 'SA-006',
    category: 'filesystem-overreach',
    pattern: /(?:readFile|readFileSync|open|fs\.read)\s*\(\s*['"`][^'"`]*(?:\.\.\/\.\.\/|\.\.\\\.\.\\)/i,
    severity: 'high',
    title: 'Path traversal attempt (../../)',
    description: 'Code reads files using path traversal sequences to access parent directories.',
    recommendation: 'Use path.resolve() and validate that resolved paths stay within the workspace.',
  },
  {
    id: 'SA-006b',
    category: 'filesystem-overreach',
    pattern: /(?:readFile|readFileSync|open|fs\.read)\s*\(\s*['"`]\/etc\//i,
    severity: 'high',
    title: 'Reading system files (/etc/)',
    description: 'Code attempts to read system configuration files from /etc/.',
    recommendation: 'Skills should not access system files. Restrict file access to the workspace directory.',
  },
  {
    id: 'SA-006c',
    category: 'filesystem-overreach',
    pattern: /(?:readFile|readFileSync|open|fs\.read)\s*\(\s*['"`](?:\/root\/|~\/|\/home\/)/i,
    severity: 'high',
    title: 'Reading user home directory files',
    description: 'Code attempts to read files from user home directories.',
    recommendation: 'Restrict file access to the designated workspace. Do not access user home directories.',
  },
  {
    id: 'SA-006d',
    category: 'filesystem-overreach',
    pattern: /(?:readFile|readFileSync|open)\s*\(\s*['"`][^'"`]*(?:\.ssh|\.aws|\.gnupg|\.kube|\.docker)/i,
    severity: 'critical',
    title: 'Accessing sensitive dot-directories',
    description: 'Code attempts to read from sensitive dot-directories (.ssh, .aws, .gnupg, etc.).',
    recommendation: 'Never access sensitive dot-directories from skills/plugins. These contain authentication credentials.',
  },
];

export function auditSkillContent(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const sp of SKILL_PATTERNS) {
    // Test full content for multi-line patterns
    if (sp.pattern.test(content)) {
      // Find the approximate line
      let matchLine: number | undefined;
      for (let i = 0; i < lines.length; i++) {
        // Check individual lines for single-line patterns, or nearby lines for multi-line
        if (sp.pattern.test(lines[i]) ||
            (i > 0 && sp.pattern.test(lines[i - 1] + '\n' + lines[i])) ||
            (i < lines.length - 1 && sp.pattern.test(lines[i] + '\n' + lines[i + 1]))) {
          matchLine = i + 1;
          break;
        }
      }

      findings.push({
        id: `${sp.id}-${filePath}-${matchLine || 0}`,
        scanner: 'skill-auditor',
        severity: sp.severity,
        title: sp.title,
        description: `${sp.description} Found in ${filePath}${matchLine ? ` near line ${matchLine}` : ''}.`,
        file: filePath,
        line: matchLine,
        recommendation: sp.recommendation,
        confidence: 'likely',
      });
    }
  }

  return findings;
}

/**
 * Apply framework-aware severity downgrades.
 * Only called when --context framework is active.
 */
export function applyFrameworkDowngrades(findings: Finding[], filePath: string): void {
  const inFrameworkDir = isFrameworkInfraFile(filePath);
  const inUserInputFile = isUserInputFile(filePath);
  const inSkillPlugin = isSkillPluginFile(filePath);

  for (const f of findings) {
    // Path traversal (SA-006): downgrade in framework infra, keep in user-input files
    if (f.id!.startsWith('SA-006-') && inFrameworkDir && !inUserInputFile) {
      if (f.severity === 'high') {
        f.severity = 'medium';
        f.description += ' [Framework infrastructure file — path traversal less likely to be exploitable here.]';
      }
    }

    // Shell execution capability (SA-003d): downgrade in core, keep in skills/plugins
    if (f.id!.startsWith('SA-003d-') && !inSkillPlugin) {
      if (f.severity === 'medium') {
        f.severity = 'info';
        f.description += ' [Framework-level shell capability — expected for AI Agent runtimes. Verify input sanitization before command execution.]';
      }
    }

    // .env / credential file reading (SA-002): downgrade if not combined with network exfil
    // SA-001/SA-001b/SA-001c are env exfiltration (keep critical)
    // SA-002 "Reading sensitive file" — downgrade standalone reads (not SA-002b which is read+network)
    if (f.id!.startsWith('SA-002-') && f.title === 'Reading sensitive file') {
      f.severity = 'info';
      f.description += ' [Standard environment variable loading (12-factor app pattern). Verify .env is in .gitignore.]';
    }
  }
}

/**
 * Detect API client files where env+network patterns (SA-001) are expected.
 * Heuristic: path or filename contains api/client/provider/sdk/service keywords,
 * or content contains common API client patterns.
 */
function isApiClientFile(filePath: string, content: string): boolean {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const basename = path.basename(normalized);
  const pathKeywords = ['api', 'client', 'provider', 'sdk', 'service'];
  const basenameKeywords = ['client', 'api', 'provider', 'auth'];
  if (pathKeywords.some(k => normalized.includes('/' + k + '/') || normalized.includes('/' + k + '.'))) return true;
  if (basenameKeywords.some(k => basename.includes(k))) return true;
  if (/\b(?:baseURL|Authorization:|Bearer |apiKey|api_key)\b/.test(content)) return true;
  return false;
}

export const skillAuditor: ScannerModule = {
  name: 'Skill Auditor',
  description: 'Scans third-party skills, plugins, and tools for suspicious behavior including data exfiltration, shell injection, and privilege escalation',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const context = options?.context || 'app';

    const files = await findFiles(targetPath, [
      '**/*.js',
      '**/*.ts',
      '**/*.py',
      '**/*.sh',
    ], options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    for (const file of files) {
      try {
        const content = readFileContent(file);
        const fileFindings = auditSkillContent(content, file);

        // Framework context: apply smart downgrades
        if (context === 'framework') {
          applyFrameworkDowngrades(fileFindings, file);
        }

        // App context (default): SA-003d shell imports are normal for agent tools
        if (context === 'app') {
          for (const f of fileFindings) {
            if (f.id!.startsWith('SA-003d-') && f.severity === 'medium') {
              f.severity = 'info';
              f.description += ' [App context: shell execution is a normal capability for AI agent tools.]';
            }
          }
        }

        // Sentori's own source/test files: pattern definitions, not vulnerabilities
        // Test/doc: severity reduced.
        applyContextDowngrades(fileFindings, file);

        // Security tools (detector, scanner, auditor, guard) reading credential
        // paths is normal behavior — they need to detect credential leaks
        if (isSecurityToolFile(file, content)) {
          for (const f of fileFindings) {
            if (f.id!.startsWith('SA-002-') && f.title === 'Reading sensitive file' && f.severity !== 'info') {
              f.severity = 'info';
              f.description += ' [security tool file — reading credential paths for detection is expected behavior]';
            }
          }
        }

        // API client files: SA-001 env+network patterns are expected behavior
        if (isApiClientFile(file, content)) {
          for (const f of fileFindings) {
            if (f.id!.startsWith('SA-001') && f.severity !== 'info') {
              f.severity = 'info';
              f.description += ' [API client file — authorization headers are expected behavior]';
            }
          }
        }

        findings.push(...fileFindings);
      } catch {
        // Skip unreadable files
      }
    }

    return {
      scanner: 'Skill Auditor',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};
