import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScannerOptions, ScanResult, Finding, Severity } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';
import defaultIOC from '../data/ioc-blocklist.json';

// --- Rule definitions ---

interface Rule {
  id: string;
  severity: Severity;
  check(file: FileEntry): Finding[];
}

// --- Helpers ---

const BASE64_REGEX = /[A-Za-z0-9+/]{50,}={0,2}/g;
const SUSPICIOUS_DECODED = /\b(curl|wget|bash|sh|chmod|exec|eval)\b/i;

/**
 * Determine if a file path belongs to third-party dependencies vs own source code.
 * Third-party includes: node_modules/, venv/, .venv/, vendor/, site-packages/, etc.
 */
function isThirdPartyCode(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const thirdPartyPatterns = [
    /\/node_modules\//,
    /\/\.venv\//,
    /\/venv\//,
    /\/vendor\//,
    /\/site-packages\//,
    /\/\.tox\//,
    /\/\.eggs\//,
    /\/bower_components\//,
    /\/jspm_packages\//,
  ];
  return thirdPartyPatterns.some((pattern) => pattern.test(normalized));
}

function isValidBase64(s: string): boolean {
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf-8');
    // Check if decoding produced mostly printable ASCII
    const printable = decoded.replace(/[^\x20-\x7E\n\r\t]/g, '');
    return printable.length > decoded.length * 0.7;
  } catch {
    return false;
  }
}

function decodeBase64(s: string): string {
  return Buffer.from(s, 'base64').toString('utf-8');
}

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split('\n').length;
}

// --- IOC loading ---

export interface IOCBlocklist {
  malicious_ips: string[];
  malicious_domains: string[];
}

export function loadIOC(externalPath?: string): IOCBlocklist {
  const base: IOCBlocklist = { ...defaultIOC };
  if (externalPath && fs.existsSync(externalPath)) {
    try {
      const ext: IOCBlocklist = JSON.parse(fs.readFileSync(externalPath, 'utf-8'));
      if (ext.malicious_ips) {
        base.malicious_ips = [...new Set([...base.malicious_ips, ...ext.malicious_ips])];
      }
      if (ext.malicious_domains) {
        base.malicious_domains = [...new Set([...base.malicious_domains, ...ext.malicious_domains])];
      }
    } catch {
      // ignore malformed external IOC
    }
  }
  return base;
}

// --- Rules ---

const base64Rule: Rule = {
  id: 'SUPPLY-001',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    let match: RegExpExecArray | null;
    const regex = new RegExp(BASE64_REGEX.source, 'g');
    while ((match = regex.exec(file.content)) !== null) {
      const candidate = match[0];
      if (!isValidBase64(candidate)) continue;
      const decoded = decodeBase64(candidate);
      if (SUSPICIOUS_DECODED.test(decoded)) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-001',
          severity: 'high',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: 'Suspicious Base64-encoded command detected',
          evidence: `Decoded: ${decoded.substring(0, 120)}`,
          isThirdParty,
        });
      }
    }
    return findings;
  },
};

const RCE_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /curl\s+[^\n]*\|\s*(bash|sh|zsh)\b/gi, desc: 'curl pipe to shell' },
  { pattern: /wget\s+[^\n]*\|\s*(bash|sh|zsh)\b/gi, desc: 'wget pipe to shell' },
  { pattern: /\beval\s*\(/gi, desc: 'eval() call' },
  { pattern: /\bexec\s*\(/gi, desc: 'exec() call' },
  { pattern: /\bbash\s+-c\b/gi, desc: 'bash -c execution' },
  { pattern: /chmod\s+\+x\s+[^\n;]+;\s*\.?\//gi, desc: 'chmod +x then execute' },
  { pattern: /curl\s+[^\n]*-o\s+[^\n;]+;\s*(bash|sh|\.\/)/gi, desc: 'download and execute' },
  { pattern: /wget\s+[^\n]*-O\s+[^\n;]+;\s*(bash|sh|\.\/)/gi, desc: 'download and execute' },
];

const rceRule: Rule = {
  id: 'SUPPLY-002',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    for (const { pattern, desc } of RCE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-002',
          severity: 'critical',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Remote code execution: ${desc}`,
          evidence: match[0].substring(0, 120),
          isThirdParty,
        });
      }
    }
    return findings;
  },
};

function createIOCRule(ioc: IOCBlocklist): Rule {
  return {
    id: 'SUPPLY-003',
    severity: 'critical',
    check(file: FileEntry): Finding[] {
      const findings: Finding[] = [];
      const isThirdParty = isThirdPartyCode(file.path);
      for (const ip of ioc.malicious_ips) {
        let idx = file.content.indexOf(ip);
        while (idx !== -1) {
          findings.push({
            scanner: 'SupplyChainScanner',
            rule: 'SUPPLY-003',
            severity: 'critical',
            file: file.relativePath,
            line: findLineNumber(file.content, idx),
            message: `Known malicious IP detected: ${ip}`,
            evidence: ip,
            isThirdParty,
          });
          idx = file.content.indexOf(ip, idx + 1);
        }
      }
      for (const domain of ioc.malicious_domains) {
        let idx = file.content.indexOf(domain);
        while (idx !== -1) {
          findings.push({
            scanner: 'SupplyChainScanner',
            rule: 'SUPPLY-003',
            severity: 'critical',
            file: file.relativePath,
            line: findLineNumber(file.content, idx),
            message: `Known malicious domain detected: ${domain}`,
            evidence: domain,
            isThirdParty,
          });
          idx = file.content.indexOf(domain, idx + 1);
        }
      }
      return findings;
    },
  };
}

const CREDENTIAL_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /osascript[^\n]*display\s+dialog[^\n]*password/gi, desc: 'osascript password dialog' },
  { pattern: /security\s+find-generic-password/gi, desc: 'keychain password access' },
  { pattern: /\bsudo\s+-S\b/gi, desc: 'sudo with stdin password' },
  { pattern: /osascript[^\n]*keystroke[^\n]*password/gi, desc: 'osascript keystroke password' },
  { pattern: /display\s+dialog[^\n]*hidden\s+answer/gi, desc: 'hidden dialog password prompt' },
];

const credentialRule: Rule = {
  id: 'SUPPLY-004',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    for (const { pattern, desc } of CREDENTIAL_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-004',
          severity: 'critical',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Credential theft: ${desc}`,
          evidence: match[0].substring(0, 120),
          isThirdParty,
        });
      }
    }
    return findings;
  },
};

const EXFIL_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /(?:zip|tar)\s+[^\n]*(?:curl|wget)\s+[^\n]*(?:POST|PUT|-X\s+(?:POST|PUT)|-T\s)/gi, desc: 'archive and upload' },
  { pattern: /curl\s+[^\n]*(?:POST|PUT|-X\s+(?:POST|PUT)|-T\s)[^\n]*\.(zip|tar|gz|tgz)/gi, desc: 'upload archive via curl' },
  { pattern: /(?:Desktop|Documents|Downloads)[^\n]*(?:zip|tar)\b/gi, desc: 'archiving user directories' },
  { pattern: /find\s+[^\n]*(?:Desktop|Documents|Downloads)[^\n]*-exec/gi, desc: 'bulk operation on user directories' },
  { pattern: /(?:zip|tar)\s+[^\n]+(?:Desktop|Documents|Downloads)/gi, desc: 'archiving user directories' },
];

const exfilRule: Rule = {
  id: 'SUPPLY-005',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    for (const { pattern, desc } of EXFIL_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-005',
          severity: 'high',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Data exfiltration: ${desc}`,
          evidence: match[0].substring(0, 120),
          isThirdParty,
        });
      }
    }
    return findings;
  },
};

const PERSISTENCE_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /LaunchAgents?[/\\]/gi, desc: 'LaunchAgent modification' },
  { pattern: /LaunchDaemons?[/\\]/gi, desc: 'LaunchDaemon modification' },
  { pattern: /\.plist\b[^\n]*(?:write|cp|mv|cat\s*>)/gi, desc: 'plist file manipulation' },
  { pattern: /\bcrontab\b/gi, desc: 'crontab modification' },
  { pattern: /(?:>>?|tee\s+-?a)\s*~?\/?[^\n]*\.(bashrc|zshrc|bash_profile|profile|zprofile)/gi, desc: 'shell init modification' },
  { pattern: /ProgramArguments/gi, desc: 'LaunchAgent ProgramArguments key' },
];

const persistenceRule: Rule = {
  id: 'SUPPLY-006',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    for (const { pattern, desc } of PERSISTENCE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-006',
          severity: 'high',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Persistence mechanism: ${desc}`,
          evidence: match[0].substring(0, 120),
          isThirdParty,
        });
      }
    }
    return findings;
  },
};

// --- Python Supply Chain Rules ---

/** Known malicious or typosquatted PyPI package names */
const MALICIOUS_PYTHON_PACKAGES: Array<{ name: string; reason: string }> = [
  // Typosquatting of popular packages
  { name: 'setup-tools', reason: 'typosquatting setuptools' },
  { name: 'colourama', reason: 'typosquatting colorama' },
  { name: 'colurama', reason: 'typosquatting colorama' },
  { name: 'requets', reason: 'typosquatting requests' },
  { name: 'request', reason: 'typosquatting requests (singular)' },
  { name: 'python-dateutil2', reason: 'typosquatting python-dateutil' },
  { name: 'py-openssl', reason: 'typosquatting pyOpenSSL' },
  { name: 'urlib3', reason: 'typosquatting urllib3' },
  { name: 'urllib', reason: 'typosquatting urllib3 / stdlib masquerade' },
  { name: 'pycrypto', reason: 'abandoned/compromised; use pycryptodome' },
  { name: 'openssl', reason: 'fake PyPI masquerade of OpenSSL C library' },
  { name: 'builtins', reason: 'PyPI masquerade of Python stdlib builtins' },
  { name: 'ctx', reason: 'known malicious package (supply-chain attack 2022)' },
  { name: 'b4nana', reason: 'known malicious test package' },
  { name: 'importantpackage', reason: 'known malicious package' },
  { name: 'importantlib', reason: 'known malicious package' },
  { name: 'loglib-modules', reason: 'known malicious package' },
  { name: 'httpx-async', reason: 'typosquatting httpx' },
  { name: 'aiohttp-requests', reason: 'suspicious combination package' },
  { name: 'python-sqlite', reason: 'fake package masquerading stdlib sqlite3' },
  { name: 'python-jwt', reason: 'malicious package (CVE-2022-39227)' },
  { name: 'pyjwt2', reason: 'typosquatting PyJWT' },
  { name: 'pytest-async', reason: 'typosquatting pytest-asyncio' },
  { name: 'nmap', reason: 'fake PyPI nmap masquerade' },
  { name: 'pip', reason: 'PyPI pip masquerade (do not install pip as a dependency)' },
  { name: 'python3', reason: 'PyPI python3 masquerade' },
];

/** Check whether a filename is a Python dependency manifest */
function isPythonDepFile(filename: string): boolean {
  const base = path.basename(filename).toLowerCase();
  return (
    base === 'requirements.txt' ||
    base.startsWith('requirements') && base.endsWith('.txt') ||
    base === 'pyproject.toml' ||
    base === 'setup.py' ||
    base === 'setup.cfg' ||
    base === 'pipfile' ||
    base === 'pipfile.lock'
  );
}

/**
 * Extract package names from a requirements.txt-style line.
 * Handles: pkg==1.0, pkg>=1.0, pkg[extra], pkg @ url, -r other.txt, etc.
 */
function extractRequirementsPkgName(line: string): string | null {
  const trimmed = line.trim();
  // Skip comments, blank lines, options flags
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) return null;
  // Handle VCS / URL requirements — keep raw for URL scanning
  if (trimmed.includes('://')) return null;
  // Strip extras, version specifiers, environment markers
  const match = trimmed.match(/^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)/);
  return match ? match[1].toLowerCase() : null;
}

/** Normalize PyPI package name: lowercase, replace - and _ */
function normalizePkg(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

const SUSPICIOUS_REQUIREMENT_URL = /(?:git\+https?|git\+ssh|hg\+https?|svn\+https?|https?):\/\/(?!github\.com|gitlab\.com|bitbucket\.org|pypi\.org|files\.pythonhosted\.org)[^\s#]+/gi;

const pythonPackageRule: Rule = {
  id: 'SUPPLY-007',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    if (!isPythonDepFile(file.path)) return [];
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    const lines = file.content.split('\n');

    const maliciousNormalized = new Map(
      MALICIOUS_PYTHON_PACKAGES.map((p) => [normalizePkg(p.name), p.reason])
    );

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const pkgName = extractRequirementsPkgName(line);
      if (!pkgName) continue;
      const normalized = normalizePkg(pkgName);
      const reason = maliciousNormalized.get(normalized);
      if (reason) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-007',
          severity: 'critical',
          file: file.relativePath,
          line: i + 1,
          message: `Known malicious/typosquatted Python package: ${pkgName} (${reason})`,
          evidence: line.trim().substring(0, 120),
          isThirdParty,
        });
      }
    }

    // Also scan pyproject.toml and setup.py for package names in string context
    if (file.path.endsWith('pyproject.toml') || file.path.endsWith('setup.py') || file.path.endsWith('setup.cfg')) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Match quoted package names in dependency arrays/lists
        const pkgMatches = line.matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*(?:\[.*?\])?(?:[>=<!~^][^\s"',;]+)?)/g);
        for (const m of pkgMatches) {
          const rawName = m[1].split(/[>=<!~^\[;]/)[0].trim();
          if (!rawName) continue;
          const normalized = normalizePkg(rawName);
          const reason = maliciousNormalized.get(normalized);
          if (reason) {
            findings.push({
              scanner: 'SupplyChainScanner',
              rule: 'SUPPLY-007',
              severity: 'critical',
              file: file.relativePath,
              line: i + 1,
              message: `Known malicious/typosquatted Python package: ${rawName} (${reason})`,
              evidence: line.trim().substring(0, 120),
              isThirdParty,
            });
          }
        }
      }
    }

    return findings;
  },
};

const pythonURLRequirementRule: Rule = {
  id: 'SUPPLY-008',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    if (!isPythonDepFile(file.path)) return [];
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const regex = new RegExp(SUSPICIOUS_REQUIREMENT_URL.source, 'gi');
      let match: RegExpExecArray | null;
      while ((match = regex.exec(trimmed)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-008',
          severity: 'high',
          file: file.relativePath,
          line: i + 1,
          message: 'Suspicious URL-based Python dependency (non-trusted host)',
          evidence: match[0].substring(0, 120),
          isThirdParty,
        });
      }
    }

    return findings;
  },
};

const SETUP_PY_DANGEROUS: Array<{ pattern: RegExp; desc: string }> = [
  // cmdclass overriding install/develop (postinstall hook)
  { pattern: /cmdclass\s*=\s*\{[^}]*['"]install['"]\s*:/g, desc: 'cmdclass["install"] override (postinstall hook)' },
  { pattern: /cmdclass\s*=\s*\{[^}]*['"]develop['"]\s*:/g, desc: 'cmdclass["develop"] override (postinstall hook)' },
  { pattern: /cmdclass\s*=\s*\{[^}]*['"]egg_info['"]\s*:/g, desc: 'cmdclass["egg_info"] override (install hook)' },
  // subprocess / os.system calls in setup.py context
  { pattern: /\bsubprocess\s*\.\s*(?:call|run|Popen|check_call|check_output)\s*\(/g, desc: 'subprocess execution in setup.py' },
  { pattern: /\bos\s*\.\s*system\s*\(/g, desc: 'os.system() call in setup.py' },
  { pattern: /\bos\s*\.\s*popen\s*\(/g, desc: 'os.popen() call in setup.py' },
  // Network fetching inside setup.py
  { pattern: /\burllib\s*\.\s*request\s*\.\s*urlretrieve\s*\(/g, desc: 'urllib network fetch in setup.py' },
  { pattern: /\brequests\s*\.\s*(?:get|post|put)\s*\(/g, desc: 'requests network call in setup.py' },
  // exec/eval with variable content
  { pattern: /\bexec\s*\(\s*(?!['"])/g, desc: 'exec() with dynamic argument in setup.py' },
  { pattern: /\beval\s*\(\s*(?!['"])/g, desc: 'eval() with dynamic argument in setup.py' },
];

const setupPyRule: Rule = {
  id: 'SUPPLY-009',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const basename = path.basename(file.path).toLowerCase();
    if (basename !== 'setup.py') return [];
    const findings: Finding[] = [];
    const isThirdParty = isThirdPartyCode(file.path);

    for (const { pattern, desc } of SETUP_PY_DANGEROUS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-009',
          severity: 'critical',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Dangerous setup.py pattern: ${desc}`,
          evidence: match[0].substring(0, 120),
          isThirdParty,
        });
      }
    }

    return findings;
  },
};

// --- Task log detection ---

/**
 * Detect agent task output log files (e.g. Tetora task logs).
 * Schema: root-level object with task_id + (output | status | agent | role).
 * These are runtime data, not source code — skip scanning.
 */
function isTaskLogFile(content: string): boolean {
  try {
    const obj = JSON.parse(content);
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return false;
    const keys = Object.keys(obj);
    if (!keys.includes('task_id')) return false;
    return keys.includes('output') || keys.includes('status') || keys.includes('agent') || keys.includes('role');
  } catch {
    return false;
  }
}

/**
 * Runtime/data paths that should not be treated as supply-chain source code.
 * These directories contain agent outputs, session transcripts, cached data,
 * and knowledge base content — not executable scripts or dependency manifests.
 */
const RUNTIME_PATH_PATTERNS = [
  /[/\\]runtime[/\\]/i,
  /[/\\]sessions?[/\\]/i,
  /[/\\]browser[/\\]/i,
  /[/\\]media[/\\]/i,
  /[/\\]vault[/\\]/i,
  /[/\\]outputs?[/\\]/i,
  /[/\\]logs?[/\\]/i,
  /[/\\]dbs?[/\\]/i,
  /[/\\]history[/\\]/i,
  /[/\\]snapshots?[/\\]/i,
  /[/\\]crawl[/\\]/i,
  /[/\\]scraped?[/\\]/i,
  /[/\\]downloaded?[/\\]/i,
  /[/\\]cache[/\\]/i,
  /[/\\]caches[/\\]/i,
  // Agent knowledge base and workspace outputs — content, not executable code
  /[/\\]knowledge[/\\]/i,
  /[/\\]intel[/\\]/i,
  /[/\\]products?[/\\]/i,
  /[/\\]content-queue[/\\]/i,
  /[/\\]drafts?[/\\]/i,
  /[/\\]research[/\\]/i,
  // Build output directories
  /[/\\]\.next[/\\]/i,
  /[/\\]\.nuxt[/\\]/i,
  // Agent coordination/state
  /[/\\]coord[/\\]/i,
  /[/\\]claims[/\\]/i,
  /[/\\]reviews[/\\]/i,
  /[/\\]state[/\\]/i,
  /[/\\]shared[/\\]/i,
  /[/\\]cron-runs[/\\]/i,
  /[/\\]memory[/\\]/i,
];

function isRuntimeDataPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return RUNTIME_PATH_PATTERNS.some(p => p.test(normalized));
}

// --- Scanner class ---

export class SupplyChainScanner implements Scanner {
  name = 'SupplyChainScanner';
  description = 'Detects supply chain poisoning in agent skills (Base64 payloads, RCE, IOC, credential theft, exfiltration, persistence)';

  private rules: Rule[];

  constructor(externalIOCPath?: string) {
    const ioc = loadIOC(externalIOCPath);
    this.rules = [
      base64Rule,
      rceRule,
      createIOCRule(ioc),
      credentialRule,
      exfilRule,
      persistenceRule,
      pythonPackageRule,
      pythonURLRequirementRule,
      setupPyRule,
    ];
  }

  async scan(targetDir: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const skillsDir = path.join(targetDir, 'skills');
    const scanDir = fs.existsSync(skillsDir) ? skillsDir : targetDir;
    const files = walkFiles(scanDir, { includeVendored: options?.includeVendored, exclude: options?.exclude, sentoriIgnorePatterns: options?.sentoriIgnorePatterns, includeWorkspaceProjects: options?.includeWorkspaceProjects });
    const findings: Finding[] = [];

    for (const file of files) {
      // Skip runtime/data paths — agent outputs, session transcripts, cached content
      if (isRuntimeDataPath(file.path)) continue;

      // Skip task output log files (Tetora/agent schema: has task_id + output + status/agent)
      if (file.path.endsWith('.json') && isTaskLogFile(file.content)) continue;

      for (const rule of this.rules) {
        findings.push(...rule.check(file));
      }
    }

    return {
      scanner: this.name,
      findings,
      filesScanned: files.length,
      duration: Date.now() - start,
    };
  }
}
