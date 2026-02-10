import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScanResult, Finding, Severity } from '../types';
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
  severity: 'HIGH',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
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
          severity: 'HIGH',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: 'Suspicious Base64-encoded command detected',
          evidence: `Decoded: ${decoded.substring(0, 120)}`,
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
  severity: 'CRITICAL',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    for (const { pattern, desc } of RCE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-002',
          severity: 'CRITICAL',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Remote code execution: ${desc}`,
          evidence: match[0].substring(0, 120),
        });
      }
    }
    return findings;
  },
};

function createIOCRule(ioc: IOCBlocklist): Rule {
  return {
    id: 'SUPPLY-003',
    severity: 'CRITICAL',
    check(file: FileEntry): Finding[] {
      const findings: Finding[] = [];
      for (const ip of ioc.malicious_ips) {
        let idx = file.content.indexOf(ip);
        while (idx !== -1) {
          findings.push({
            scanner: 'SupplyChainScanner',
            rule: 'SUPPLY-003',
            severity: 'CRITICAL',
            file: file.relativePath,
            line: findLineNumber(file.content, idx),
            message: `Known malicious IP detected: ${ip}`,
            evidence: ip,
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
            severity: 'CRITICAL',
            file: file.relativePath,
            line: findLineNumber(file.content, idx),
            message: `Known malicious domain detected: ${domain}`,
            evidence: domain,
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
  severity: 'CRITICAL',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    for (const { pattern, desc } of CREDENTIAL_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-004',
          severity: 'CRITICAL',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Credential theft: ${desc}`,
          evidence: match[0].substring(0, 120),
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
  severity: 'HIGH',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    for (const { pattern, desc } of EXFIL_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-005',
          severity: 'HIGH',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Data exfiltration: ${desc}`,
          evidence: match[0].substring(0, 120),
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
  severity: 'HIGH',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    for (const { pattern, desc } of PERSISTENCE_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'SupplyChainScanner',
          rule: 'SUPPLY-006',
          severity: 'HIGH',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Persistence mechanism: ${desc}`,
          evidence: match[0].substring(0, 120),
        });
      }
    }
    return findings;
  },
};

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
    ];
  }

  async scan(targetDir: string): Promise<ScanResult> {
    const start = Date.now();
    const skillsDir = path.join(targetDir, 'skills');
    const scanDir = fs.existsSync(skillsDir) ? skillsDir : targetDir;
    const files = walkFiles(scanDir);
    const findings: Finding[] = [];

    for (const file of files) {
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
