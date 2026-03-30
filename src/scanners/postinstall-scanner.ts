import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScannerOptions, ScanResult, Finding, Severity } from '../types';

// --- Suspicious pattern definitions ---

const SUSPICIOUS_PATTERNS: Array<{ pattern: RegExp; desc: string; severity: Severity }> = [
  { pattern: /curl\s+[^\n]*\|\s*(bash|sh|zsh)\b/gi, desc: 'curl pipe to shell', severity: 'critical' },
  { pattern: /wget\s+[^\n]*\|\s*(bash|sh|zsh)\b/gi, desc: 'wget pipe to shell', severity: 'critical' },
  { pattern: /\beval\s*\(/gi, desc: 'eval() call', severity: 'high' },
  { pattern: /chmod\s+\+x\s+[^\n;]+;\s*\.?\//gi, desc: 'chmod +x then execute', severity: 'high' },
  { pattern: /curl\s+[^\n]*-o\s+[^\n;]+;\s*(bash|sh|\.\/)/gi, desc: 'download and execute', severity: 'critical' },
  { pattern: /wget\s+[^\n]*-O\s+[^\n;]+;\s*(bash|sh|\.\/)/gi, desc: 'download and execute', severity: 'critical' },
  { pattern: /rm\s+-rf\s+\/(?!tmp|var\/tmp)/gi, desc: 'dangerous recursive delete', severity: 'critical' },
  { pattern: /:\(\)\s*\{\s*:\|\:&\s*\};\s*:/gi, desc: 'fork bomb', severity: 'critical' },
];

// --- Lifecycle hooks we care about ---
const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall'] as const;
type LifecycleHook = typeof LIFECYCLE_HOOKS[number];

// --- Scanner configuration ---
export interface PostinstallScannerConfig {
  /** Scan depth: 1 = direct deps only, -1 = unlimited */
  depth?: number;
}

// --- Package.json interface ---
interface PackageJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  [key: string]: unknown;
}

// --- Scanner class ---

export class PostinstallScanner implements Scanner {
  name = 'PostinstallScanner';
  description = 'Scans node_modules for suspicious lifecycle scripts (preinstall, install, postinstall)';

  private depth: number;

  constructor(config?: PostinstallScannerConfig) {
    this.depth = config?.depth ?? 1;
  }

  async scan(targetDir: string, _options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    let scannedPackages = 0;

    const nodeModulesPath = path.join(targetDir, 'node_modules');
    
    if (!fs.existsSync(nodeModulesPath)) {
      return {
        scanner: this.name,
        findings: [{
          scanner: this.name,
          severity: 'info',
          message: 'No node_modules directory found',
          recommendation: 'Run npm install first',
        }],
        scannedFiles: 0,
        duration: Date.now() - start,
      };
    }

    // Recursively scan node_modules
    const scanPackages = (modulesPath: string, currentDepth: number): void => {
      if (this.depth !== -1 && currentDepth > this.depth) {
        return;
      }

      if (!fs.existsSync(modulesPath)) {
        return;
      }

      const entries = fs.readdirSync(modulesPath, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        
        // Handle scoped packages (@org/package)
        if (entry.name.startsWith('@')) {
          const scopePath = path.join(modulesPath, entry.name);
          const scopedEntries = fs.readdirSync(scopePath, { withFileTypes: true });
          
          for (const scopedEntry of scopedEntries) {
            if (!scopedEntry.isDirectory()) continue;
            const packagePath = path.join(scopePath, scopedEntry.name);
            this.scanPackage(packagePath, findings);
            scannedPackages++;
            
            // Recursively scan nested node_modules
            const nestedModules = path.join(packagePath, 'node_modules');
            scanPackages(nestedModules, currentDepth + 1);
          }
        } else {
          const packagePath = path.join(modulesPath, entry.name);
          this.scanPackage(packagePath, findings);
          scannedPackages++;
          
          // Recursively scan nested node_modules
          const nestedModules = path.join(packagePath, 'node_modules');
          scanPackages(nestedModules, currentDepth + 1);
        }
      }
    };

    scanPackages(nodeModulesPath, 1);

    return {
      scanner: this.name,
      findings,
      scannedFiles: scannedPackages,
      duration: Date.now() - start,
    };
  }

  private scanPackage(packagePath: string, findings: Finding[]): void {
    const packageJsonPath = path.join(packagePath, 'package.json');
    
    if (!fs.existsSync(packageJsonPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(packageJsonPath, 'utf-8');
      const pkg: PackageJson = JSON.parse(content);
      
      if (!pkg.scripts) {
        return;
      }

      // Check each lifecycle hook
      for (const hook of LIFECYCLE_HOOKS) {
        const script = pkg.scripts[hook];
        if (!script) continue;

        // Relative path from project root
        const relPath = packageJsonPath.replace(process.cwd() + '/', '');
        
        // Report the lifecycle script existence
        findings.push({
          scanner: this.name,
          severity: 'info',
          rule: 'POSTINSTALL-001',
          file: relPath,
          message: `Package "${pkg.name || 'unknown'}" has ${hook} script`,
          evidence: script,
          recommendation: 'Review the script for suspicious behavior',
        });

        // Check for suspicious patterns
        for (const { pattern, desc, severity } of SUSPICIOUS_PATTERNS) {
          if (pattern.test(script)) {
            findings.push({
              scanner: this.name,
              severity,
              rule: 'POSTINSTALL-002',
              file: relPath,
              message: `Suspicious ${hook} script in "${pkg.name || 'unknown'}": ${desc}`,
              evidence: script,
              recommendation: `Review and potentially remove package "${pkg.name}"`,
              confidence: 'definite',
            });
          }
        }

        // Additional checks for common malicious indicators
        this.checkForMaliciousIndicators(script, pkg.name || 'unknown', hook, relPath, findings);
      }
    } catch (err) {
      // Invalid JSON or read error, skip
    }
  }

  private checkForMaliciousIndicators(
    script: string,
    packageName: string,
    hook: LifecycleHook,
    file: string,
    findings: Finding[]
  ): void {
    // Check for network requests to suspicious TLDs
    const suspiciousTLDs = /https?:\/\/[^\s]*\.(tk|ml|ga|cf|gq|pw|cc|top|xyz)\b/gi;
    if (suspiciousTLDs.test(script)) {
      findings.push({
        scanner: this.name,
        severity: 'high',
        rule: 'POSTINSTALL-003',
        file,
        message: `Suspicious TLD in ${hook} script of "${packageName}"`,
        evidence: script,
        recommendation: 'Verify the domain is legitimate',
        confidence: 'likely',
      });
    }

    // Check for IP addresses (potential C2)
    const ipPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const ipMatches = script.match(ipPattern);
    if (ipMatches && ipMatches.some(ip => !ip.startsWith('127.') && !ip.startsWith('0.'))) {
      findings.push({
        scanner: this.name,
        severity: 'medium',
        rule: 'POSTINSTALL-004',
        file,
        message: `IP address found in ${hook} script of "${packageName}"`,
        evidence: script,
        recommendation: 'Verify the IP address is expected',
        confidence: 'likely',
      });
    }

    // Check for encoded/obfuscated scripts
    const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/g;
    if (base64Pattern.test(script) && /base64|atob|Buffer\.from/.test(script)) {
      findings.push({
        scanner: this.name,
        severity: 'high',
        rule: 'POSTINSTALL-005',
        file,
        message: `Base64-encoded content in ${hook} script of "${packageName}"`,
        evidence: script,
        recommendation: 'Decode and review the content',
        confidence: 'likely',
      });
    }

    // Check for environment variable exfiltration
    const envExfilPattern = /(?:curl|wget|fetch|axios|http)[^\n]*(?:env|process\.env|printenv)/gi;
    if (envExfilPattern.test(script)) {
      findings.push({
        scanner: this.name,
        severity: 'critical',
        rule: 'POSTINSTALL-006',
        file,
        message: `Potential environment variable exfiltration in ${hook} script of "${packageName}"`,
        evidence: script,
        recommendation: 'Remove this package immediately and rotate credentials',
        confidence: 'definite',
      });
    }
  }
}
