import * as fs from 'fs';
import * as path from 'path';
import * as dns from 'dns';
import { Scanner, ScanResult, Finding, Severity } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';

// --- Types ---

export interface PackageMetadata {
  name: string;
  ageInDays: number;
  weeklyDownloads: number;
  maintainerCount: number;
}

export interface ContextScore {
  originalSeverity: Severity;
  adjustedSeverity: Severity;
  reason: string;
}

// --- Constants ---

/** TLDs that collide with common file extensions. */
export const RISKY_TLDS = new Set([
  '.md', '.ai', '.io', '.sh', '.py', '.rs', '.ts', '.js', '.app', '.dev',
]);

/** Well-known agent convention filenames that are squattable domains. */
export const KNOWN_CONVENTION_FILES: string[] = [
  'heartbeat.md', 'readme.md', 'agents.md', 'soul.md', 'memory.md',
  'bootstrap.md', 'identity.md', 'tools.md',
];

/** Files commonly read on a periodic/heartbeat schedule. */
const HEARTBEAT_FILENAMES = new Set([
  'heartbeat.md', 'heartbeat.json', 'heartbeat.yaml', 'heartbeat.yml',
]);

/** Patterns indicating URL-based file resolution. */
const URL_RESOLUTION_PATTERNS: Array<{ pattern: RegExp; desc: string }> = [
  { pattern: /\bhttp\.get\s*\(\s*['"`]?[\w-]+\.\w{2,4}['"`]?\s*\)/gi, desc: 'http.get with filename-like argument' },
  { pattern: /\bfetch\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'fetch() with bare filename argument' },
  { pattern: /\baxios\s*\.\s*get\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'axios.get with filename-like argument' },
  { pattern: /\burllib\.request\.urlopen\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'urllib with filename-like argument' },
  { pattern: /\brequests\.get\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'requests.get with filename-like argument' },
  { pattern: /\bnew\s+URL\s*\(\s*['"`][\w-]+\.\w{2,4}['"`]\s*\)/gi, desc: 'new URL() with filename-like argument' },
];

// --- Helpers ---

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split('\n').length;
}

/**
 * Check if a filename (e.g. "README.md") could be interpreted as a valid
 * domain by checking its extension against risky TLDs.
 */
export function isTLDCollision(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase();
  return RISKY_TLDS.has(ext);
}

/**
 * Resolve a domain via DNS. Returns true if any A/AAAA record exists.
 * Wrapped for testability – callers can override via the resolver param.
 */
export async function domainResolves(
  domain: string,
  resolver: (hostname: string) => Promise<string[]> = defaultResolve,
): Promise<boolean> {
  try {
    const addrs = await resolver(domain);
    return addrs.length > 0;
  } catch {
    return false;
  }
}

function defaultResolve(hostname: string): Promise<string[]> {
  return dns.promises.resolve4(hostname);
}

/**
 * Fetch package metadata from npm registry.
 * Returns null if package doesn't exist or API fails.
 */
export async function fetchPackageMetadata(
  packageName: string,
  fetcher: (url: string) => Promise<any> = defaultFetcher,
): Promise<PackageMetadata | null> {
  try {
    const data = await fetcher(`https://registry.npmjs.org/${packageName}`);
    
    // Calculate package age
    const createdTime = data.time?.created;
    const ageInDays = createdTime 
      ? Math.floor((Date.now() - new Date(createdTime).getTime()) / (1000 * 60 * 60 * 24))
      : 0;

    // Get weekly downloads from npm API
    const downloadsData = await fetcher(
      `https://api.npmjs.org/downloads/point/last-week/${packageName}`
    );
    const weeklyDownloads = downloadsData?.downloads ?? 0;

    // Count maintainers
    const maintainerCount = Array.isArray(data.maintainers) ? data.maintainers.length : 0;

    return {
      name: packageName,
      ageInDays,
      weeklyDownloads,
      maintainerCount,
    };
  } catch {
    return null;
  }
}

async function defaultFetcher(url: string): Promise<any> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/**
 * Calculate context score and adjust severity based on package metadata.
 * 
 * Scoring rules:
 * - Age < 30 days: keep severity
 * - Age < 365 days && downloads < 1000/week: keep severity
 * - Age >= 365 days && downloads >= 10000/week && maintainers >= 3: downgrade by 2 levels
 * - Age >= 365 days && downloads >= 1000/week: downgrade by 1 level
 */
export function calculateContextScore(
  originalSeverity: Severity,
  metadata: PackageMetadata | null,
): ContextScore {
  if (!metadata) {
    return {
      originalSeverity,
      adjustedSeverity: originalSeverity,
      reason: 'No package metadata available',
    };
  }

  const { ageInDays, weeklyDownloads, maintainerCount } = metadata;

  // New/suspicious packages: keep original severity
  if (ageInDays < 30) {
    return {
      originalSeverity,
      adjustedSeverity: originalSeverity,
      reason: `Package age < 30 days (${ageInDays} days) - potential squatting`,
    };
  }

  // Low-traffic packages: keep original severity
  if (ageInDays < 365 && weeklyDownloads < 1000) {
    return {
      originalSeverity,
      adjustedSeverity: originalSeverity,
      reason: `Low traffic (${weeklyDownloads}/week) - suspicious activity`,
    };
  }

  // Established, high-traffic packages: downgrade by 2 levels
  if (ageInDays >= 365 && weeklyDownloads >= 10000 && maintainerCount >= 3) {
    const adjusted = downgradeSeverity(originalSeverity, 2);
    return {
      originalSeverity,
      adjustedSeverity: adjusted,
      reason: `Established package (${ageInDays} days, ${weeklyDownloads}/week, ${maintainerCount} maintainers) - likely legitimate`,
    };
  }

  // Moderate packages: downgrade by 1 level
  if (ageInDays >= 365 && weeklyDownloads >= 1000) {
    const adjusted = downgradeSeverity(originalSeverity, 1);
    return {
      originalSeverity,
      adjustedSeverity: adjusted,
      reason: `Moderate package (${ageInDays} days, ${weeklyDownloads}/week) - likely legitimate`,
    };
  }

  return {
    originalSeverity,
    adjustedSeverity: originalSeverity,
    reason: 'No context adjustments applied',
  };
}

function downgradeSeverity(severity: Severity, levels: number): Severity {
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'info'];
  const currentIndex = severityOrder.indexOf(severity);
  const newIndex = Math.min(currentIndex + levels, severityOrder.length - 1);
  return severityOrder[newIndex];
}

// --- Scanner ---

/** Scan extensions for node_modules */
const NODE_MODULES_SCAN_EXTENSIONS = new Set(['.md', '.sh', '.py', '.js', '.ts', '.yaml', '.yml', '.json']);

export class ConventionSquattingScanner implements Scanner {
  name = 'ConventionSquattingScanner';
  description =
    'Detects convention filenames that collide with registrable domain TLDs (.md, .ai, .io, etc.) and URL resolution risks';

  /** Injected resolver for testing. */
  private resolver: (hostname: string) => Promise<string[]>;
  /** Whether to perform live DNS checks. */
  private dnsCheck: boolean;
  /** Whether to enable context scoring. */
  private enableContextScoring: boolean;
  /** Injected fetcher for testing. */
  private fetcher: (url: string) => Promise<any>;
  /** Scan depth for node_modules: 1 = direct deps only, 0 = skip node_modules, -1 = unlimited */
  private nodeModulesDepth: number;

  constructor(opts?: { 
    resolver?: (hostname: string) => Promise<string[]>; 
    dnsCheck?: boolean;
    enableContextScoring?: boolean;
    fetcher?: (url: string) => Promise<any>;
    nodeModulesDepth?: number;
  }) {
    this.resolver = opts?.resolver ?? defaultResolve;
    this.dnsCheck = opts?.dnsCheck ?? false;
    this.enableContextScoring = opts?.enableContextScoring ?? true;
    this.fetcher = opts?.fetcher ?? defaultFetcher;
    this.nodeModulesDepth = opts?.nodeModulesDepth ?? 1;
  }

  async scan(targetDir: string): Promise<ScanResult> {
    const start = Date.now();
    const files = walkFiles(targetDir);
    const findings: Finding[] = [];

    // Scan node_modules if enabled
    if (this.nodeModulesDepth > 0) {
      const nodeModulesFiles = this.scanNodeModules(targetDir, this.nodeModulesDepth);
      files.push(...nodeModulesFiles);
    }

    // Rule 1: Convention Filename TLD Collision
    for (const file of files) {
      const basename = path.basename(file.relativePath);
      if (isTLDCollision(basename)) {
        const domain = basename.toLowerCase();
        const isKnown = KNOWN_CONVENTION_FILES.includes(domain);
        const isHeartbeat = HEARTBEAT_FILENAMES.has(domain);

        let severity: Severity = isHeartbeat ? 'high' : isKnown ? 'medium' : 'info';
        const rec = isHeartbeat
          ? 'CRITICAL: This file is read periodically — a squatted domain would enable persistent injection. Use absolute local paths and validate file source is local filesystem, not network.'
          : 'Filename resolves as a valid domain. Ensure agent reads via local fs path, not URL resolution. Add integrity checks (hash verification) for convention files.';

        // Apply context scoring if enabled
        let contextNote = '';
        if (this.enableContextScoring) {
          // Convert domain to potential npm package name (remove extension)
          const packageName = domain.replace(/\.[^/.]+$/, '');
          const metadata = await fetchPackageMetadata(packageName, this.fetcher);
          const contextScore = calculateContextScore(severity, metadata);
          
          if (contextScore.adjustedSeverity !== severity) {
            contextNote = ` [Context: ${contextScore.originalSeverity} → ${contextScore.adjustedSeverity}: ${contextScore.reason}]`;
            severity = contextScore.adjustedSeverity;
          }
        }

        findings.push({
          id: 'SQUAT-001',
          scanner: this.name,
          rule: 'SQUAT-001',
          severity,
          title: 'Convention Filename TLD Collision',
          description: `Convention filename "${basename}" is a registrable domain (TLD collision: ${path.extname(basename)})${contextNote}`,
          file: file.relativePath,
          line: 0,
          message: `Convention filename "${basename}" is a registrable domain (TLD collision: ${path.extname(basename)})${contextNote}`,
          evidence: `${domain} — ${rec}`,
          recommendation: rec,
        });

        // Rule 4: Heartbeat/Periodic Read Risk (additional finding)
        if (isHeartbeat) {
          findings.push({
            id: 'SQUAT-004',
            scanner: this.name,
            rule: 'SQUAT-004',
            severity: 'high',
            title: 'Heartbeat File Domain Squatting Risk',
            description: `Heartbeat file "${basename}" is highest risk for persistent injection via domain squatting`,
            file: file.relativePath,
            line: 0,
            message: `Heartbeat file "${basename}" is highest risk for persistent injection via domain squatting`,
            evidence:
              'Files read periodically can be hijacked if resolved via URL. Use absolute local path, verify file hash, ensure fs-only access.',
            recommendation: 'Use absolute local path, verify file hash, ensure fs-only access.',
          });
        }
      }
    }

    // Rule 2: URL Resolution Risk
    for (const file of files) {
      for (const { pattern, desc } of URL_RESOLUTION_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags);
        let match: RegExpExecArray | null;
        while ((match = regex.exec(file.content)) !== null) {
          findings.push({
            id: 'SQUAT-002',
            scanner: this.name,
            rule: 'SQUAT-002',
            severity: 'high',
            title: 'URL Resolution Risk',
            description: `URL resolution risk: ${desc}`,
            file: file.relativePath,
            line: findLineNumber(file.content, match.index),
            message: `URL resolution risk: ${desc}`,
            evidence: `${match[0].substring(0, 120)} — Recommendation: Use fs.readFileSync or equivalent for local files. Never pass bare filenames to network APIs.`,
            recommendation: 'Use fs.readFileSync or equivalent for local files. Never pass bare filenames to network APIs.',
          });
        }
      }
    }

    // Rule 3: Known Squatted Domains (DNS check)
    if (this.dnsCheck) {
      for (const domain of KNOWN_CONVENTION_FILES) {
        const resolves = await domainResolves(domain, this.resolver);
        if (resolves) {
          findings.push({
            id: 'SQUAT-003',
            scanner: this.name,
            rule: 'SQUAT-003',
            severity: 'critical',
            title: 'Known Squatted Domain Detected',
            description: `Known convention filename "${domain}" resolves as a live domain`,
            file: '<dns-check>',
            line: 0,
            message: `Known convention filename "${domain}" resolves as a live domain`,
            evidence: `${domain} has DNS A records. An attacker (or opportunist) has registered this domain. Any agent resolving this filename via URL will fetch attacker-controlled content.`,
            recommendation: 'Block or monitor this domain. Ensure agents never resolve convention filenames via network.',
          });
        }
      }
    }

    return {
      scanner: this.name,
      findings,
      scannedFiles: files.length,
      filesScanned: files.length,
      duration: Date.now() - start,
    };
  }

  /**
   * Scan node_modules directory up to specified depth.
   * depth: 1 = direct deps only, -1 = unlimited
   */
  private scanNodeModules(targetDir: string, maxDepth: number): FileEntry[] {
    const nodeModulesPath = path.join(targetDir, 'node_modules');
    const files: FileEntry[] = [];

    if (!fs.existsSync(nodeModulesPath)) {
      return files;
    }

    const scanPackageDir = (packagePath: string, currentDepth: number): void => {
      if (maxDepth !== -1 && currentDepth > maxDepth) {
        return;
      }

      try {
        const entries = fs.readdirSync(packagePath, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(packagePath, entry.name);
          
          if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            if (NODE_MODULES_SCAN_EXTENSIONS.has(ext)) {
              try {
                const content = fs.readFileSync(fullPath, 'utf-8');
                files.push({
                  path: fullPath,
                  relativePath: path.relative(targetDir, fullPath),
                  content,
                });
              } catch {
                // skip unreadable files
              }
            }
          } else if (entry.isDirectory() && entry.name === 'node_modules') {
            // Nested node_modules found, scan it recursively if depth allows
            const nestedEntries = fs.readdirSync(fullPath, { withFileTypes: true });
            for (const nestedEntry of nestedEntries) {
              if (nestedEntry.isDirectory()) {
                if (nestedEntry.name.startsWith('@')) {
                  // Scoped package
                  const scopePath = path.join(fullPath, nestedEntry.name);
                  const scopedEntries = fs.readdirSync(scopePath, { withFileTypes: true });
                  for (const scopedEntry of scopedEntries) {
                    if (scopedEntry.isDirectory()) {
                      scanPackageDir(path.join(scopePath, scopedEntry.name), currentDepth + 1);
                    }
                  }
                } else {
                  // Regular package
                  scanPackageDir(path.join(fullPath, nestedEntry.name), currentDepth + 1);
                }
              }
            }
          }
        }
      } catch {
        // skip unreadable directories
      }
    };

    // Scan top-level packages in node_modules
    try {
      const entries = fs.readdirSync(nodeModulesPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        
        if (entry.name.startsWith('@')) {
          // Scoped package (@org/package)
          const scopePath = path.join(nodeModulesPath, entry.name);
          try {
            const scopedEntries = fs.readdirSync(scopePath, { withFileTypes: true });
            for (const scopedEntry of scopedEntries) {
              if (scopedEntry.isDirectory()) {
                scanPackageDir(path.join(scopePath, scopedEntry.name), 1);
              }
            }
          } catch {
            // skip unreadable scope directory
          }
        } else {
          // Regular package
          scanPackageDir(path.join(nodeModulesPath, entry.name), 1);
        }
      }
    } catch {
      // skip if node_modules is unreadable
    }

    return files;
  }
}
