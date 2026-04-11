/**
 * PackageGateScanner — Phase 2: Version Conflict Detection
 *
 * Supports:
 *  - package-lock.json  (npm)
 *  - pnpm-lock.yaml     (pnpm)
 *  - bun.lockb          (bun; binary but contains ASCII-readable sections)
 */

import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScanResult, Finding, Severity } from '../types';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface ParsedDependency {
  name: string;
  version: string;
  resolved?: string; // registry URL
  integrity?: string;
}

export interface ParsedLockResult {
  lockType: 'npm' | 'pnpm' | 'bun';
  dependencies: ParsedDependency[];
  /** package name → all versions found across the lock file */
  rawVersionMap: Record<string, string[]>;
}

export interface ConflictFinding {
  packageName: string;
  versions: string[]; // all versions found
  conflictType: 'multi-version' | 'suspicious-version' | 'pinned-mismatch';
  severity: Severity;
  details?: string;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Push a version into the rawVersionMap, deduplicating */
function addToVersionMap(
  map: Record<string, string[]>,
  name: string,
  version: string,
): void {
  if (!map[name]) map[name] = [];
  if (!map[name].includes(version)) {
    map[name].push(version);
  }
}

// Strict semver: x.y.z (digits only, no suffix)
const SEMVER_STRICT = /^\d+\.\d+\.\d+$/;

// Suspicious pre-release suffixes
const SUSPICIOUS_SUFFIX = /(-beta|-alpha|-rc|-dev)(\.\d+)?$/i;

// Only flag truly placeholder version (all-zero): 0.0.0
// Previously used /\.0\.0$/ which caused high false-positive rate on normal
// releases like 1.0.0, 2.0.0, 10.0.0, etc.
const SUSPICIOUS_ZERO = /^0\.0\.0$/;

// Packages where pre-release versions are common and expected in dev environments.
// These are still reported (so intentional usage is visible) but with reduced severity.
const PRERELEASE_COMMON_PACKAGES = new Set([
  'typescript',
  'next',
  'react',
  'react-dom',
  'vue',
  'nuxt',
  'vite',
  'webpack',
  'rollup',
  'esbuild',
  'eslint',
  'prettier',
  '@angular/core',
  '@angular/cli',
  '@babel/core',
  '@babel/preset-env',
  '@vue/compiler-sfc',
]);

// ---------------------------------------------------------------------------
// Version Conflict Detection (Phase 2 Core)
// ---------------------------------------------------------------------------

/**
 * Detect version conflicts and anomalies from a parsed lock file result.
 *
 * Returns ConflictFinding[] covering three conflict types:
 *  - multi-version:      same package resolved to ≥2 different versions
 *  - suspicious-version: version has pre-release suffix or .0.0 ending
 *  - pinned-mismatch:    version doesn't match strict semver (x.y.z)
 */
export function detectVersionConflicts(result: ParsedLockResult): ConflictFinding[] {
  const findings: ConflictFinding[] = [];

  for (const [packageName, versions] of Object.entries(result.rawVersionMap)) {
    // 1. multi-version: ≥2 different versions for the same package
    if (versions.length >= 2) {
      findings.push({
        packageName,
        versions: [...versions],
        conflictType: 'multi-version',
        severity: 'medium',
        details: `Found ${versions.length} different versions: ${versions.join(', ')}`,
      });
    }

    // 2. suspicious-version: pre-release suffix or true placeholder (0.0.0)
    //
    // Noise-reduction changes (2026-02):
    //  - SUSPICIOUS_ZERO now matches only "0.0.0" (true placeholder), NOT all x.0.0
    //  - Severity downgraded from 'high' → 'medium' (pre-release is common in dev)
    //  - Packages in PRERELEASE_COMMON_PACKAGES are expected to ship pre-release;
    //    flagged at 'low' severity to keep signal without drowning dashboards.
    const suspiciousVersions = versions.filter(
      (v) => SUSPICIOUS_SUFFIX.test(v) || SUSPICIOUS_ZERO.test(v),
    );
    if (suspiciousVersions.length > 0) {
      const isCommonPackage = PRERELEASE_COMMON_PACKAGES.has(packageName);
      findings.push({
        packageName,
        versions: suspiciousVersions,
        conflictType: 'suspicious-version',
        // Common tooling packages (typescript, next, vite…) often ship pre-release;
        // report at 'info' level to reduce dashboard noise while keeping visibility.
        // Unknown packages get 'medium' (down from 'high' — false-positive reduction).
        severity: isCommonPackage ? 'info' : 'medium',
        details: `Suspicious version(s) detected: ${suspiciousVersions.join(', ')}${isCommonPackage ? ' (common package — pre-release may be intentional)' : ''}`,
      });
    }

    // 3. pinned-mismatch: version does not conform to x.y.z semver
    const nonSemverVersions = versions.filter((v) => !SEMVER_STRICT.test(v));
    if (nonSemverVersions.length > 0) {
      findings.push({
        packageName,
        versions: nonSemverVersions,
        conflictType: 'pinned-mismatch',
        severity: 'medium',
        details: `Non-semver version(s): ${nonSemverVersions.join(', ')}`,
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// PackageGateLockParser
// ---------------------------------------------------------------------------

export class PackageGateLockParser {
  /**
   * Parse npm `package-lock.json` (lockfileVersion 1, 2, or 3).
   *
   * v1: top-level `dependencies` map
   * v2/v3: top-level `packages` map (preferred) plus optional `dependencies`
   */
  parseNpmLock(content: string): ParsedLockResult {
    const deps: ParsedDependency[] = [];
    const versionMap: Record<string, string[]> = {};

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(content);
    } catch {
      return { lockType: 'npm', dependencies: [], rawVersionMap: {} };
    }

    const lockfileVersion = (parsed.lockfileVersion as number | undefined) ?? 1;

    // --- v2 / v3: `packages` map (keys are "node_modules/foo" or "node_modules/foo/node_modules/bar")
    if (lockfileVersion >= 2 && parsed.packages && typeof parsed.packages === 'object') {
      const packages = parsed.packages as Record<string, Record<string, unknown>>;
      for (const [pkgPath, pkgData] of Object.entries(packages)) {
        // Skip the root entry ("")
        if (pkgPath === '') continue;

        // Derive name from path: "node_modules/foo" → "foo", "node_modules/@scope/foo" → "@scope/foo"
        const name = pkgPath.replace(/^(?:.*node_modules\/)/, '');
        if (!name) continue;

        const version = typeof pkgData.version === 'string' ? pkgData.version : '';
        if (!version) continue;

        const dep: ParsedDependency = { name, version };
        if (typeof pkgData.resolved === 'string') dep.resolved = pkgData.resolved;
        if (typeof pkgData.integrity === 'string') dep.integrity = pkgData.integrity;

        deps.push(dep);
        addToVersionMap(versionMap, name, version);
      }
    }

    // --- v1 (or fallback): `dependencies` map (nested)
    if ((lockfileVersion === 1 || deps.length === 0) && parsed.dependencies && typeof parsed.dependencies === 'object') {
      function parseDepsV1(
        obj: Record<string, Record<string, unknown>>,
      ): void {
        for (const [name, data] of Object.entries(obj)) {
          const version = typeof data.version === 'string' ? data.version : '';
          if (!version) continue;

          const dep: ParsedDependency = { name, version };
          if (typeof data.resolved === 'string') dep.resolved = data.resolved;
          if (typeof data.integrity === 'string') dep.integrity = data.integrity;

          deps.push(dep);
          addToVersionMap(versionMap, name, version);

          // Recurse nested dependencies (npm v1 hoisting conflicts)
          if (data.dependencies && typeof data.dependencies === 'object') {
            parseDepsV1(data.dependencies as Record<string, Record<string, unknown>>);
          }
        }
      }
      parseDepsV1(parsed.dependencies as Record<string, Record<string, unknown>>);
    }

    return { lockType: 'npm', dependencies: deps, rawVersionMap: versionMap };
  }

  /**
   * Parse pnpm `pnpm-lock.yaml`.
   *
   * We use a hand-rolled YAML parser focused on the lock file structure
   * rather than pulling in a full YAML library:
   *
   * lockfileVersion: 5.x / '6.0'
   *
   * v5 format:
   *   packages:
   *     /foo/1.2.3:
   *       resolution: {integrity: sha512-...}
   *
   * v6 format:
   *   packages:
   *     foo@1.2.3:
   *       resolution: {integrity: sha512-..., tarball: ...}
   *
   * v9 format (lockfileVersion: '9.0'):
   *   snapshots:
   *     foo@1.2.3:
   *       ...
   *   packages:
   *     foo@1.2.3:
   *       resolution: ...
   */
  parsePnpmLock(content: string): ParsedLockResult {
    const deps: ParsedDependency[] = [];
    const versionMap: Record<string, string[]> = {};

    const lines = content.split('\n');
    let inPackagesBlock = false;
    let inSnapshotsBlock = false;
    let currentEntry: Partial<ParsedDependency> | null = null;

    // Detect lockfile version
    let lockfileVersion = '';
    for (const line of lines) {
      const m = line.match(/^lockfileVersion:\s*['"]?([^'"]+)['"]?/);
      if (m) { lockfileVersion = m[1].trim(); break; }
    }

    const isV5 = lockfileVersion.startsWith('5');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Detect top-level block switches
      if (/^packages:/.test(line)) {
        // Flush previous entry
        if (currentEntry?.name && currentEntry.version) {
          const d = currentEntry as ParsedDependency;
          deps.push(d);
          addToVersionMap(versionMap, d.name, d.version);
        }
        currentEntry = null;
        inPackagesBlock = true;
        inSnapshotsBlock = false;
        continue;
      }
      if (/^snapshots:/.test(line)) {
        if (currentEntry?.name && currentEntry.version) {
          const d = currentEntry as ParsedDependency;
          deps.push(d);
          addToVersionMap(versionMap, d.name, d.version);
        }
        currentEntry = null;
        inSnapshotsBlock = true;
        inPackagesBlock = false;
        continue;
      }
      // Any other top-level key ends these blocks
      if (/^\w/.test(line) && !line.startsWith(' ') && !line.startsWith('\t')) {
        if (currentEntry?.name && currentEntry.version) {
          const d = currentEntry as ParsedDependency;
          deps.push(d);
          addToVersionMap(versionMap, d.name, d.version);
        }
        currentEntry = null;
        inPackagesBlock = false;
        inSnapshotsBlock = false;
        continue;
      }

      if (!inPackagesBlock && !inSnapshotsBlock) continue;

      // Package entry key line: exactly 2-space indent + key ending with ':'
      // e.g. "  /lodash/4.17.21:" (v5) or "  lodash@4.17.21:" (v6+)
      const entryMatch = line.match(/^  ([^\s:][^:]+):(\s*)$/);
      if (entryMatch) {
        // Flush previous
        if (currentEntry?.name && currentEntry.version) {
          const d = currentEntry as ParsedDependency;
          deps.push(d);
          addToVersionMap(versionMap, d.name, d.version);
        }

        const rawKey = entryMatch[1].trim();
        let name = '';
        let version = '';

        if (isV5) {
          // v5: "/package-name/version" or "/@scope/package/version"
          // e.g. /lodash/4.17.21, /@babel/core/7.0.0
          const v5Match = rawKey.match(/^\/(@?[^/]+(?:\/[^/]+)?)\/([\d][^/]*)$/);
          if (v5Match) {
            name = v5Match[1];
            version = v5Match[2];
          } else {
            // Fallback: last segment as version
            const parts = rawKey.split('/').filter(Boolean);
            if (parts.length >= 2) {
              version = parts[parts.length - 1];
              name = parts.slice(0, parts.length - 1).join('/');
              if (!name.startsWith('@')) name = parts[parts.length - 2];
            }
          }
        } else {
          // v6+: "package@version" or "@scope/package@version"
          // Some v6 files still use a leading "/" before the name — strip it
          const keyForV6 = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;

          // Handle peer suffix: "lodash@4.17.21(react@18.0.0)" → name=lodash, version=4.17.21
          const v6Match = keyForV6.match(/^(@?[^@]+)@([\d][^(@]*)(\(.*\))?$/);
          if (v6Match) {
            name = v6Match[1];
            version = v6Match[2];
          } else if (rawKey.startsWith('/')) {
            // Fallback: treat as v5-style path even though lockfileVersion says v6
            const v5Fallback = rawKey.match(/^\/(@?[^/]+(?:\/[^/]+)?)\/([\d][^/]*)$/);
            if (v5Fallback) {
              name = v5Fallback[1];
              version = v5Fallback[2];
            }
          }
        }

        if (name && version) {
          currentEntry = { name, version };
        } else {
          currentEntry = null;
        }
        continue;
      }

      // Inside a package entry — pick up resolution fields
      if (currentEntry) {
        // integrity: sha512-...
        const integrityMatch = line.match(/^\s+integrity:\s*(.+)/);
        if (integrityMatch) {
          currentEntry.integrity = integrityMatch[1].trim();
        }
        // tarball URL (resolved)
        const tarballMatch = line.match(/^\s+tarball:\s*(.+)/);
        if (tarballMatch) {
          currentEntry.resolved = tarballMatch[1].trim();
        }
      }
    }

    // Flush last entry
    if (currentEntry?.name && currentEntry.version) {
      const d = currentEntry as ParsedDependency;
      deps.push(d);
      addToVersionMap(versionMap, d.name, d.version);
    }

    return { lockType: 'pnpm', dependencies: deps, rawVersionMap: versionMap };
  }

  /**
   * Parse bun `bun.lockb`.
   *
   * bun.lockb is a binary file, but it contains readable ASCII sections
   * with package name@version strings.  We extract those heuristically.
   *
   * Pattern seen in bun.lockb ASCII sections:
   *   "package-name@version" strings surrounded by null bytes / binary data.
   *
   * We scan the buffer for printable ASCII runs and extract npm-style
   * `name@semver` tokens from them.
   */
  parseBunLock(content: string): ParsedLockResult {
    const deps: ParsedDependency[] = [];
    const versionMap: Record<string, string[]> = {};

    // content may be read as utf-8 (lossy) from a binary file
    // Extract all printable ASCII runs of length >= 4
    const asciiRuns = content.match(/[\x20-\x7E]{4,}/g) ?? [];

    // Match package@version tokens (semver-ish)
    // e.g. "lodash@4.17.21", "@babel/core@7.21.0"
    const pkgPattern = /(@?[a-zA-Z0-9][\w.-]*(?:\/[\w.-]+)?)@(\d[\w.\-+]*)/g;

    const seen = new Set<string>();
    for (const run of asciiRuns) {
      let m: RegExpExecArray | null;
      const re = new RegExp(pkgPattern.source, 'g');
      while ((m = re.exec(run)) !== null) {
        const name = m[1];
        const version = m[2];
        const key = `${name}@${version}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // Skip things that look like node paths or URLs
        if (name.includes('://') || name.startsWith('.')) continue;
        // Skip very short/obviously non-package names
        if (name.length < 2 || version.length < 3) continue;

        deps.push({ name, version });
        addToVersionMap(versionMap, name, version);
      }
    }

    return { lockType: 'bun', dependencies: deps, rawVersionMap: versionMap };
  }
}

// ---------------------------------------------------------------------------
// Phase 3A: Suspicious install hooks detection
// ---------------------------------------------------------------------------

/** Hook script names to inspect */
const HOOK_SCRIPTS = ['preinstall', 'install', 'postinstall'] as const;

/** PKGATE-010: Dangerous shell commands */
const DANGEROUS_COMMANDS_RE = /\b(curl|wget|bash|sh|eval|exec)\b/;

/** PKGATE-011: Base64 decode patterns */
const BASE64_DECODE_RE =
  /base64\s+(--decode|-d)|atob\s*\(|Buffer\.from\s*\([^,)]+,\s*['"]base64['"]\)/;

/** PKGATE-012: External URL references */
const EXTERNAL_URL_RE = /https?:\/\//;

/**
 * Detect suspicious install hooks in a `package.json` file.
 *
 * Checks `scripts.preinstall`, `scripts.install`, and `scripts.postinstall` for:
 *  - PKGATE-010 (high):     dangerous shell commands (curl, wget, bash, sh, eval, exec)
 *  - PKGATE-011 (critical): base64 decode patterns
 *  - PKGATE-012 (high):     external URL references (http/https)
 *  - PKGATE-013 (info):     blank / whitespace-only hook
 *
 * @param packageJsonContent  UTF-8 content of the `package.json` file
 * @param filePath            Absolute path of the file (used for Finding.file)
 * @returns Finding[] — may be empty if no suspicious hooks found
 */
export function detectSuspiciousHooks(
  packageJsonContent: string,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(packageJsonContent);
  } catch {
    return [];
  }

  const scripts =
    pkg.scripts && typeof pkg.scripts === 'object'
      ? (pkg.scripts as Record<string, unknown>)
      : {};

  for (const hookName of HOOK_SCRIPTS) {
    const rawScript = scripts[hookName];
    if (rawScript === undefined) continue;
    if (typeof rawScript !== 'string') continue;

    const script = rawScript;
    const trimmed = script.trim();

    // PKGATE-013: blank hook (whitespace only)
    if (trimmed === '') {
      findings.push({
        id: 'PKGATE-013',
        scanner: 'PackageGateScanner',
        severity: 'info',
        title: `Blank ${hookName} hook detected`,
        description: `The "${hookName}" script in ${filePath} contains only whitespace and does nothing.`,
        file: filePath,
        recommendation:
          'Remove empty install hooks. Blank hooks may be placeholder remnants or the result of accidental script injection.',
      });
      continue; // blank — no further analysis needed
    }

    // PKGATE-011: base64 decode (critical — check before dangerous-command to avoid ordering issues)
    if (BASE64_DECODE_RE.test(trimmed)) {
      findings.push({
        id: 'PKGATE-011',
        scanner: 'PackageGateScanner',
        severity: 'critical',
        title: `Base64 decode in "${hookName}" hook`,
        description: `The "${hookName}" script decodes base64 data: ${trimmed.slice(0, 120)}${trimmed.length > 120 ? '…' : ''}`,
        file: filePath,
        recommendation:
          'Base64-encoded payloads in install hooks are a classic supply-chain attack pattern. ' +
          'Audit this script immediately and remove if not explicitly required.',
      });
    }

    // PKGATE-010: dangerous shell commands
    if (DANGEROUS_COMMANDS_RE.test(trimmed)) {
      findings.push({
        id: 'PKGATE-010',
        scanner: 'PackageGateScanner',
        severity: 'high',
        title: `Dangerous command in "${hookName}" hook`,
        description: `The "${hookName}" script contains potentially dangerous shell commands: ${trimmed.slice(0, 120)}${trimmed.length > 120 ? '…' : ''}`,
        file: filePath,
        recommendation:
          'Avoid using shell execution primitives (curl, wget, bash, sh, eval, exec) in install hooks. ' +
          'These commands can be exploited by supply-chain attackers to run arbitrary code on install.',
      });
    }

    // PKGATE-012: external URL reference
    if (EXTERNAL_URL_RE.test(trimmed)) {
      findings.push({
        id: 'PKGATE-012',
        scanner: 'PackageGateScanner',
        severity: 'high',
        title: `External URL in "${hookName}" hook`,
        description: `The "${hookName}" script references an external URL: ${trimmed.slice(0, 120)}${trimmed.length > 120 ? '…' : ''}`,
        file: filePath,
        recommendation:
          'Install hooks that fetch from external URLs introduce supply-chain risk. ' +
          'Verify that the endpoint is legitimate and consider bundling resources locally.',
      });
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Conflict type → rule ID / title / recommendation mapping
// ---------------------------------------------------------------------------

const CONFLICT_RULE_MAP: Record<
  ConflictFinding['conflictType'],
  { id: string; title: string; recommendation: string }
> = {
  'multi-version': {
    id: 'PKGATE-001',
    title: 'Multiple versions of the same package detected',
    recommendation:
      'Deduplicate dependency versions by aligning transitive requirements. ' +
      'Run `npm dedupe` (npm) or check `pnpm why <package>` (pnpm) to understand the conflict tree.',
  },
  'suspicious-version': {
    id: 'PKGATE-002',
    title: 'Suspicious pre-release or placeholder version detected',
    recommendation:
      'Avoid shipping pre-release versions (-alpha, -beta, -rc, -dev) or the all-zero ' +
      'placeholder version (0.0.0) in production lock files. ' +
      'Pin to a stable release and verify package integrity. ' +
      'For well-known tooling packages (e.g. typescript, next, vite) pre-release usage ' +
      'is common and flagged at lower severity — review intentional vs. accidental use.',
  },
  'pinned-mismatch': {
    id: 'PKGATE-003',
    title: 'Non-semver version format detected in lock file',
    recommendation:
      'Ensure all resolved versions conform to semver (x.y.z). ' +
      'Non-semver strings may indicate git references, local paths, or registry anomalies.',
  },
};

// ---------------------------------------------------------------------------
// PackageGateScanner — Phase 2 (implements Scanner)
// ---------------------------------------------------------------------------

export class PackageGateScanner implements Scanner {
  name = 'PackageGateScanner';
  description = 'Detects dependency version anomalies and supply-chain risks via lock file analysis';

  private parser = new PackageGateLockParser();

  async scan(targetDir: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;

    // Locate lock files under targetDir (recursive, skips node_modules / build dirs)
    const lockFiles: Array<{ filePath: string; type: 'npm' | 'pnpm' | 'bun' }> = [];

    function findLockFiles(dir: string, depth = 0): void {
      if (depth > 6) return;
      if (!fs.existsSync(dir)) return;
      let items: fs.Dirent[];
      try {
        items = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const item of items) {
        if (item.isDirectory()) {
          if (['node_modules', '.git', 'dist', 'build'].includes(item.name)) continue;
          findLockFiles(path.join(dir, item.name), depth + 1);
        } else if (item.isFile()) {
          const fullPath = path.join(dir, item.name);
          if (item.name === 'package-lock.json') lockFiles.push({ filePath: fullPath, type: 'npm' });
          else if (item.name === 'pnpm-lock.yaml') lockFiles.push({ filePath: fullPath, type: 'pnpm' });
          else if (item.name === 'bun.lockb') lockFiles.push({ filePath: fullPath, type: 'bun' });
        }
      }
    }

    findLockFiles(targetDir);

    for (const { filePath, type } of lockFiles) {
      filesScanned++;
      try {
        let content: string;
        if (type === 'bun') {
          // Read binary as latin1 to preserve byte values as ASCII codepoints
          content = fs.readFileSync(filePath, 'latin1');
        } else {
          content = fs.readFileSync(filePath, 'utf-8');
        }

        // Parse lock file
        let parsed: ParsedLockResult;
        switch (type) {
          case 'npm':  parsed = this.parser.parseNpmLock(content);  break;
          case 'pnpm': parsed = this.parser.parsePnpmLock(content); break;
          case 'bun':  parsed = this.parser.parseBunLock(content);  break;
        }

        // Detect version conflicts
        const conflicts = detectVersionConflicts(parsed);

        // Convert ConflictFinding[] → Finding[]
        for (const conflict of conflicts) {
          const rule = CONFLICT_RULE_MAP[conflict.conflictType];
          findings.push({
            id: rule.id,
            scanner: this.name,
            severity: conflict.severity,
            title: `[${conflict.packageName}] ${rule.title}`,
            description:
              conflict.details ??
              `Package "${conflict.packageName}" has ${conflict.conflictType} conflict.`,
            file: filePath,
            recommendation: rule.recommendation,
          });
        }
      } catch {
        // skip unreadable files
      }
    }

    // -----------------------------------------------------------------------
    // Phase 3B: Scan package.json files for suspicious install hooks
    // -----------------------------------------------------------------------

    const packageJsonFiles: string[] = [];

    function findPackageJsonFiles(dir: string, depth = 0): void {
      if (depth > 6) return;
      if (!fs.existsSync(dir)) return;
      let items: fs.Dirent[];
      try {
        items = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const item of items) {
        if (item.isDirectory()) {
          // Skip vendor / build dirs (same exclusion list as lock file search)
          if (['node_modules', '.git', 'dist', 'build'].includes(item.name)) continue;
          findPackageJsonFiles(path.join(dir, item.name), depth + 1);
        } else if (item.isFile() && item.name === 'package.json') {
          packageJsonFiles.push(path.join(dir, item.name));
        }
      }
    }

    findPackageJsonFiles(targetDir);

    for (const pkgJsonPath of packageJsonFiles) {
      filesScanned++;
      try {
        const content = fs.readFileSync(pkgJsonPath, 'utf-8');
        const hookFindings = detectSuspiciousHooks(content, pkgJsonPath);
        findings.push(...hookFindings);
      } catch {
        // skip unreadable files
      }
    }

    return {
      scanner: this.name,
      findings,
      scannedFiles: filesScanned,
      duration: Date.now() - start,
    };
  }
}
