/**
 * PackageGateScanner — Phase 1: Lock file parser
 *
 * Supports:
 *  - package-lock.json  (npm)
 *  - pnpm-lock.yaml     (pnpm)
 *  - bun.lockb          (bun; binary but contains ASCII-readable sections)
 */

import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScanResult, Finding } from '../types';

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
// PackageGateScanner — Phase 1 skeleton (implements Scanner)
// Scan logic is deferred to Phase 2.
// ---------------------------------------------------------------------------

export class PackageGateScanner implements Scanner {
  name = 'PackageGateScanner';
  description = 'Detects dependency version anomalies and supply-chain risks via lock file analysis';

  private parser = new PackageGateLockParser();

  async scan(targetDir: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    let filesScanned = 0;

    // Locate lock files under targetDir
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

        // TODO (Phase 2): analyse parsed result for:
        //   - Version pinning violations
        //   - Known-malicious packages (CVE / IOC cross-reference)
        //   - Registry confusion (non-standard resolved URLs)
        //   - Ghost dependencies
        //   - Version drift across workspaces
        let _parsed;
        switch (type) {
          case 'npm':  _parsed = this.parser.parseNpmLock(content);  break;
          case 'pnpm': _parsed = this.parser.parsePnpmLock(content); break;
          case 'bun':  _parsed = this.parser.parseBunLock(content);  break;
        }
        // Phase 2 will use _parsed to generate findings
      } catch {
        // skip unreadable files
      }
    }

    return {
      scanner: this.name,
      findings,
      filesScanned,
      duration: Date.now() - start,
    };
  }
}
