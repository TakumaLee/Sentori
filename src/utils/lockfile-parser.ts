import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

/**
 * PackageGate Lock File Parser
 * 
 * Purpose: Extract dependency information from lock files for supply-chain vulnerability detection.
 * Based on PackageGate research (2026-01 Koi Research Team)
 * 
 * Supports:
 * - package-lock.json (NPM)
 * - pnpm-lock.yaml (PNPM)
 * - bun.lockb (Bun) - basic support
 */

export interface PackageDependency {
  /** Package name (e.g., "express") */
  name: string;
  /** Resolved version (e.g., "4.18.2") */
  version: string;
  /** Resolved URL/tarball location */
  resolved?: string;
  /** Package integrity hash */
  integrity?: string;
  /** Is this a dev dependency? */
  dev?: boolean;
  /** Nested dependencies (if available) */
  dependencies?: Record<string, string>;
}

export interface LockFileParseResult {
  /** Lock file type */
  type: 'npm' | 'pnpm' | 'bun' | 'unknown';
  /** Lock file format version */
  lockfileVersion?: number | string;
  /** All resolved packages */
  packages: PackageDependency[];
  /** Parse errors (if any) */
  errors: string[];
}

/**
 * Parse package-lock.json (NPM v2/v3)
 */
function parseNPMLockfile(content: string): LockFileParseResult {
  const result: LockFileParseResult = {
    type: 'npm',
    packages: [],
    errors: [],
  };

  try {
    const lockData = JSON.parse(content);
    result.lockfileVersion = lockData.lockfileVersion;

    // NPM lockfile v2+ has "packages" field
    if (lockData.packages) {
      for (const [pkgPath, pkgData] of Object.entries<any>(lockData.packages)) {
        // Skip root entry (empty string key)
        if (pkgPath === '') continue;

        // Extract package name from path (e.g., "node_modules/express" -> "express")
        const name = pkgPath.replace(/^node_modules\//, '').split('/node_modules/').pop() || '';

        if (!name) continue;

        result.packages.push({
          name,
          version: pkgData.version || 'unknown',
          resolved: pkgData.resolved,
          integrity: pkgData.integrity,
          dev: pkgData.dev === true,
          dependencies: pkgData.dependencies,
        });
      }
    }

    // NPM lockfile v1 has "dependencies" field (nested structure)
    if (lockData.dependencies && !lockData.packages) {
      const extractDependencies = (deps: any, parentPath = ''): void => {
        for (const [name, data] of Object.entries<any>(deps)) {
          result.packages.push({
            name,
            version: data.version || 'unknown',
            resolved: data.resolved,
            integrity: data.integrity,
            dev: data.dev === true,
            dependencies: data.requires,
          });

          // Recursively extract nested dependencies
          if (data.dependencies) {
            extractDependencies(data.dependencies, `${parentPath}/${name}`);
          }
        }
      };

      extractDependencies(lockData.dependencies);
    }
  } catch (err) {
    result.errors.push(`Failed to parse NPM lockfile: ${err instanceof Error ? err.message : String(err)}`);
  }

  return result;
}

/**
 * Parse pnpm-lock.yaml (PNPM)
 */
function parsePNPMLockfile(content: string): LockFileParseResult {
  const result: LockFileParseResult = {
    type: 'pnpm',
    packages: [],
    errors: [],
  };

  try {
    const lockData = yaml.load(content) as any;
    result.lockfileVersion = lockData.lockfileVersion;

    // PNPM v6+ uses "packages" field with key format: "/package-name/version"
    if (lockData.packages) {
      for (const [pkgKey, pkgData] of Object.entries<any>(lockData.packages)) {
        // Parse package key: "/express/4.18.2" or "/@types/node/20.0.0"
        const match = pkgKey.match(/^\/(@?[^/]+(?:\/[^/]+)?)\/(.+)$/);
        if (!match) continue;

        const name = match[1]; // e.g., "express" or "@types/node"
        const version = match[2]; // e.g., "4.18.2"

        result.packages.push({
          name,
          version,
          resolved: pkgData.resolution?.tarball,
          integrity: pkgData.resolution?.integrity,
          dev: pkgData.dev === true,
          dependencies: pkgData.dependencies,
        });
      }
    }

    // PNPM v5 and earlier use different structure
    if (lockData.specifiers && !lockData.packages) {
      for (const [name, version] of Object.entries<string>(lockData.specifiers)) {
        result.packages.push({
          name,
          version,
          dev: false,
        });
      }
    }
  } catch (err) {
    result.errors.push(`Failed to parse PNPM lockfile: ${err instanceof Error ? err.message : String(err)}`);
  }

  return result;
}

/**
 * Parse bun.lockb (Bun binary lockfile)
 * Note: Bun lockfiles are in binary format and require special handling.
 * This is a basic implementation that may not work for all cases.
 */
function parseBunLockfile(filePath: string): LockFileParseResult {
  const result: LockFileParseResult = {
    type: 'bun',
    packages: [],
    errors: [],
  };

  try {
    // Bun lockfiles are binary format, not easily parseable without Bun runtime
    // For now, we return a warning and suggest using Bun CLI
    result.errors.push(
      'Bun lockfiles (.lockb) are in binary format and cannot be parsed directly. ' +
      'Consider using `bun install --dry-run` or `bun pm ls` to inspect dependencies.'
    );
  } catch (err) {
    result.errors.push(`Failed to parse Bun lockfile: ${err instanceof Error ? err.message : String(err)}`);
  }

  return result;
}

/**
 * Auto-detect and parse lock file
 */
export function parseLockfile(filePath: string): LockFileParseResult {
  const basename = path.basename(filePath).toLowerCase();

  if (!fs.existsSync(filePath)) {
    return {
      type: 'unknown',
      packages: [],
      errors: [`Lock file not found: ${filePath}`],
    };
  }

  try {
    // Detect lock file type by filename
    if (basename === 'package-lock.json') {
      const content = fs.readFileSync(filePath, 'utf-8');
      return parseNPMLockfile(content);
    } else if (basename === 'pnpm-lock.yaml') {
      const content = fs.readFileSync(filePath, 'utf-8');
      return parsePNPMLockfile(content);
    } else if (basename === 'bun.lockb') {
      return parseBunLockfile(filePath);
    } else {
      return {
        type: 'unknown',
        packages: [],
        errors: [`Unknown lock file type: ${basename}`],
      };
    }
  } catch (err) {
    return {
      type: 'unknown',
      packages: [],
      errors: [`Failed to read lock file: ${err instanceof Error ? err.message : String(err)}`],
    };
  }
}

/**
 * Find all lock files in a directory (non-recursive)
 */
export function findLockfiles(dir: string): string[] {
  const lockfiles: string[] = [];
  const filenames = ['package-lock.json', 'pnpm-lock.yaml', 'bun.lockb'];

  for (const filename of filenames) {
    const filepath = path.join(dir, filename);
    if (fs.existsSync(filepath)) {
      lockfiles.push(filepath);
    }
  }

  return lockfiles;
}

/**
 * Extract all unique packages from multiple lock files
 */
export function mergePackages(results: LockFileParseResult[]): PackageDependency[] {
  const packageMap = new Map<string, PackageDependency>();

  for (const result of results) {
    for (const pkg of result.packages) {
      const key = `${pkg.name}@${pkg.version}`;
      // Keep first occurrence (prefer npm over pnpm over bun)
      if (!packageMap.has(key)) {
        packageMap.set(key, pkg);
      }
    }
  }

  return Array.from(packageMap.values());
}

/**
 * Get package summary statistics
 */
export interface PackageSummary {
  totalPackages: number;
  prodPackages: number;
  devPackages: number;
  uniqueNames: number;
  lockfileType: string;
}

export function summarizePackages(result: LockFileParseResult): PackageSummary {
  const uniqueNames = new Set(result.packages.map((p) => p.name));
  const prodCount = result.packages.filter((p) => !p.dev).length;
  const devCount = result.packages.filter((p) => p.dev).length;

  return {
    totalPackages: result.packages.length,
    prodPackages: prodCount,
    devPackages: devCount,
    uniqueNames: uniqueNames.size,
    lockfileType: result.type,
  };
}
