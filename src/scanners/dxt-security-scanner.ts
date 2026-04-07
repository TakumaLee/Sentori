import * as fs from 'fs';
import * as path from 'path';
import { z } from 'zod';
import { Scanner, ScannerOptions, ScanResult, Finding, Severity } from '../types';

// --- Types ---

export interface DxtExtensionConfig {
  name?: string;
  version?: string;
  permissions?: DxtPermissions;
  sandbox?: boolean | DxtSandboxConfig;
  signature?: DxtSignature;
  data_sources?: DxtDataSource[];
  executors?: DxtExecutor[];
  [key: string]: unknown;
}

export interface DxtPermissions {
  file_system?: boolean | string[];
  network?: boolean | string[];
  code_execution?: boolean;
  clipboard?: boolean;
  notifications?: boolean;
  [key: string]: unknown;
}

export interface DxtSandboxConfig {
  enabled?: boolean;
  level?: string;
}

export interface DxtSignature {
  signed?: boolean;
  verified?: boolean;
  issuer?: string;
}

export interface DxtDataSource {
  type: string; // 'calendar', 'email', 'webhook', 'api', etc.
  external?: boolean;
  [key: string]: unknown;
}

export interface DxtExecutor {
  type: string; // 'shell', 'script', 'binary', etc.
  unrestricted?: boolean;
  [key: string]: unknown;
}

// --- Zod schemas ---

// Validates the top-level structure of a DXT config file before passing it to
// extractExtensions(). This prevents type-confusion crashes from malformed
// JSON that happens to parse without error (e.g. a bare array or string).
const DxtConfigFileSchema = z.union([
  // Single extension at top level or nested under `extensions`/`dxt_extensions`
  z.record(z.string(), z.unknown()),
  // Some tools emit an array of extension configs
  z.array(z.unknown()),
]);

// --- Helpers ---

function isSandboxed(ext: DxtExtensionConfig): boolean {
  if (ext.sandbox === true) return true;
  if (typeof ext.sandbox === 'object' && ext.sandbox?.enabled === true) return true;
  return false;
}

function hasExternalDataSource(ext: DxtExtensionConfig): boolean {
  if (!ext.data_sources) return false;
  return ext.data_sources.some(
    (ds) => ds.external === true || ['calendar', 'email', 'webhook', 'api'].includes(ds.type)
  );
}

function hasLocalExecutor(ext: DxtExtensionConfig): boolean {
  if (!ext.executors) return false;
  return ext.executors.some(
    (ex) => ['shell', 'script', 'binary'].includes(ex.type)
  );
}

function hasUnrestrictedPermission(perms: DxtPermissions, key: string): boolean {
  const val = perms[key];
  if (val === true) return true;
  return false;
}

function isUnsigned(ext: DxtExtensionConfig): boolean {
  if (!ext.signature) return true;
  return ext.signature.signed !== true;
}

function isUnverified(ext: DxtExtensionConfig): boolean {
  if (!ext.signature) return true;
  return ext.signature.verified !== true;
}

// --- Scanner ---

export class DxtSecurityScanner implements Scanner {
  name = 'DxtSecurityScanner';
  description =
    'Scans for insecure Claude Desktop Extension (DXT) configurations: unsandboxed extensions, dangerous permission combos, unsigned packages';

  /**
   * Scan a target directory for DXT extension configs.
   * Looks for JSON files that contain DXT extension definitions.
   */
  async scan(targetDir: string, _options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Collect DXT config files
    const configFiles = this.findDxtConfigs(targetDir);

    for (const file of configFiles) {
      let content: string;
      try {
        content = fs.readFileSync(file, 'utf-8');
      } catch (err) {
        process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'DxtSecurityScanner', file, error: 'Failed to read DXT config file — skipping', message: String(err) }) + '\n');
        continue;
      }

      let rawParsed: unknown;
      try {
        rawParsed = JSON.parse(content);
      } catch (err) {
        process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'DxtSecurityScanner', file, error: 'DXT config JSON parse failed — skipping', message: String(err) }) + '\n');
        continue;
      }
      const dxtSchemaResult = DxtConfigFileSchema.safeParse(rawParsed);
      if (!dxtSchemaResult.success) {
        process.stderr.write(JSON.stringify({ level: 'warn', scanner: 'DxtSecurityScanner', file, error: 'DXT config JSON has unexpected shape (not an object or array) — skipping', issues: dxtSchemaResult.error.issues }) + '\n');
        continue;
      }
      const parsed: unknown = dxtSchemaResult.data;

      const extensions = this.extractExtensions(parsed);
      const relPath = path.relative(targetDir, file);
      for (const [extName, ext] of extensions) {
        findings.push(...this.auditExtension(extName, ext, relPath));
      }
    }

    return {
      scanner: this.name,
      findings,
      filesScanned: configFiles.length,
      duration: Date.now() - start,
    };
  }

  /**
   * Audit a single extension config. Exported for direct testing.
   */
  auditExtension(extName: string, ext: DxtExtensionConfig, filePath?: string): Finding[] {
    const findings: Finding[] = [];
    const perms = ext.permissions || {};
    const sandboxed = isSandboxed(ext);
    const externalData = hasExternalDataSource(ext);
    const localExec = hasLocalExecutor(ext);

    // DXT-001: CRITICAL — unsandboxed extension with external data access + local executor
    if (!sandboxed && externalData && localExec) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-001',
        severity: 'critical',
        file: filePath,
        message: `DXT extension "${extName}" is unsandboxed with external data source AND local executor — arbitrary code execution via malicious input (e.g. calendar invite)`,
        recommendation:
          'Enable sandboxing, restrict executor permissions, or remove external data sources from this extension',
        confidence: 'definite',
      });
    }

    // DXT-002: HIGH — unrestricted file system access
    if (hasUnrestrictedPermission(perms, 'file_system')) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-002',
        severity: 'high',
        file: filePath,
        message: `DXT extension "${extName}" has unrestricted file system access`,
        recommendation: 'Restrict file_system permission to specific paths instead of blanket access',
        confidence: 'definite',
      });
    }

    // DXT-003: HIGH — unrestricted network access
    if (hasUnrestrictedPermission(perms, 'network')) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-003',
        severity: 'high',
        file: filePath,
        message: `DXT extension "${extName}" has unrestricted network access`,
        recommendation: 'Restrict network permission to specific domains/endpoints',
        confidence: 'definite',
      });
    }

    // DXT-004: HIGH — code execution permission enabled
    if (hasUnrestrictedPermission(perms, 'code_execution')) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-004',
        severity: 'high',
        file: filePath,
        message: `DXT extension "${extName}" has code execution permission enabled`,
        recommendation: 'Disable code_execution unless absolutely required; use sandboxed execution instead',
        confidence: 'definite',
      });
    }

    // DXT-005: HIGH — extension not sandboxed
    if (!sandboxed) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-005',
        severity: 'high',
        file: filePath,
        message: `DXT extension "${extName}" is running without sandboxing`,
        recommendation: 'Enable sandbox mode to limit extension privileges',
        confidence: 'definite',
      });
    }

    // DXT-006: HIGH — unsigned extension
    if (isUnsigned(ext)) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-006',
        severity: 'high',
        file: filePath,
        message: `DXT extension "${extName}" is unsigned`,
        recommendation: 'Only install signed DXT extensions from trusted sources',
        confidence: 'definite',
      });
    }

    // DXT-007: MEDIUM — signed but unverified extension
    if (!isUnsigned(ext) && isUnverified(ext)) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-007',
        severity: 'medium',
        file: filePath,
        message: `DXT extension "${extName}" is signed but signature is not verified`,
        recommendation: 'Verify extension signature before installation',
        confidence: 'likely',
      });
    }

    // DXT-008: MEDIUM — dangerous permission combo (file_system + network without sandbox)
    if (
      !sandboxed &&
      (hasUnrestrictedPermission(perms, 'file_system') || Array.isArray(perms.file_system)) &&
      (hasUnrestrictedPermission(perms, 'network') || Array.isArray(perms.network))
    ) {
      // Only add if not already covered by DXT-001
      if (sandboxed || !externalData || !localExec) {
        findings.push({
          scanner: this.name,
          rule: 'DXT-008',
          severity: 'medium',
          file: filePath,
          message: `DXT extension "${extName}" has both file system and network access without sandboxing — potential exfiltration vector`,
          recommendation: 'Enable sandboxing or restrict one of the two permissions',
          confidence: 'likely',
        });
      }
    }

    // DXT-009: MEDIUM — external data source without sandbox
    if (!sandboxed && externalData && !localExec) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-009',
        severity: 'medium',
        file: filePath,
        message: `DXT extension "${extName}" has external data sources without sandboxing`,
        recommendation: 'Enable sandboxing for extensions that process external data',
        confidence: 'likely',
      });
    }

    // DXT-010: MEDIUM — unrestricted executor
    if (ext.executors?.some((ex) => ex.unrestricted === true)) {
      findings.push({
        scanner: this.name,
        rule: 'DXT-010',
        severity: 'medium',
        file: filePath,
        message: `DXT extension "${extName}" has an unrestricted executor`,
        recommendation: 'Restrict executor capabilities to minimum required permissions',
        confidence: 'definite',
      });
    }

    return findings;
  }

  /** Find DXT-related config files in the target directory */
  private findDxtConfigs(targetDir: string): string[] {
    const configs: string[] = [];

    // Search common Claude Desktop config paths
    const searchPaths = [
      targetDir,
      path.join(targetDir, '.claude'),
      path.join(targetDir, '.claude', 'extensions'),
      path.join(targetDir, 'extensions'),
    ];

    for (const dir of searchPaths) {
      if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) continue;
      this.walkJsonFiles(dir, configs, 3);
    }

    return [...new Set(configs)];
  }

  /** Recursively find JSON files up to maxDepth */
  private walkJsonFiles(dir: string, results: string[], maxDepth: number): void {
    if (maxDepth <= 0) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        this.walkJsonFiles(full, results, maxDepth - 1);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        results.push(full);
      }
    }
  }

  /**
   * Extract extension definitions from a parsed config.
   * Supports both top-level extension objects and nested `extensions` / `dxt_extensions` maps.
   */
  private extractExtensions(parsed: unknown): Array<[string, DxtExtensionConfig]> {
    if (!parsed || typeof parsed !== 'object') return [];
    const obj = parsed as Record<string, unknown>;
    const results: Array<[string, DxtExtensionConfig]> = [];

    // If top-level has `extensions` or `dxt_extensions` map
    for (const key of ['extensions', 'dxt_extensions']) {
      const map = obj[key];
      if (map && typeof map === 'object' && !Array.isArray(map)) {
        for (const [name, config] of Object.entries(map as Record<string, unknown>)) {
          if (config && typeof config === 'object') {
            results.push([name, config as DxtExtensionConfig]);
          }
        }
      }
    }

    // If top-level itself looks like a single extension config (has permissions or executors)
    if (results.length === 0 && (obj.permissions || obj.executors || obj.data_sources || obj.sandbox !== undefined)) {
      const name = (obj.name as string) || 'unknown';
      results.push([name, obj as DxtExtensionConfig]);
    }

    return results;
  }
}
