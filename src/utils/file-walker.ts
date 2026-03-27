import * as fs from 'fs';
import * as path from 'path';
import { shouldIgnoreFile } from './ignore-parser';

export interface FileEntry {
  path: string;
  relativePath: string;
  content: string;
}

const SCAN_EXTENSIONS = new Set(['.md', '.sh', '.py', '.js', '.ts', '.yaml', '.yml', '.json', '.txt', '.plist', '.toml', '.cfg']);

/** Default maximum file size in bytes (10 MB). */
export const DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;

export interface WalkOptions {
  extensions?: Set<string>;
  /** Maximum file size in bytes. Files larger than this are skipped. Default: 10 MB. */
  maxFileSize?: number;
  /**
   * When true, include vendored/third-party directories (third_party, external,
   * deps, etc.). Default: false (vendored dirs are skipped).
   */
  includeVendored?: boolean;
  /** User-supplied exclude patterns (from --exclude flag). Plain names → dir glob, glob patterns used as-is. */
  exclude?: string[];
  /** Patterns loaded from .sentoriignore file */
  sentoriIgnorePatterns?: string[];
}

/** Directory names considered vendored/third-party — skipped unless includeVendored is true. */
const VENDORED_SKIP_DIRS = new Set([
  'third_party', 'third-party', 'thirdparty',
  'external', 'deps',
]);

export function walkFiles(dir: string, extensionsOrOpts?: Set<string> | WalkOptions): FileEntry[] {
  let exts: Set<string>;
  let maxFileSize: number;
  let includeVendored: boolean;
  let exclude: string[];
  let sentoriIgnorePatterns: string[];

  if (extensionsOrOpts instanceof Set) {
    exts = extensionsOrOpts;
    maxFileSize = DEFAULT_MAX_FILE_SIZE;
    includeVendored = false;
    exclude = [];
    sentoriIgnorePatterns = [];
  } else if (extensionsOrOpts) {
    exts = extensionsOrOpts.extensions ?? SCAN_EXTENSIONS;
    maxFileSize = extensionsOrOpts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
    includeVendored = extensionsOrOpts.includeVendored ?? false;
    exclude = extensionsOrOpts.exclude ?? [];
    sentoriIgnorePatterns = extensionsOrOpts.sentoriIgnorePatterns ?? [];
  } else {
    exts = SCAN_EXTENSIONS;
    maxFileSize = DEFAULT_MAX_FILE_SIZE;
    includeVendored = false;
    exclude = [];
    sentoriIgnorePatterns = [];
  }

  const allExcludePatterns = [...exclude, ...sentoriIgnorePatterns];

  const entries: FileEntry[] = [];

  function walk(currentDir: string): void {
    if (!fs.existsSync(currentDir)) return;
    const items = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      if (item.isDirectory()) {
        // Skip common large/irrelevant directories
        const skipDirs = new Set([
          'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
          'browser', 'Extensions', '.cache', 'Cache', 'CacheStorage',
          'GPUCache', 'ShaderCache', 'GrShaderCache', '__pycache__',
          '.venv', 'venv', '.tox', '.mypy_cache',
          'models', 'checkpoints', 'weights',  // ML model dirs
          'sd-setup',  // Stable Diffusion
          // Runtime data directories (sync with DEFAULT_IGNORE in file-utils.ts)
          'outputs', 'output', 'data', 'logs', 'dbs',
          'vault', 'uploads', 'history', 'runtime',
          'snapshots', 'crawl', 'scraped', 'downloaded',
          'sessions', 'cron-runs', 'media',  // Agent runtime
        ]);
        if (skipDirs.has(item.name)) continue;
        if (!includeVendored && VENDORED_SKIP_DIRS.has(item.name)) continue;
        // Check user-supplied exclude patterns for directories
        if (allExcludePatterns.length > 0) {
          const relDir = path.relative(dir, fullPath);
          if (shouldIgnoreFile(relDir + '/x', allExcludePatterns)) continue;
        }
        walk(fullPath);
      } else if (item.isFile()) {
        const ext = path.extname(item.name).toLowerCase();
        if (exts.has(ext) || item.name === 'SKILL.md' || item.name === 'Makefile') {
          // Check user-supplied exclude patterns for files
          if (allExcludePatterns.length > 0) {
            const relFile = path.relative(dir, fullPath);
            if (shouldIgnoreFile(relFile, allExcludePatterns)) continue;
          }
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > maxFileSize) {
              console.warn(`[Sentori] Skipping large file (${(stat.size / 1024 / 1024).toFixed(1)} MB): ${path.relative(dir, fullPath)}`);
              continue;
            }
            const content = fs.readFileSync(fullPath, 'utf-8');
            entries.push({
              path: fullPath,
              relativePath: path.relative(dir, fullPath),
              content,
            });
          } catch {
            // skip unreadable files
          }
        }
      }
    }
  }

  walk(dir);
  return entries;
}
