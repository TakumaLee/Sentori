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
  /** When true, scan sub-projects inside workspace/ directories. Default: false. */
  includeWorkspaceProjects?: boolean;
}

/** Files that indicate a directory is a project root. */
const PROJECT_MARKERS = [
  'package.json', 'go.mod', 'Cargo.toml', 'pyproject.toml',
  'setup.py', 'requirements.txt', 'pubspec.yaml', 'Gemfile',
  'pom.xml', 'build.gradle', 'build.gradle.kts', 'Makefile',
  'CMakeLists.txt', 'composer.json', 'mix.exs',
];

/** Known workspace directory names used by AI agent systems. */
const WORKSPACE_DIRS = new Set([
  'workspace', 'workspaces',
]);

/**
 * Check if a directory looks like a sub-project root
 * (has .git or a build system manifest).
 */
function isProjectRoot(dirPath: string): boolean {
  try {
    const items = fs.readdirSync(dirPath);
    if (items.includes('.git')) return true;
    return PROJECT_MARKERS.some(m => items.includes(m));
  } catch {
    return false;
  }
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
  let includeWorkspaceProjects: boolean;
  let exclude: string[];
  let sentoriIgnorePatterns: string[];

  if (extensionsOrOpts instanceof Set) {
    exts = extensionsOrOpts;
    maxFileSize = DEFAULT_MAX_FILE_SIZE;
    includeVendored = false;
    includeWorkspaceProjects = false;
    exclude = [];
    sentoriIgnorePatterns = [];
  } else if (extensionsOrOpts) {
    exts = extensionsOrOpts.extensions ?? SCAN_EXTENSIONS;
    maxFileSize = extensionsOrOpts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
    includeVendored = extensionsOrOpts.includeVendored ?? false;
    includeWorkspaceProjects = extensionsOrOpts.includeWorkspaceProjects ?? false;
    exclude = extensionsOrOpts.exclude ?? [];
    sentoriIgnorePatterns = extensionsOrOpts.sentoriIgnorePatterns ?? [];
  } else {
    exts = SCAN_EXTENSIONS;
    maxFileSize = DEFAULT_MAX_FILE_SIZE;
    includeVendored = false;
    includeWorkspaceProjects = false;
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
        // Skip sub-projects inside workspace/ directories (default: off)
        if (!includeWorkspaceProjects && WORKSPACE_DIRS.has(path.basename(currentDir))) {
          if (isProjectRoot(fullPath)) continue;
        }
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
