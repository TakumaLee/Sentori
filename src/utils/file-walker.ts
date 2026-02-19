import * as fs from 'fs';
import * as path from 'path';

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
}

export function walkFiles(dir: string, extensionsOrOpts?: Set<string> | WalkOptions): FileEntry[] {
  let exts: Set<string>;
  let maxFileSize: number;

  if (extensionsOrOpts instanceof Set) {
    exts = extensionsOrOpts;
    maxFileSize = DEFAULT_MAX_FILE_SIZE;
  } else if (extensionsOrOpts) {
    exts = extensionsOrOpts.extensions ?? SCAN_EXTENSIONS;
    maxFileSize = extensionsOrOpts.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  } else {
    exts = SCAN_EXTENSIONS;
    maxFileSize = DEFAULT_MAX_FILE_SIZE;
  }

  const entries: FileEntry[] = [];

  function walk(currentDir: string): void {
    if (!fs.existsSync(currentDir)) return;
    const items = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      if (item.isDirectory()) {
        // Skip common large/irrelevant directories
        const skipDirs = new Set([
          'node_modules', '.git', 'dist', 'build', 'coverage',
          'browser', 'Extensions', '.cache', 'Cache', 'CacheStorage',
          'GPUCache', 'ShaderCache', 'GrShaderCache', '__pycache__',
          '.venv', 'venv', '.tox', '.mypy_cache',
          'models', 'checkpoints', 'weights',  // ML model dirs
          'sd-setup',  // Stable Diffusion
        ]);
        if (skipDirs.has(item.name)) continue;
        walk(fullPath);
      } else if (item.isFile()) {
        const ext = path.extname(item.name).toLowerCase();
        if (exts.has(ext) || item.name === 'SKILL.md' || item.name === 'Makefile') {
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
