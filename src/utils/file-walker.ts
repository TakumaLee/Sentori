import * as fs from 'fs';
import * as path from 'path';

export interface FileEntry {
  path: string;
  relativePath: string;
  content: string;
}

const SCAN_EXTENSIONS = new Set(['.md', '.sh', '.py', '.js', '.ts', '.yaml', '.yml', '.json', '.txt', '.plist']);

export function walkFiles(dir: string, extensions?: Set<string>): FileEntry[] {
  const exts = extensions ?? SCAN_EXTENSIONS;
  const entries: FileEntry[] = [];

  function walk(currentDir: string): void {
    if (!fs.existsSync(currentDir)) return;
    const items = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      if (item.isDirectory()) {
        if (item.name === 'node_modules' || item.name === '.git') continue;
        walk(fullPath);
      } else if (item.isFile()) {
        const ext = path.extname(item.name).toLowerCase();
        if (exts.has(ext) || item.name === 'SKILL.md' || item.name === 'Makefile') {
          try {
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
