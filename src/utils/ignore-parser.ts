import * as fs from 'fs';
import * as path from 'path';

/**
 * Default patterns for .sentoriignore (always excluded unless overridden)
 */
export const DEFAULT_SENTORI_IGNORE = [
  'node_modules/',
  '*.test.*',
  '__test__/',
  '__tests__/',
  'tests/',
  'coverage/',
  '.git/',
];

/**
 * Parse a .sentoriignore file (gitignore-like syntax).
 * Returns an array of patterns (strings).
 * 
 * Supports:
 * - Comments (#)
 * - Blank lines (ignored)
 * - Negation (!) — stored as-is, caller must handle
 * - Directory markers (trailing /)
 * - Glob patterns (*, **, ?)
 */
export function parseIgnoreFile(content: string): string[] {
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0 && !line.startsWith('#'));
}

/**
 * Read and parse a .sentoriignore file from a target directory.
 * Returns merged patterns (defaults + user patterns).
 * Negation patterns (!) remove matching default patterns.
 */
export function loadIgnorePatterns(targetPath: string): { patterns: string[]; hasFile: boolean } {
  const ignorePath = path.join(targetPath, '.sentoriignore');
  let userPatterns: string[] = [];
  let hasFile = false;

  try {
    if (fs.existsSync(ignorePath)) {
      const content = fs.readFileSync(ignorePath, 'utf-8');
      userPatterns = parseIgnoreFile(content);
      hasFile = true;
    }
  } catch {
    // File not readable, use defaults only
  }

  // Separate negation patterns from normal patterns
  const negations = userPatterns
    .filter(p => p.startsWith('!'))
    .map(p => p.slice(1));
  const additions = userPatterns.filter(p => !p.startsWith('!'));

  // Start with defaults, remove negated ones
  let merged = DEFAULT_SENTORI_IGNORE.filter(defaultPat => {
    return !negations.some(neg => neg === defaultPat || neg === defaultPat.replace(/\/$/, ''));
  });

  // Add user patterns
  merged = [...merged, ...additions];

  return { patterns: merged, hasFile };
}

/**
 * Convert .sentoriignore patterns to glob ignore patterns
 * compatible with the glob library.
 */
export function ignoreToGlobPatterns(patterns: string[]): string[] {
  return patterns.map(pattern => {
    // Remove leading /
    let p = pattern.startsWith('/') ? pattern.slice(1) : pattern;

    // Directory pattern (trailing /) → match all contents
    if (p.endsWith('/')) {
      return `**/${p}**`;
    }

    // If pattern has no path separator and no glob, treat as matching anywhere
    if (!p.includes('/') && !p.includes('**')) {
      // File glob pattern like *.test.* → match anywhere
      if (p.includes('*') || p.includes('?')) {
        return `**/${p}`;
      }
      // Plain name → treat as directory
      return `**/${p}/**`;
    }

    return p;
  });
}

/**
 * Check if a file path matches any of the ignore patterns.
 * Used for post-filtering files that were already found.
 */
export function shouldIgnoreFile(filePath: string, patterns: string[]): boolean {
  const normalized = filePath.replace(/\\/g, '/');

  for (const pattern of patterns) {
    let p = pattern;
    // Remove leading /
    if (p.startsWith('/')) p = p.slice(1);

    if (p.endsWith('/')) {
      // Directory pattern: check if path contains this directory
      const dirName = p.slice(0, -1);
      if (normalized.includes(`/${dirName}/`) || normalized.startsWith(`${dirName}/`)) {
        return true;
      }
    } else if (p.includes('*')) {
      // Glob pattern: simple matching
      const regex = globToRegex(p);
      if (regex.test(normalized)) {
        return true;
      }
    } else if (p.includes('/')) {
      // Path pattern
      if (normalized.includes(p)) {
        return true;
      }
    } else {
      // Plain name: match as directory
      if (normalized.includes(`/${p}/`) || normalized.startsWith(`${p}/`)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Convert a simple glob pattern to a RegExp.
 */
function globToRegex(pattern: string): RegExp {
  let regexStr = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');

  // If pattern doesn't start with **, prepend to match anywhere in path
  if (!pattern.startsWith('**')) {
    regexStr = `(?:^|/)${regexStr}`;
  }

  return new RegExp(regexStr);
}
