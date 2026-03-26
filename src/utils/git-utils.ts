import { execFileSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Check if a file is tracked by git.
 * Returns true if the file is in git's index (tracked), false otherwise.
 * Returns null if git is not available or directory is not a git repo.
 */
export function isGitTracked(filePath: string): boolean | null {
  try {
    const dir = path.dirname(filePath);
    const basename = path.basename(filePath);

    // Check if this is a git repo
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
      cwd: dir,
      stdio: 'pipe',
    });

    // Check if file is tracked — use execFileSync to avoid shell injection
    execFileSync('git', ['ls-files', '--error-unmatch', basename], {
      cwd: dir,
      stdio: 'pipe',
    });

    return true; // File is tracked
  } catch {
    // Either not a git repo or file is not tracked
    // Distinguish between "not a git repo" and "file not tracked"
    try {
      const dir = path.dirname(filePath);
      execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
        cwd: dir,
        stdio: 'pipe',
      });
      // It IS a git repo, but file is not tracked
      return false;
    } catch {
      // Not a git repo
      return null;
    }
  }
}

/**
 * Check if a file is protected by .gitignore.
 * Returns true if the file matches a .gitignore pattern.
 */
export function isGitIgnored(filePath: string): boolean {
  try {
    const dir = path.dirname(filePath);
    const basename = path.basename(filePath);

    execFileSync('git', ['check-ignore', '-q', basename], {
      cwd: dir,
      stdio: 'pipe',
    });

    return true; // File is ignored
  } catch {
    return false; // Not ignored (or not a git repo)
  }
}

/**
 * Determine if a file is "locally protected" — not tracked by git
 * and covered by .gitignore rules.
 */
export function isLocallyProtected(filePath: string): boolean {
  const tracked = isGitTracked(filePath);
  if (tracked === null) return false; // Not a git repo — can't determine
  if (tracked) return false; // Tracked — not locally protected
  return isGitIgnored(filePath); // Not tracked — check if gitignored
}

/**
 * Batch check: get git tracking status for multiple files.
 * More efficient than checking one by one.
 */
export function getGitTrackingStatus(targetPath: string, files: string[]): Map<string, 'tracked' | 'untracked' | 'unknown'> {
  const result = new Map<string, 'tracked' | 'untracked' | 'unknown'>();

  // Check if target is a git repo
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
      cwd: targetPath,
      stdio: 'pipe',
    });
  } catch {
    // Not a git repo
    for (const f of files) result.set(f, 'unknown');
    return result;
  }

  // Get all tracked files
  let trackedFiles: Set<string>;
  try {
    const output = execFileSync('git', ['ls-files'], {
      cwd: targetPath,
      stdio: 'pipe',
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large repos
    }).toString().trim();

    trackedFiles = new Set(
      output.split('\n')
        .filter(f => f.length > 0)
        .map(f => path.resolve(targetPath, f))
    );
  } catch {
    for (const f of files) result.set(f, 'unknown');
    return result;
  }

  for (const f of files) {
    const resolved = path.resolve(f);
    result.set(f, trackedFiles.has(resolved) ? 'tracked' : 'untracked');
  }

  return result;
}
