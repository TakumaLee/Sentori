/**
 * CustomRulesScanner — runs user-defined pattern rules from .sentori.yml
 *
 * Only registered when a .sentori.yml with at least one rule is present.
 */

import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { ScanResult, Finding, Severity } from '../types';
import { CustomRule } from '../config/sentori-config';

export const CUSTOM_RULES_SCANNER_NAME = 'Custom Rules';

const DEFAULT_GLOB = '**/*';
const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/*.min.js',
  '**/*.map',
];

/** Max file size to scan (1 MB) */
const MAX_FILE_BYTES = 1_048_576;

/**
 * Maximum time (ms) allowed for scanning a single file with a single rule.
 * If exceeded, an info-level finding is emitted and the remaining lines are skipped.
 * Note: this guards against pathological regexes across many lines; a single
 * catastrophically-backtracking re.exec() call cannot be interrupted by JS.
 */
const MATCH_TIMEOUT_MS = 5_000;

function isBinaryExtension(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.woff', '.woff2',
    '.ttf', '.eot', '.otf', '.pdf', '.zip', '.gz', '.tar', '.bin',
    '.exe', '.dll', '.so', '.dylib', '.lock'].includes(ext);
}

export async function runCustomRules(
  targetDir: string,
  rules: CustomRule[],
): Promise<ScanResult> {
  const start = Date.now();
  const findings: Finding[] = [];

  // Build per-rule compiled regex
  const compiled = rules.map((r) => {
    let re: RegExp | null = null;
    try {
      re = new RegExp(r.pattern, 'g');
    } catch (err) {
      findings.push({
        scanner: CUSTOM_RULES_SCANNER_NAME,
        severity: 'info',
        rule: r.id,
        title: `[Custom] Invalid regex in rule "${r.id}"`,
        message: `Rule "${r.id}" has an invalid regex pattern and was skipped: ${(err as Error).message}`,
        description: `Rule "${r.id}" has an invalid regex pattern and was skipped: ${(err as Error).message}`,
        evidence: r.pattern,
      });
    }
    return { rule: r, re };
  });

  // Group rules by file glob pattern to minimise glob calls
  const globPatternMap = new Map<string, typeof compiled>();
  for (const entry of compiled) {
    if (!entry.re) continue;
    const g = entry.rule.files ?? DEFAULT_GLOB;
    if (!globPatternMap.has(g)) globPatternMap.set(g, []);
    globPatternMap.get(g)!.push(entry);
  }

  for (const [globPattern, ruleEntries] of globPatternMap) {
    const files = await glob(globPattern, {
      cwd: targetDir,
      nodir: true,
      ignore: DEFAULT_IGNORE,
      absolute: true,
    });

    for (const filePath of files) {
      if (isBinaryExtension(filePath)) continue;

      let content: string;
      try {
        const stat = fs.statSync(filePath);
        if (stat.size > MAX_FILE_BYTES) continue;
        content = fs.readFileSync(filePath, 'utf-8');
      } catch (readErr) {
        // File is unreadable (permissions, broken symlink, etc.) — skip silently.
        // Set SENTORI_DEBUG=1 to surface these errors during development.
        if (process.env['SENTORI_DEBUG']) {
          process.stderr.write(`[custom-rules] skipping unreadable file ${filePath}: ${(readErr as Error).message}\n`);
        }
        continue;
      }

      const relPath = path.relative(targetDir, filePath);
      const lines = content.split('\n');

      for (const { rule, re } of ruleEntries) {
        if (!re) continue;
        re.lastIndex = 0; // reset global regex state

        for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
          // Guard: bail out if the overall scan has been running too long.
          // Cannot interrupt a blocking re.exec(), but prevents runaway multi-line scans.
          if (Date.now() - start > MATCH_TIMEOUT_MS) {
            findings.push({
              scanner: CUSTOM_RULES_SCANNER_NAME,
              severity: 'info',
              rule: rule.id,
              title: `[Custom] Regex timeout in rule "${rule.id}"`,
              message: `Rule "${rule.id}" exceeded ${MATCH_TIMEOUT_MS}ms scanning ${relPath} — results may be incomplete`,
              description: `Rule "${rule.id}" exceeded ${MATCH_TIMEOUT_MS}ms scanning ${relPath} — results may be incomplete`,
              file: relPath,
              line: lineIdx + 1,
            });
            break;
          }

          const line = lines[lineIdx];
          let match: RegExpExecArray | null;
          re.lastIndex = 0;
          while ((match = re.exec(line)) !== null) {
            findings.push({
              scanner: CUSTOM_RULES_SCANNER_NAME,
              severity: rule.severity as Severity,
              rule: rule.id,
              title: `[Custom] ${rule.id}`,
              message: rule.message,
              description: rule.message,
              evidence: match[0].slice(0, 120),
              file: relPath,
              line: lineIdx + 1,
            });
            // Avoid infinite loop on zero-length match
            if (match[0].length === 0) break;
          }
        }
      }
    }
  }

  return {
    scanner: CUSTOM_RULES_SCANNER_NAME,
    findings,
    duration: Date.now() - start,
  };
}

/** ScannerModule-compatible wrapper for the registry */
export const customRulesScanner = (rules: CustomRule[]) => ({
  name: CUSTOM_RULES_SCANNER_NAME,
  description: 'User-defined pattern rules from .sentori.yml',
  async scan(targetDir: string): Promise<ScanResult> {
    return runCustomRules(targetDir, rules);
  },
});
