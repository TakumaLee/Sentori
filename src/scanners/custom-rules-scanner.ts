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

// ---------------------------------------------------------------------------
// ReDoS heuristic — pre-compile pattern validation
// ---------------------------------------------------------------------------

/**
 * Returns true if the regex body (a slice of a pattern string inside a group)
 * contains a repeating quantifier (+, *, or unbounded {n,} / {n,m}) OR a bare
 * alternation operator (|) outside of a character class or escape sequence.
 *
 * Alternation under a repeating outer quantifier is a textbook ReDoS vector:
 * e.g. (cat|dog)+ causes catastrophic backtracking on non-matching input.
 *
 * This is used as the inner check for nested-quantifier / alternation ReDoS detection.
 */
function bodyContainsQuantifier(body: string): boolean {
  let i = 0;
  while (i < body.length) {
    const ch = body[i];
    if (ch === '\\') {
      i += 2; // skip escape sequence
      continue;
    }
    if (ch === '[') {
      // skip character class
      i++;
      while (i < body.length) {
        if (body[i] === '\\') { i += 2; }
        else if (body[i] === ']') { i++; break; }
        else { i++; }
      }
      continue;
    }
    if (ch === '+' || ch === '*' || ch === '|') return true;
    if (ch === '{') {
      // {n,} or {n,m} — both allow repetition beyond 1 occurrence
      const close = body.indexOf('}', i + 1);
      if (close !== -1 && body.slice(i + 1, close).includes(',')) return true;
    }
    i++;
  }
  return false;
}

/**
 * Detects catastrophic backtracking (ReDoS) patterns via structural heuristics.
 *
 * Flags **nested quantifiers**: a group followed by a repeating quantifier whose
 * body also contains a repeating quantifier.  This is the dominant cause of
 * exponential/polynomial backtracking in JavaScript's RegExp engine and cannot
 * be interrupted once a `re.exec()` call starts.
 *
 * Examples that are rejected:
 *   (\w+)+            nested quantifier on captured group
 *   (a*)*             nested quantifier
 *   (?:[a-z]+|[0-9]+)+  non-capturing group, alternation with inner quantifiers
 *   (\w{2,})+         unbounded {n,} inside a quantified group
 *
 * Returns a human-readable reason string when risk is detected, null otherwise.
 */
export function detectRedos(pattern: string): string | null {
  // Collect [start, end] spans for every group '(...)' in the pattern.
  const groups: Array<{ start: number; end: number }> = [];
  const stack: number[] = [];

  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === '\\') { i += 2; continue; }
    if (ch === '[') {
      // skip character class
      i++;
      while (i < pattern.length) {
        if (pattern[i] === '\\') { i += 2; }
        else if (pattern[i] === ']') { i++; break; }
        else { i++; }
      }
      continue;
    }
    if (ch === '(') { stack.push(i); }
    else if (ch === ')') {
      if (stack.length > 0) groups.push({ start: stack.pop()!, end: i });
    }
    i++;
  }

  for (const { start, end } of groups) {
    // Check character immediately after ')' for a repeating quantifier.
    const after = pattern[end + 1];
    if (!after) continue;

    let isRepeating = false;
    if (after === '+' || after === '*') {
      isRepeating = true;
    } else if (after === '{') {
      const close = pattern.indexOf('}', end + 2);
      if (close !== -1) isRepeating = true; // any {n}, {n,}, {n,m}
    }
    if (!isRepeating) continue;

    const body = pattern.slice(start + 1, end);

    // Determine the effective body to inspect, stripping group-type prefixes.
    let effectiveBody: string;
    if (/^\?[=!]/.test(body) || /^\?<[=!]/.test(body)) {
      // Lookahead / lookbehind — zero-width, cannot backtrack in the same way.
      continue;
    } else if (body.startsWith('?:')) {
      effectiveBody = body.slice(2); // non-capturing (?:...)
    } else if (/^\?<[^=!]/.test(body)) {
      // Named capture (?<name>...) — strip up to closing '>'
      const nameEnd = body.indexOf('>');
      effectiveBody = nameEnd !== -1 ? body.slice(nameEnd + 1) : body;
    } else if (body.startsWith('?')) {
      // Other special group forms — skip conservatively.
      continue;
    } else {
      effectiveBody = body;
    }

    if (bodyContainsQuantifier(effectiveBody)) {
      const snippet = effectiveBody.slice(0, 40);
      return (
        `nested quantifier or alternation at position ${start}: ` +
        `group body "${snippet}${effectiveBody.length > 40 ? '…' : ''}" ` +
        `contains a repeating quantifier or alternation and is itself repeated — ` +
        `this pattern can cause catastrophic backtracking`
      );
    }
  }

  return null;
}

// ---------------------------------------------------------------------------

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

    // Pre-compile validation: reject patterns that can cause catastrophic backtracking.
    const redosReason = detectRedos(r.pattern);
    if (redosReason) {
      findings.push({
        scanner: CUSTOM_RULES_SCANNER_NAME,
        severity: 'info',
        rule: r.id,
        title: `[Custom] Unsafe regex in rule "${r.id}" (ReDoS risk)`,
        message: `Rule "${r.id}" was skipped: ${redosReason}`,
        description: `Rule "${r.id}" was skipped: ${redosReason}`,
        evidence: r.pattern,
      });
      return { rule: r, re };
    }

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
