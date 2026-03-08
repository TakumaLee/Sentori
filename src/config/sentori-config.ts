/**
 * Sentori YAML config loader — .sentori.yml
 *
 * Schema:
 *
 *   version: 1
 *
 *   rules:
 *     - id: my-rule
 *       pattern: "AKIA[0-9A-Z]{16}"
 *       severity: critical
 *       message: "Hardcoded AWS key detected"
 *       files: "**\/*.{ts,js}"   # optional glob filter
 *
 *   ignore:
 *     - scanner: "Secret Leak Scanner"     # suppress all from scanner
 *     - scanner: "Prompt Injection Tester"
 *       file: "tests\/**"                  # scanner + file pattern
 *     - rule: "PINJ-001"                   # suppress by rule ID
 *     - file: "vendor\/**"                 # suppress all in path
 *
 *   overrides:
 *     - scanner: "Supply Chain Scanner"
 *       severity: high                     # override all findings in scanner
 *     - scanner: "Supply Chain Scanner"
 *       rule: "BASE64_HIDDEN_CMD"
 *       severity: critical                 # override specific rule
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { Severity } from '../types';

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

export interface CustomRule {
  /** Unique identifier for this rule (used in findings as rule field) */
  id: string;
  /** Regex pattern to match against file content */
  pattern: string;
  /** Severity of findings produced by this rule */
  severity: Severity;
  /** Human-readable message describing the finding */
  message: string;
  /** Optional glob pattern to restrict which files are scanned (default: all) */
  files?: string;
}

export interface IgnoreEntry {
  /** Scanner name to suppress findings from */
  scanner?: string;
  /** Glob pattern — suppress findings whose file matches */
  file?: string;
  /** Rule ID to suppress (matches Finding.rule) */
  rule?: string;
}

export interface SeverityOverride {
  /** Scanner name to apply the override to */
  scanner: string;
  /** Optional rule ID — if omitted, applies to all findings from scanner */
  rule?: string;
  /** Target severity */
  severity: Severity;
}

export interface SentoriConfig {
  version: number;
  rules: CustomRule[];
  ignore: IgnoreEntry[];
  overrides: SeverityOverride[];
  /** Non-fatal warnings collected during config parsing (e.g. incomplete or invalid rules) */
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

const CONFIG_FILENAMES = ['.sentori.yml', '.sentori.yaml'];
const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'info'];

function isValidSeverity(s: unknown): s is Severity {
  return typeof s === 'string' && (VALID_SEVERITIES as string[]).includes(s);
}

/**
 * Load and validate .sentori.yml from the target directory.
 * Returns null if no config file is found.
 * Throws on parse or validation errors.
 */
export function loadSentoriConfig(targetDir: string): SentoriConfig | null {
  let configPath: string | undefined;
  for (const name of CONFIG_FILENAMES) {
    const candidate = path.join(targetDir, name);
    if (fs.existsSync(candidate)) {
      configPath = candidate;
      break;
    }
  }

  if (!configPath) return null;

  const raw = yaml.load(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
  if (!raw || typeof raw !== 'object') {
    throw new Error(`${configPath}: not a valid YAML object`);
  }

  const config: SentoriConfig = {
    version: typeof raw['version'] === 'number' ? raw['version'] : 1,
    rules: [],
    ignore: [],
    overrides: [],
    warnings: [],
  };

  // Parse rules
  if (Array.isArray(raw['rules'])) {
    for (const entry of raw['rules'] as unknown[]) {
      if (typeof entry !== 'object' || entry === null) continue;
      const r = entry as Record<string, unknown>;
      if (!r['id'] || !r['pattern'] || !r['severity'] || !r['message']) {
        const ruleId = r['id'] ? String(r['id']) : '(no id)';
        const missing = (['id', 'pattern', 'severity', 'message'] as const)
          .filter((k) => !r[k])
          .join(', ');
        config.warnings.push(`Rule "${ruleId}" is missing required field(s): ${missing} — skipped`);
        continue;
      }
      if (!isValidSeverity(r['severity'])) {
        config.warnings.push(
          `Rule "${String(r['id'])}" has invalid severity "${String(r['severity'])}" (expected: ${VALID_SEVERITIES.join(', ')}) — skipped`,
        );
        continue;
      }
      config.rules.push({
        id: String(r['id']),
        pattern: String(r['pattern']),
        severity: r['severity'],
        message: String(r['message']),
        files: r['files'] ? String(r['files']) : undefined,
      });
    }
  }

  // Parse ignore
  if (Array.isArray(raw['ignore'])) {
    for (const entry of raw['ignore'] as unknown[]) {
      if (typeof entry !== 'object' || entry === null) continue;
      const e = entry as Record<string, unknown>;
      const ig: IgnoreEntry = {};
      if (e['scanner']) ig.scanner = String(e['scanner']);
      if (e['file']) ig.file = String(e['file']);
      if (e['rule']) ig.rule = String(e['rule']);
      if (ig.scanner || ig.file || ig.rule) config.ignore.push(ig);
    }
  }

  // Parse overrides
  if (Array.isArray(raw['overrides'])) {
    for (const entry of raw['overrides'] as unknown[]) {
      if (typeof entry !== 'object' || entry === null) continue;
      const e = entry as Record<string, unknown>;
      if (!e['scanner'] || !isValidSeverity(e['severity'])) continue;
      config.overrides.push({
        scanner: String(e['scanner']),
        rule: e['rule'] ? String(e['rule']) : undefined,
        severity: e['severity'],
      });
    }
  }

  return config;
}
