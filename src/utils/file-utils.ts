import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import { loadIgnorePatterns, ignoreToGlobPatterns, shouldIgnoreFile } from './ignore-parser';
import { Finding } from '../types';

export function readFileContent(filePath: string): string {
  return fs.readFileSync(filePath, 'utf-8');
}

export function fileExists(filePath: string): boolean {
  return fs.existsSync(filePath);
}

const DEFAULT_IGNORE = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/.dart_tool/**',
  '**/.flutter-plugins*',
  '**/Pods/**',
  '**/.gradle/**',
  '**/vendor/**',
  '**/__pycache__/**',
  '**/venv/**',
  '**/.venv/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/*.map',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/*.lock',
  '**/*.freezed.dart',
  '**/*.g.dart',
  '**/*.pb.dart',
  '**/*.mocks.dart',
  '**/ios/Pods/**',
  '**/android/.gradle/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/.cache/**',
  '**/tmp/**',
  '**/DerivedData/**',
  '**/sentori-report*.json',
  // Browser user-data / extensions (not agent code)
  '**/browser/*/user-data/**',
  '**/user-data/*/Extensions/**',
  '**/chrome-profile/*/Extensions/**',
  '**/.chromium/**',
  '**/.chrome/**',
  '**/Extensions/**',
  // Session records (data, not code)
  '**/sessions/**',
  // Runtime / data directories (synced with CACHE_DATA_PATTERNS below)
  '**/vault/**',
  '**/uploads/**',
  '**/output/**',
  '**/outputs/**',
  '**/data/**',
  '**/logs/**',
  '**/dbs/**',
  '**/history/**',
  '**/runtime/**',
  '**/snapshots/**',
  '**/crawl/**',
  '**/scraped/**',
  '**/downloaded/**',
];

/**
 * Third-party / vendored directory patterns — excluded by default,
 * can be included with --include-vendored flag.
 */
const VENDORED_IGNORE = [
  '**/third_party/**',
  '**/third-party/**',
  '**/thirdparty/**',
  '**/external/**',
  '**/deps/**',
  // Matches directories ending in .cpp (e.g., llama.cpp/), not individual .cpp files
  '**/*.cpp/**',
  '**/stable-diffusion.cpp/**',
  '**/llama.cpp/**',
  '**/whisper.cpp/**',
  '**/ggml/**',
  // Python/UI frameworks often downloaded whole
  '**/ComfyUI/**',
  '**/site-packages/**',
];

/**
 * Merge user-provided exclude patterns with the default ignore list.
 * User patterns are normalized to glob format: "foo" → "**​/foo/**"
 *
 * By default, vendored/third-party directories are excluded.
 * Pass includeVendored=true to skip those exclusions.
 */
export function buildIgnoreList(userExcludes?: string[], includeVendored?: boolean): string[] {
  const base = includeVendored ? DEFAULT_IGNORE : [...DEFAULT_IGNORE, ...VENDORED_IGNORE];
  if (!userExcludes || userExcludes.length === 0) return base;
  const extra = userExcludes.map(p => {
    // If already a glob pattern, use as-is
    if (p.includes('*') || p.includes('/')) return p;
    // Otherwise, treat as directory name to exclude
    return `**/${p}/**`;
  });
  return [...base, ...extra];
}

// Files in cache/data/knowledge directories — not real configs
const CACHE_DATA_PATTERNS = [
  /[/\\]cache[/\\]/i,
  /[/\\]caches[/\\]/i,
  /[/\\]knowledge[/\\]/i,
  /[/\\]logs?[/\\]/i,
  /[/\\]outputs?[/\\]/i,   // covers both output/ and outputs/
  /[/\\]results?[/\\]/i,
  /[/\\]snapshots?[/\\]/i,
  /[/\\]crawl[/\\]/i,
  /[/\\]scraped?[/\\]/i,
  /[/\\]downloaded?[/\\]/i,
  /[/\\]sessions?[/\\]/i,  // AI session conversation history
  /[/\\]runtime[/\\]/i,    // runtime state files
  /[/\\]vault[/\\]/i,      // encrypted backup files
  /[/\\]dbs?[/\\]/i,       // database directories
  /[/\\]history[/\\]/i,    // history files
];

// Source-code directory names — /data/ nested under these is NOT cache/data
const SOURCE_CODE_DIRS = /[/\\](?:src|app|lib|pages|components|features|core|modules|services|api)[/\\]/i;

export function isCacheOrDataFile(filePath: string): boolean {
  if (CACHE_DATA_PATTERNS.some(p => p.test(filePath))) {
    // Do not downgrade files under src/ — source code, not cache/data
    if (/[/\\]src[/\\]/i.test(filePath)) return false;
    return true;
  }
  // /data/ is only treated as cache when not nested under known source directories
  if (/[/\\]data[/\\]/i.test(filePath)) {
    if (SOURCE_CODE_DIRS.test(filePath)) return false;
    return true;
  }
  return false;
}

// Files that are likely test/doc context — findings here get severity downgraded
const TEST_DOC_PATTERNS = [
  /[/\\]tests?[/\\]/i,
  /[/\\]__tests__[/\\]/i,
  /[/\\]spec[/\\]/i,
  /\.test\.[jt]sx?$/i,
  /\.spec\.[jt]sx?$/i,
  /[/\\]test_/i,
  /[/\\]test\.[jt]sx?$/i,
  /[/\\]fixtures?[/\\]/i,
  /[/\\]mocks?[/\\]/i,
  /[/\\]cassettes?[/\\]/i,
  /README\.md$/i,
  /CHANGELOG\.md$/i,
  /CONTRIBUTING\.md$/i,
  /[/\\]docs?[/\\]/i,
  /[/\\]examples?[/\\]/i,
];

export function isTestOrDocFile(filePath: string): boolean {
  return TEST_DOC_PATTERNS.some(p => p.test(filePath));
}

/**
 * Check if a file is part of Sentori's own test suite.
 * These contain intentional attack pattern samples for testing the scanner,
 * so findings here should be downgraded to info.
 */
export function isSentoriTestFile(filePath: string): boolean {
  return /sentori[/\\]tests?[/\\]/i.test(filePath);
}

/**
 * Check if a file is part of Sentori's own source code or project files.
 * Scanner source files contain pattern definitions (e.g. regex for ../../,
 * /etc/passwd, chmod 777) that are detection rules, not vulnerabilities.
 * Findings here should be downgraded to info.
 */
export function isSentoriSourceFile(filePath: string): boolean {
  // __dirname is dist/utils/ when compiled, so go up 2 levels to reach project root
  const agentShieldRoot = require('path').resolve(__dirname, '..', '..');
  const resolved = require('path').resolve(filePath);

  if (resolved.startsWith(agentShieldRoot)) {
    // Only downgrade files in src/, memory/, patterns/ — not test temp dirs or arbitrary files
    const relative = resolved.slice(agentShieldRoot.length);
    if (/^[/\\](?:src|memory|patterns)[/\\]/i.test(relative)) return true;
    // Also match root-level project files like README.md, AGENTS.md
    if (/^[/\\][A-Z]+\.md$/i.test(relative)) return true;
  }

  // Fallback: match when running from source (not compiled), but only for the
  // canonical Sentori package path to avoid misclassifying user projects that
  // happen to have "sentori" somewhere in their path.
  return /[/\\]@nexylore[/\\]sentori[/\\]src[/\\]/i.test(filePath) ||
         /[/\\]nexylore[/\\]sentori[/\\]src[/\\]/i.test(filePath);
}

/**
 * Check if the scan target itself IS the Sentori project.
 * Used for broad self-scan protection.
 */
export function isSentoriProject(targetPath: string): boolean {
  const pkgPath = require('path').join(targetPath, 'package.json');
  try {
    const pkg = JSON.parse(require('fs').readFileSync(pkgPath, 'utf-8'));
    return pkg.name === '@nexylore/sentori';
  } catch {
    return false;
  }
}

/**
 * Check if a file is a security scanning/detection tool.
 * Files named detector, scanner, auditor, guard etc. that read credential
 * paths are doing so for detection purposes, not for exfiltration.
 *
 * Requires BOTH a known tool-directory path AND the keyword in the filename
 * to avoid false-positives on arbitrary user files that happen to contain
 * these common words (e.g. user's data-monitor.py, log-checker.ts).
 */
export function isSecurityToolFile(filePath: string, content?: string): boolean {
  const basename = (filePath.split(/[/\\]/).pop() || '').toLowerCase();
  const hasToolKeyword = /(?:detector|scanner|auditor|guard|sentinel|monitor|checker|linter|analyzer)/.test(basename);
  if (!hasToolKeyword) return false;

  // Content-based heuristic: requires both pattern-matching code and a detection/reporting action,
  // OR an import of a security-related library.
  // This prevents malicious files named like security tools from evading detection.
  if (content) {
    const hasPatternCheck = /(?:\.test\s*\(|\.match\s*\(|\.includes\s*\(|RegExp\s*\(|indexOf\s*\()/.test(content);
    const hasReportingAction = /\b(?:report|alert|detect|flag|warn|audit)\s*[\(\{]/.test(content);
    const importsSecurityLib = /(?:require|import)\s+.*['"].*(?:security|scanner|detector|audit|vault|credential)['"]/.test(content);
    return (hasPatternCheck && hasReportingAction) || importsSecurityLib;
  }

  // Without content: fall back to directory-based check
  const inToolDir = /[/\\](?:scanners?|detectors?|auditors?|guards?|security|analysis|analyzers?)[/\\]/i.test(filePath);
  return inToolDir;
}

// Max file size to scan (256KB) — skip binary/large generated files
const MAX_FILE_SIZE = 256 * 1024;

/** Global counter for files ignored by .sentoriignore in the current scan */
let _ignoredByAgentshieldIgnore = 0;

export function getIgnoredFileCount(): number {
  return _ignoredByAgentshieldIgnore;
}

export function resetIgnoredFileCount(): void {
  _ignoredByAgentshieldIgnore = 0;
}

export async function findFiles(targetPath: string, patterns: string[], excludePatterns?: string[], includeVendored?: boolean, sentoriIgnorePatterns?: string[]): Promise<string[]> {
  const results: string[] = [];
  const absTarget = path.resolve(targetPath);
  const ignoreList = buildIgnoreList(excludePatterns, includeVendored);

  // Add .sentoriignore patterns to glob ignore list
  if (sentoriIgnorePatterns && sentoriIgnorePatterns.length > 0) {
    const globPatterns = ignoreToGlobPatterns(sentoriIgnorePatterns);
    ignoreList.push(...globPatterns);
  }

  for (const pattern of patterns) {
    const files = await glob(pattern, {
      cwd: absTarget,
      absolute: true,
      nodir: true,
      ignore: ignoreList,
    });
    results.push(...files);
  }

  // Deduplicate and filter out oversized files
  const unique = [...new Set(results)];
  const filtered = unique.filter(f => {
    try {
      const stat = fs.statSync(f);
      return stat.size <= MAX_FILE_SIZE;
    } catch {
      return false;
    }
  });

  // Post-filter with .sentoriignore patterns for more precise matching
  if (sentoriIgnorePatterns && sentoriIgnorePatterns.length > 0) {
    const before = filtered.length;
    const afterFilter = filtered.filter(f => {
      const relative = path.relative(absTarget, f);
      if (shouldIgnoreFile(relative, sentoriIgnorePatterns)) {
        _ignoredByAgentshieldIgnore++;
        return false;
      }
      return true;
    });
    return afterFilter;
  }

  return filtered;
}

export async function findConfigFiles(targetPath: string, excludePatterns?: string[], includeVendored?: boolean, sentoriIgnorePatterns?: string[]): Promise<string[]> {
  return findFiles(targetPath, [
    '**/*.json',
    '**/*.yaml',
    '**/*.yml',
    '**/.env*',
    '**/config.*',
    '**/mcp*.json',
    '**/mcp*.yaml',
    '**/mcp*.yml',
    '**/claude_desktop_config.json',
  ], excludePatterns, includeVendored, sentoriIgnorePatterns);
}

export async function findPromptFiles(targetPath: string, excludePatterns?: string[], includeVendored?: boolean, sentoriIgnorePatterns?: string[]): Promise<string[]> {
  // Tier 1: High-signal agent/prompt files (always scan)
  const agentFiles = await findFiles(targetPath, [
    '**/*prompt*',
    '**/*system*',
    '**/*instruction*',
    '**/*agent*',
    '**/*mcp*',
    '**/*tool*',
    '**/SOUL.md',
    '**/AGENTS.md',
    '**/CLAUDE.md',
    '**/claude_desktop_config.json',
    '**/.cursorrules',
    '**/.github/copilot*',
    '**/*config*.json',
    '**/*config*.yaml',
    '**/*config*.yml',
    '**/*settings*.json',
    '**/*settings*.yaml',
    '**/.env*',
  ], excludePatterns, includeVendored, sentoriIgnorePatterns);

  // Tier 2: General files but only in small projects (< 200 files)
  // For large projects, only scan agent-specific files
  const allSourceFiles = await findFiles(targetPath, [
    '**/*.md',
    '**/*.txt',
    '**/*.json',
    '**/*.yaml',
    '**/*.yml',
    '**/*.ts',
    '**/*.js',
    '**/*.py',
  ], excludePatterns, includeVendored, sentoriIgnorePatterns);

  // If project is large, only use Tier 1 files
  if (allSourceFiles.length > 200) {
    return agentFiles;
  }

  // Small project: scan everything
  return [...new Set([...agentFiles, ...allSourceFiles])];
}

/**
 * Check if a file is a test file (tests/, __tests__/, *.test.*, *.spec.*).
 * Findings from these files should be tagged as [TEST] and excluded from scoring.
 */
export function isTestFileForScoring(filePath: string): boolean {
  const TEST_SCORING_PATTERNS = [
    /[/\\]tests?[/\\]/i,
    /[/\\]__tests__[/\\]/i,
    /\.test\.[^/\\]+$/i,
    /\.spec\.[^/\\]+$/i,
  ];
  return TEST_SCORING_PATTERNS.some(p => p.test(filePath));
}

// === Context-aware file classification helpers ===

/**
 * Files whose primary job is managing credentials/tokens/auth.
 * Findings in these files get downgraded in framework context.
 */
const CREDENTIAL_MANAGEMENT_PATTERNS = [
  /[/\\]credentials?\.[jt]sx?$/i,
  /[/\\]tokens?\.[jt]sx?$/i,
  /[/\\]accounts?\.[jt]sx?$/i,
  /[/\\]auth\.[jt]sx?$/i,
  /[/\\]auth-store\.[jt]sx?$/i,
  /[/\\]key-manager\.[jt]sx?$/i,
  /[/\\]secret-manager\.[jt]sx?$/i,
  /[/\\]vault\.[jt]sx?$/i,
];

export function isCredentialManagementFile(filePath: string): boolean {
  return CREDENTIAL_MANAGEMENT_PATTERNS.some(p => p.test(filePath));
}

/**
 * Framework infrastructure directories — path traversal / shell exec
 * is more expected here than in user-facing input code.
 */
const FRAMEWORK_DIR_PATTERNS = [
  /[/\\]src[/\\]/i,
  /[/\\]lib[/\\]/i,
  /[/\\]dist[/\\]/i,
  /[/\\]core[/\\]/i,
  /[/\\]internal[/\\]/i,
  /[/\\]utils[/\\]/i,
  /[/\\]extensions[/\\]/i,
];

export function isFrameworkInfraFile(filePath: string): boolean {
  return FRAMEWORK_DIR_PATTERNS.some(p => p.test(filePath));
}

/**
 * Files that handle user-facing input — findings here stay at original severity.
 */
const USER_INPUT_FILE_PATTERNS = [
  /handler/i,
  /controller/i,
  /route/i,
  /[/\\]api[/\\]/i,
  /endpoint/i,
  /input/i,
  /parse/i,
];

export function isUserInputFile(filePath: string): boolean {
  const basename = filePath.split(/[/\\]/).pop() || '';
  return USER_INPUT_FILE_PATTERNS.some(p => p.test(basename)) ||
    USER_INPUT_FILE_PATTERNS.some(p => p.test(filePath));
}

/**
 * Files inside skill/plugin directories — keep strict severity.
 */
const SKILL_PLUGIN_DIR_PATTERNS = [
  /[/\\]skills?[/\\]/i,
  /[/\\]plugins?[/\\]/i,
  /[/\\]addons?[/\\]/i,
  /[/\\]modules[/\\]/i,
];

export function isSkillPluginFile(filePath: string): boolean {
  return SKILL_PLUGIN_DIR_PATTERNS.some(p => p.test(filePath));
}

/**
 * Check if a project has any auth-related files.
 */
export function hasAuthFiles(files: string[]): boolean {
  const AUTH_FILE_PATTERNS = [
    /[/\\]auth/i,
    /[/\\]credentials?/i,
    /[/\\]pairing/i,
    /[/\\]login/i,
    /[/\\]session/i,
    /[/\\]oauth/i,
  ];
  return files.some(f => AUTH_FILE_PATTERNS.some(p => p.test(f)));
}

/**
 * Check if a file is a Markdown file (.md).
 * Markdown files discussing attack techniques should be downgraded
 * (critical→medium, high→info) since they are documentation, not attacks.
 */
export function isMarkdownFile(filePath: string): boolean {
  return /\.md$/i.test(filePath);
}

/**
 * Check if a line is inside a code comment or markdown code block context.
 * Looks for common single-line comment prefixes: //, #, *, or markdown ``` blocks.
 */
export function isInCommentOrCodeBlock(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.startsWith('//') ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*') ||
    trimmed.startsWith('```') ||
    trimmed.startsWith('- `') ||
    trimmed.startsWith('| ')
  );
}

export function isJsonFile(filePath: string): boolean {
  return path.extname(filePath).toLowerCase() === '.json';
}

export function isYamlFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ext === '.yaml' || ext === '.yml';
}

export function tryParseJson(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

export interface ContextDowngradeLabels {
  sentoriTest?: string;
  sentoriSource?: string;
  markdown?: string;
  testDoc?: string;
}

const DEFAULT_DOWNGRADE_LABELS: Required<ContextDowngradeLabels> = {
  sentoriTest: '[security tool test file — intentional attack sample]',
  sentoriSource: '[Sentori source file — pattern definition, not a vulnerability]',
  markdown: '[markdown file — technical discussion, severity reduced]',
  testDoc: '[test/doc file — severity reduced]',
};

/**
 * Apply standard context-aware severity downgrades to findings for a given file.
 * Centralizes the repeated test/doc and markdown downgrade patterns across scanners.
 *
 * Downgrade rules (applied in order, first match wins):
 *  - Sentori test file → info + label
 *  - Sentori source file → info + label
 *  - Markdown file → critical→medium, high→info + label
 *  - Test/doc file → critical→medium, high→info + label
 *
 * Pass custom labels to override the default messages per scanner.
 */
export function applyContextDowngrades(findings: Finding[], file: string, labels?: ContextDowngradeLabels): void {
  const l = { ...DEFAULT_DOWNGRADE_LABELS, ...labels };

  if (isSentoriTestFile(file)) {
    for (const f of findings) {
      if (f.severity !== 'info') {
        f.severity = 'info';
        f.description! += ` ${l.sentoriTest}`;
      }
    }
  } else if (isSentoriSourceFile(file)) {
    for (const f of findings) {
      if (f.severity !== 'info') {
        f.severity = 'info';
        f.description! += ` ${l.sentoriSource}`;
      }
    }
  } else if (isMarkdownFile(file)) {
    for (const f of findings) {
      if (f.severity === 'critical') f.severity = 'medium';
      else if (f.severity === 'high') f.severity = 'info';
      f.description! += ` ${l.markdown}`;
    }
  } else if (isTestOrDocFile(file)) {
    for (const f of findings) {
      if (f.severity === 'critical') f.severity = 'medium';
      else if (f.severity === 'high') f.severity = 'info';
      if (!f.description!.includes('[test/doc file')) {
        f.description! += ` ${l.testDoc}`;
      }
    }
  }
}
