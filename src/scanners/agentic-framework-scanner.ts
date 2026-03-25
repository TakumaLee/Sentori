import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScanResult, Finding, Severity, ScannerOptions } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';

/**
 * AgenticFrameworkScanner
 *
 * Detects security issues in agentic AI framework configurations:
 * - LangChain: LANGCHAIN_API_KEY in .env files, langchain.json config
 * - AutoGen:   api_key plaintext in autogen config JSON/YAML/Python
 * - CrewAI:    tool API keys in crew config files
 * - Generic:   hardcoded API keys in .py/.ts/.js code (common in agentic frameworks)
 */

interface Rule {
  id: string;
  severity: Severity;
  check(file: FileEntry): Finding[];
}

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split('\n').length;
}

function isPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  const placeholders = [
    'your_', 'xxx', 'placeholder', '<your', 'example',
    'change_me', 'todo', 'fixme', 'replace', 'insert_',
    '${', 'process.env', 'os.environ', 'env.',
    'dummy', 'sample', 'mock', 'fake', 'default',
    'changeme', 'fill_in', 'put_your',
    '<insert', '<api', '<token', '<key', '<secret',
    '...', 'n/a', 'none', 'null', 'undefined', 'secret_here',
    'sk-xxxx', 'lc-xxxx', 'crewai-xxxx',
  ];
  return placeholders.some(p => lower.includes(p));
}

// ---------------------------------------------------------------------------
// LangChain rules
// ---------------------------------------------------------------------------

const langchainEnvKeyRule: Rule = {
  id: 'AGENTIC-001',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    const isEnvFile = /\.env(\.[a-z]+)?$/i.test(file.relativePath);
    const isEnvExample = /\.env\.(example|sample|template|dist)$/i.test(file.relativePath);
    if (!isEnvFile) return findings;

    const lines = file.content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(/^\s*LANGCHAIN_API_KEY\s*=\s*(.+)/i);
      if (!match) continue;
      const value = match[1].trim().replace(/^["']|["']$/g, '');
      if (isPlaceholder(value)) continue;

      const severity: Severity = isEnvExample ? 'info' : 'critical';
      findings.push({
        scanner: 'AgenticFrameworkScanner',
        rule: 'AGENTIC-001',
        severity,
        file: file.relativePath,
        line: i + 1,
        message: 'LangChain API key found in .env file',
        evidence: line.trim().replace(/(LANGCHAIN_API_KEY\s*=\s*)(.{4}).+/, '$1$2****'),
        recommendation: isEnvExample
          ? 'This appears to be an example file. Ensure the real .env is in .gitignore.'
          : 'Move LANGCHAIN_API_KEY out of .env files committed to version control. Use a secrets manager or CI/CD environment variables.',
      });
    }
    return findings;
  },
};

const langchainJsonConfigRule: Rule = {
  id: 'AGENTIC-002',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    // Target: langchain.json, langchain_config.json, .langchain/*.json
    const isLangchainConfig =
      /langchain[_-]?config\.json$/i.test(file.relativePath) ||
      /langchain\.json$/i.test(file.relativePath) ||
      /\.langchain[/\\].+\.json$/i.test(file.relativePath);
    if (!isLangchainConfig) return findings;

    let parsed: unknown;
    try {
      parsed = JSON.parse(file.content);
    } catch {
      return findings;
    }

    // Walk the JSON for key-like fields
    const apiKeyFields = ['api_key', 'apiKey', 'langchain_api_key', 'openai_api_key', 'anthropic_api_key'];
    const flagged = extractFieldValues(parsed, apiKeyFields);
    for (const { key, value, path: fieldPath } of flagged) {
      if (isPlaceholder(value)) continue;
      findings.push({
        scanner: 'AgenticFrameworkScanner',
        rule: 'AGENTIC-002',
        severity: 'high',
        file: file.relativePath,
        message: `LangChain config contains plaintext API key: ${key}`,
        evidence: `${fieldPath}: "${value.substring(0, 4)}****"`,
        recommendation: 'Do not store API keys in langchain config JSON files. Use environment variables or a secrets manager.',
      });
    }
    return findings;
  },
};

// ---------------------------------------------------------------------------
// AutoGen rules
// ---------------------------------------------------------------------------

const autogenApiKeyRule: Rule = {
  id: 'AGENTIC-003',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];

    const isAutogenConfig =
      /autogen[_-]?config\.(json|ya?ml)$/i.test(file.relativePath) ||
      /OAI_CONFIG_LIST/i.test(file.relativePath) ||
      /\.autogen[/\\].+\.(json|ya?ml)$/i.test(file.relativePath);

    const isAutogenPython =
      /\.(py)$/i.test(file.relativePath) &&
      /autogen|pyautogen/i.test(file.content);

    if (!isAutogenConfig && !isAutogenPython) return findings;

    if (isAutogenConfig) {
      // JSON config: look for api_key fields
      if (file.relativePath.endsWith('.json')) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(file.content);
        } catch {
          return findings;
        }
        const apiKeyFields = ['api_key', 'apiKey', 'openai_api_key'];
        for (const { key, value, path: fieldPath } of extractFieldValues(parsed, apiKeyFields)) {
          if (isPlaceholder(value)) continue;
          findings.push({
            scanner: 'AgenticFrameworkScanner',
            rule: 'AGENTIC-003',
            severity: 'critical',
            file: file.relativePath,
            message: `AutoGen config contains plaintext API key: ${key}`,
            evidence: `${fieldPath}: "${value.substring(0, 4)}****"`,
            recommendation: 'Remove plaintext API keys from AutoGen config files. Use environment variable references (e.g. "api_key": "${OPENAI_API_KEY}") or a secrets manager.',
          });
        }
      }
      // YAML config
      if (/\.ya?ml$/i.test(file.relativePath)) {
        const lines = file.content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const match = lines[i].match(/^\s*api_key\s*:\s*(.+)/i);
          if (!match) continue;
          const value = match[1].trim().replace(/^["']|["']$/g, '');
          if (isPlaceholder(value)) continue;
          findings.push({
            scanner: 'AgenticFrameworkScanner',
            rule: 'AGENTIC-003',
            severity: 'critical',
            file: file.relativePath,
            line: i + 1,
            message: 'AutoGen YAML config contains plaintext api_key',
            evidence: lines[i].trim().replace(/(api_key\s*:\s*)(.{4}).+/, '$1$2****'),
            recommendation: 'Remove plaintext API keys from AutoGen YAML configs. Use environment variable references instead.',
          });
        }
      }
    }

    if (isAutogenPython) {
      // Python: config_list = [{"api_key": "sk-..."}]
      const pattern = /["']api_key["']\s*:\s*["']([^"']{8,})["']/gi;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(file.content)) !== null) {
        const value = match[1];
        if (isPlaceholder(value)) continue;
        findings.push({
          scanner: 'AgenticFrameworkScanner',
          rule: 'AGENTIC-003',
          severity: 'critical',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: 'AutoGen Python config contains hardcoded api_key',
          evidence: match[0].replace(/(["']api_key["']\s*:\s*["'])(.{4}).+/, '$1$2****"'),
          recommendation: 'Use os.environ.get("OPENAI_API_KEY") or a config file outside the repository instead of hardcoded API keys.',
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// CrewAI rules
// ---------------------------------------------------------------------------

const crewaiToolKeyRule: Rule = {
  id: 'AGENTIC-004',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];

    const isCrewConfig =
      /crew[_-]?config\.(json|ya?ml|toml)$/i.test(file.relativePath) ||
      /\.crew[/\\].+\.(json|ya?ml|toml)$/i.test(file.relativePath) ||
      /agents?\.ya?ml$/i.test(file.relativePath) ||
      /tasks?\.ya?ml$/i.test(file.relativePath);

    const isCrewPython =
      /\.(py)$/i.test(file.relativePath) &&
      /crewai|CrewBase|@crew|@agent|@task/i.test(file.content);

    if (!isCrewConfig && !isCrewPython) return findings;

    const keyFieldPatterns = [
      /tool[_-]?api[_-]?key/i,
      /serper[_-]?api[_-]?key/i,
      /browserless[_-]?api[_-]?key/i,
      /exa[_-]?api[_-]?key/i,
      /api[_-]?key/i,
    ];

    if (isCrewConfig) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pat of keyFieldPatterns) {
          const m = line.match(new RegExp(`(${pat.source})\\s*[=:]\\s*["']?([^"'\\s,}]{8,})["']?`, 'i'));
          if (!m) continue;
          const value = m[2];
          if (isPlaceholder(value)) continue;
          findings.push({
            scanner: 'AgenticFrameworkScanner',
            rule: 'AGENTIC-004',
            severity: 'high',
            file: file.relativePath,
            line: i + 1,
            message: `CrewAI config contains plaintext tool API key: ${m[1]}`,
            evidence: line.trim().replace(/(key\s*[=:]\s*["']?)(.{4}).+/, '$1$2****'),
            recommendation: 'Store CrewAI tool API keys in environment variables. Reference them via os.environ.get() or .env files excluded from version control.',
          });
        }
      }
    }

    if (isCrewPython) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const pat of keyFieldPatterns) {
          const m = lines[i].match(new RegExp(`(${pat.source})\\s*=\\s*["']([^"']{8,})["']`, 'i'));
          if (!m) continue;
          const value = m[2];
          if (isPlaceholder(value)) continue;
          findings.push({
            scanner: 'AgenticFrameworkScanner',
            rule: 'AGENTIC-004',
            severity: 'high',
            file: file.relativePath,
            line: i + 1,
            message: `CrewAI Python file contains hardcoded tool API key: ${m[1]}`,
            evidence: lines[i].trim().replace(/(key\s*=\s*["'])(.{4}).+/, '$1$2****'),
            recommendation: 'Use os.environ.get() to load API keys from environment variables instead of hardcoding them.',
          });
        }
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Generic agentic hardcoded API key rule (.py / .ts / .js)
// ---------------------------------------------------------------------------

const AGENTIC_IMPORT_PATTERNS = [
  /from\s+langchain/i,
  /import\s+langchain/i,
  /from\s+autogen/i,
  /import\s+autogen/i,
  /from\s+crewai/i,
  /import\s+crewai/i,
  /from\s+openai/i,
  /import\s+openai/i,
  /from\s+anthropic/i,
  /import\s+anthropic/i,
  /require\s*\(['"]openai['"]\)/i,
  /require\s*\(['"]anthropic['"]\)/i,
  /require\s*\(['"]@langchain/i,
];

const HARDCODED_KEY_PATTERNS = [
  { pattern: /(?:openai|OPENAI)[_-]?api[_-]?key\s*[=:]\s*["']([^"']{20,})["']/gi, desc: 'OpenAI API key' },
  { pattern: /(?:anthropic|ANTHROPIC)[_-]?api[_-]?key\s*[=:]\s*["']([^"']{20,})["']/gi, desc: 'Anthropic API key' },
  { pattern: /(?:langchain|LANGCHAIN)[_-]?api[_-]?key\s*[=:]\s*["']([^"']{20,})["']/gi, desc: 'LangChain API key' },
  { pattern: /new\s+OpenAI\s*\(\s*\{[^}]*api_key\s*:\s*["']([^"']{20,})["']/gi, desc: 'OpenAI client with hardcoded key' },
  { pattern: /new\s+Anthropic\s*\(\s*\{[^}]*api_key\s*:\s*["']([^"']{20,})["']/gi, desc: 'Anthropic client with hardcoded key' },
  { pattern: /ChatOpenAI\s*\([^)]*openai_api_key\s*=\s*["']([^"']{20,})["']/gi, desc: 'LangChain ChatOpenAI with hardcoded key' },
];

const genericHardcodedKeyRule: Rule = {
  id: 'AGENTIC-005',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];

    const isCode = /\.(py|ts|js|jsx|tsx)$/i.test(file.relativePath);
    if (!isCode) return findings;

    // Only flag files that use agentic framework imports OR have explicit key assignment patterns
    const hasAgenticImports = AGENTIC_IMPORT_PATTERNS.some(p => p.test(file.content));
    if (!hasAgenticImports) return findings;

    for (const { pattern, desc } of HARDCODED_KEY_PATTERNS) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(file.content)) !== null) {
        const keyValue = match[1] || '';
        if (isPlaceholder(keyValue) || isPlaceholder(match[0])) continue;

        findings.push({
          scanner: 'AgenticFrameworkScanner',
          rule: 'AGENTIC-005',
          severity: 'critical',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: `Hardcoded ${desc} detected in agentic framework code`,
          evidence: match[0].replace(/(['"]).{8,}(['"])/, '$1****$2'),
          recommendation: `Use environment variables (os.environ.get() / process.env) or a secrets manager instead of hardcoding ${desc}.`,
        });
      }
    }

    return findings;
  },
};

// ---------------------------------------------------------------------------
// Utility: extract field values from JSON
// ---------------------------------------------------------------------------

interface FieldMatch {
  key: string;
  value: string;
  path: string;
}

function extractFieldValues(
  obj: unknown,
  fields: string[],
  currentPath = '$',
): FieldMatch[] {
  const results: FieldMatch[] = [];
  if (typeof obj !== 'object' || obj === null) return results;

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      results.push(...extractFieldValues(obj[i], fields, `${currentPath}[${i}]`));
    }
  } else {
    const record = obj as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const childPath = `${currentPath}.${key}`;
      if (fields.includes(key) && typeof record[key] === 'string' && record[key] !== '') {
        results.push({ key, value: record[key] as string, path: childPath });
      } else {
        results.push(...extractFieldValues(record[key], fields, childPath));
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Scanner class
// ---------------------------------------------------------------------------

const rules: Rule[] = [
  langchainEnvKeyRule,
  langchainJsonConfigRule,
  autogenApiKeyRule,
  crewaiToolKeyRule,
  genericHardcodedKeyRule,
];

export class AgenticFrameworkScanner implements Scanner {
  name = 'AgenticFrameworkScanner';
  description =
    'Detects security issues in agentic AI framework configurations (LangChain, AutoGen, CrewAI) — API key leaks, plaintext credentials, and hardcoded secrets';

  async scan(targetDir: string, options?: ScannerOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let scannedFiles = 0;

    // Scan both config-type files and code files
    const extensions = new Set(['.py', '.ts', '.js', '.jsx', '.tsx', '.json', '.yaml', '.yml', '.toml', '.env']);
    const files = walkFiles(targetDir, {
      extensions,
      includeVendored: options?.includeVendored,
    });

    // Additionally walk for .env files which walkFiles might miss (no extension)
    const envFiles = findEnvFiles(targetDir);

    const allFiles = [...files];
    // Merge env files that aren't already in the list
    const existingPaths = new Set(files.map(f => f.path));
    for (const ef of envFiles) {
      if (!existingPaths.has(ef.path)) allFiles.push(ef);
    }

    for (const file of allFiles) {
      scannedFiles++;
      for (const rule of rules) {
        try {
          const ruleFindings = rule.check(file);
          findings.push(...ruleFindings);
        } catch {
          // Skip rule errors
        }
      }
    }

    return {
      scanner: this.name,
      findings,
      scannedFiles,
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Walk directory for .env files (dotfiles with no extension or .env.* variants).
 */
function findEnvFiles(dir: string): FileEntry[] {
  const results: FileEntry[] = [];
  const ENV_PATTERN = /^\.env(\.[a-z]+)?$/i;
  const skipDirs = new Set([
    'node_modules', '.git', 'dist', 'build', 'coverage',
    '__pycache__', '.venv', 'venv',
  ]);

  function walk(currentDir: string): void {
    if (!fs.existsSync(currentDir)) return;
    let items: fs.Dirent[];
    try {
      items = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const item of items) {
      const fullPath = path.join(currentDir, item.name);
      if (item.isDirectory()) {
        if (!skipDirs.has(item.name)) walk(fullPath);
      } else if (item.isFile() && ENV_PATTERN.test(item.name)) {
        try {
          const content = fs.readFileSync(fullPath, 'utf-8');
          results.push({
            path: fullPath,
            relativePath: path.relative(dir, fullPath),
            content,
          });
        } catch {
          // skip
        }
      }
    }
  }

  walk(dir);
  return results;
}

export default AgenticFrameworkScanner;
