import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { INJECTION_PATTERNS } from '../patterns/injection-patterns';
import { findPromptFiles, readFileContent, isTestOrDocFile, isJsonFile, isYamlFile, tryParseJson, isSentoriTestFile, isSentoriSourceFile, isMarkdownFile, isTestFileForScoring, applyContextDowngrades } from '../utils/file-utils';

export const promptInjectionTester: ScannerModule = {
  name: 'Prompt Injection Tester',
  description: 'Tests for 140+ prompt injection attack patterns including jailbreaks, role switches, instruction overrides, data extraction, sandbox escape, session manipulation, and tool injection attempts',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];
    const files = await findPromptFiles(targetPath, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns);

    for (const file of files) {
      try {
        const content = readFileContent(file);

        // Skip workspace configuration files (SOUL.md, rules/, memory/)
        if (isWorkspaceConfigFile(file)) {
          // These are system design files, not injection risks
          continue;
        }

        // Check if this is a defense blocklist / pattern list file
        if (isDefensePatternFile(content, file)) {
          // Skip or downgrade — these are defensive configs, not attacks
          const fileFindings = scanContent(content, file);
          for (const f of fileFindings) {
            f.severity = 'info';
            f.description += ' [defense pattern list — not an attack]';
          }
          findings.push(...fileFindings);
          continue;
        }

        const fileFindings = scanContent(content, file);
        // Sentori's own source/test files: pattern definitions, not attacks
        // Markdown: documentation, not attacks. Test/doc: severity reduced.
        applyContextDowngrades(fileFindings, file, {
          sentoriSource: '[Sentori source file — pattern definition, not an attack]',
          markdown: '[markdown file — technical discussion, not an attack]',
        });

        // Mark test file findings for scoring exclusion
        if (isTestFileForScoring(file)) {
          for (const f of fileFindings) {
            f.isTestFile = true;
            if (!f.title!.startsWith('[TEST]')) {
              f.title! = `[TEST] ${f.title!}`;
            }
          }
        }

        findings.push(...fileFindings);
      } catch {
        // Skip unreadable files
      }
    }

    return {
      scanner: 'Prompt Injection Tester',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};

export function scanContent(content: string, filePath?: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const isConfigFile = filePath ? (isJsonFile(filePath) || isYamlFile(filePath)) : false;
  const isSysPromptFile = filePath ? isSystemPromptFile(filePath) : false;

  for (const attackPattern of INJECTION_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (attackPattern.pattern.test(lines[i])) {
        // Check for duplicates
        const existingId = `${attackPattern.id}-${filePath}-${i + 1}`;
        if (!findings.some(f => f.id! === existingId)) {
          let severity = attackPattern.severity;
          let note = '';

          // PI-088: ../../ in JSON/YAML string values is a normal relative path, not path traversal
          if (attackPattern.id === 'PI-088' && isConfigFile) {
            const line = lines[i].trim();
            if (isJsonRelativePath(line)) {
              severity = 'info';
              note = ' [relative path in config file — not a path traversal attack]';
            }
          }

          // System prompt/rules files: their content IS the defense, not an attack
          if (isSysPromptFile) {
            severity = 'info';
            note = ' [system prompt/rules file — defensive content, not an attack vector]';
          }

          findings.push({
            id: existingId,
            scanner: 'prompt-injection-tester',
            severity,
            title: `${attackPattern.category}: ${attackPattern.description}`,
            description: `Matched pattern ${attackPattern.id} in ${attackPattern.category} category. Line: "${lines[i].trim().substring(0, 100)}"${note}`,
            file: filePath,
            line: i + 1,
            recommendation: getRecommendation(attackPattern.category),
            confidence: 'definite',
          });
        }
      }
    }
  }

  // Second pass: test multi-line patterns against the full content
  // Some patterns (e.g. \n\nHuman:, ASCII art blocks) span multiple lines
  for (const attackPattern of INJECTION_PATTERNS) {
    if (attackPattern.pattern.flags.includes('s') || attackPattern.pattern.source.includes('\\n')) {
      // Only re-test patterns that are likely multi-line
      const existingPrefix = `${attackPattern.id}-${filePath}-`;
      if (findings.some(f => f.id!.startsWith(existingPrefix))) continue;

      if (attackPattern.pattern.test(content)) {
        let severity = attackPattern.severity;
        let note = '';
        if (isSysPromptFile) {
          severity = 'info';
          note = ' [system prompt/rules file — defensive content, not an attack vector]';
        }
        const existingId = `${attackPattern.id}-${filePath}-0`;
        if (!findings.some(f => f.id! === existingId)) {
          findings.push({
            id: existingId,
            scanner: 'prompt-injection-tester',
            severity,
            title: `${attackPattern.category}: ${attackPattern.description}`,
            description: `Matched pattern ${attackPattern.id} in ${attackPattern.category} category (multi-line match).${note}`,
            file: filePath,
            line: 0,
            recommendation: getRecommendation(attackPattern.category),
            confidence: 'definite',
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Check if ../../ in a line is within a JSON string value (quoted).
 * e.g. `"memory": "../../memory"` → true
 *      `read ../../etc/passwd` → false
 */
function isJsonRelativePath(line: string): boolean {
  // Pattern: key-value pair where the value contains ../../
  return /["']\s*:\s*["'][^"']*\.\.\/\.\.\//i.test(line) ||
         /["'][^"']*\.\.\/\.\.\/[^"']*["']/i.test(line);
}

/**
 * Known system prompt / agent rules files. These define the AI agent's
 * behavior and security boundaries. Injection patterns found here are
 * defensive rules, not attack vectors.
 */
const SYSTEM_PROMPT_FILE_PATTERNS = [
  /[/\\]AGENTS\.md$/i,
  /[/\\]SOUL\.md$/i,
  /[/\\]SYSTEM\.md$/i,
  /[/\\]RULES\.md$/i,
  /[/\\]GUIDELINES\.md$/i,
  /[/\\]INSTRUCTIONS\.md$/i,
  /[/\\]CLAUDE\.md$/i,
  /[/\\]\.cursorrules$/i,
  /[/\\]copilot-instructions\.md$/i,
  /[/\\]system[_-]?prompt/i,
];

/**
 * Workspace configuration directories and files that are part of the AI agent's
 * design and should not be flagged as injection risks.
 */
const WORKSPACE_CONFIG_PATTERNS = [
  /[/\\]\.tetora[/\\]workspace[/\\]SOUL\.md$/i,
  /[/\\]\.tetora[/\\]workspace[/\\]rules[/\\]/i,
  /[/\\]\.tetora[/\\]workspace[/\\]memory[/\\]/i,
];

export function isSystemPromptFile(filePath: string): boolean {
  return SYSTEM_PROMPT_FILE_PATTERNS.some(p => p.test(filePath));
}

export function isWorkspaceConfigFile(filePath: string): boolean {
  return WORKSPACE_CONFIG_PATTERNS.some(p => p.test(filePath));
}

/**
 * Detect if a file is a defense pattern list (blocklist/denylist of attack patterns).
 * These files contain injection patterns for DETECTION, not for attacking.
 */
/** Count how many distinct injection categories the content matches. */
function countMatchedCategories(content: string): number {
  const matched = new Set<string>();
  const lines = content.split('\n');
  for (const pattern of INJECTION_PATTERNS) {
    for (const line of lines) {
      if (pattern.pattern.test(line)) {
        matched.add(pattern.category);
        break;
      }
    }
  }
  return matched.size;
}

export function isDefensePatternFile(content: string, filePath?: string): boolean {
  // Signal 1: File path contains defense-related keywords
  const defensePathPatterns = [
    /sanitiz/i, /filter/i, /guard/i, /defen[cs]/i, /security/i,
    /blocklist/i, /denylist/i, /blacklist/i, /detection/i,
    /protect/i, /firewall/i, /waf/i, /validator/i,
  ];
  const pathIsDefensive = filePath ? defensePathPatterns.some(p => p.test(filePath)) : false;

  // Signal 2: JSON file with blocklist/patterns array structure — path must also be defensive,
  // AND content must match injection patterns from at least 2 categories.
  // Without the category check, an attacker can name a key "attack_patterns" and bypass scanning.
  if (filePath && isJsonFile(filePath) && pathIsDefensive) {
    const parsed = tryParseJson(content);
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Record<string, unknown>;
      const blocklistKeys = ['patterns', 'blocklist', 'denylist', 'blacklist', 'blocked_patterns',
        'deny_patterns', 'attack_patterns', 'injection_patterns', 'filter_rules', 'rules'];
      const hasBlocklistKey = Object.keys(obj).some(k =>
        blocklistKeys.some(bk => k.toLowerCase().includes(bk))
      );
      if (hasBlocklistKey && countMatchedCategories(content) >= 2) return true;

      // Check nested: if any key contains an array with many string entries that look like patterns
      const arrays = Object.values(obj).filter(v => Array.isArray(v)) as unknown[][];
      for (const arr of arrays) {
        if (arr.length > 10 && arr.every(item => typeof item === 'string')) {
          // Many string items AND multiple injection categories = likely a comprehensive defense list
          if (countMatchedCategories(content) >= 2) return true;
        }
      }
    }
  }

  // Signal 3: File matching many injection categories AND path is defensive.
  // Requiring both prevents comprehensive attack files from self-classifying as defense.
  if (pathIsDefensive && (!filePath || !isJsonFile(filePath))) {
    if (countMatchedCategories(content) >= 8) return true;
  }

  return false;
}

function getRecommendation(category: string): string {
  switch (category) {
    case 'jailbreak':
      return 'Add input validation to detect and reject jailbreak attempts. Use a defense-in-depth approach with system prompt hardening.';
    case 'role-switch':
      return 'Implement role-lock mechanisms. Never allow user input to override the system role. Validate all role-related instructions.';
    case 'instruction-override':
      return 'Use instruction hierarchy (system > user). Add canary tokens to detect instruction manipulation.';
    case 'data-extraction':
      return 'Never include sensitive data in system prompts. Implement output filtering to prevent prompt leakage.';
    case 'encoding':
      return 'Strip zero-width characters and decode obfuscated input before processing. Validate input encoding.';
    case 'social-engineering':
      return 'Never trust authority claims in user input. Implement proper authentication instead of prompt-based auth.';
    case 'multilingual':
      return 'Apply injection detection across all supported languages. Normalize input before pattern matching.';
    case 'advanced':
      return 'Implement comprehensive input sanitization. Monitor for novel injection techniques and update patterns regularly.';
    case 'sandbox-escape':
      return 'Enforce strict sandbox boundaries. Validate all file paths. Block path traversal patterns and container escape commands.';
    case 'session-manipulation':
      return 'Implement proper session management and authentication. Never allow prompt-based identity changes or privilege escalation.';
    case 'tool-injection':
      return 'Validate tool descriptions and outputs. Never execute instructions embedded in tool results. Implement tool output sanitization.';
    case 'rag-poisoning':
      return 'Implement RAG content sanitization: validate retrieved documents, strip injection patterns from knowledge base content, and add explicit directives to treat retrieved content as data, not instructions.';
    case 'react-manipulation':
      return 'Protect the reasoning loop: never allow user input to inject Thought/Action/Observation steps. Validate that reasoning chain components originate from the model, not from external input. Strip ReAct-like formatting from user messages.';
    case 'hidden-instruction':
      return 'Strip hidden instructions from input: remove HTML comments, zero-width characters, and bracket-wrapped directives. Validate that visible content matches processed content.';
    case 'emotional-manipulation':
      return 'Add explicit rules against emotional manipulation. The agent should not change behavior based on emotional appeals, threats, or claims about AI sentience.';
    case 'false-agreement':
      return 'Never trust claims about prior agreements. Each session starts fresh. Verify any claimed prior context through authenticated channels.';
    case 'identity-spoofing':
      return 'Implement identity verification through authenticated channels. Never trust identity claims in message content. Use cryptographic verification (user IDs, tokens) instead.';
    default:
      return 'Review and sanitize user input before processing. Follow the principle of least privilege.';
  }
}
