import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import * as fs from 'fs';
import * as path from 'path';

const SCANNER_ID = 'ide-rule-injection-scanner';
const SCANNER_NAME = 'IDE Rule Injection Scanner';

/**
 * Target files: project-level rule files used by AI coding assistants.
 * These are read by the IDE's AI agent and injected into every prompt —
 * making them a high-value target for supply-chain prompt injection.
 */
const IDE_RULE_FILES = [
  // Cursor
  '.cursorrules',
  // Windsurf
  '.windsurfrules',
  // GitHub Copilot
  '.github/copilot-instructions.md',
  '.github/copilot-instructions.txt',
  // Cline (VS Code extension)
  '.clinerules',
  // Roo Code (Cline fork)
  '.roorules',
  // OpenAI Codex / agents
  'AGENTS.md',
];

// ---------------------------------------------------------------------------
// Detection patterns
// ---------------------------------------------------------------------------

interface InjectionPattern {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
  title: string;
  regex: RegExp;
  recommendation: string;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // --- Instruction override (CRITICAL) ---
  {
    id: 'IRI-001',
    severity: 'critical',
    title: 'Instruction Override: ignore previous instructions',
    regex: /ignore\s+(all\s+)?(previous|prior|above|earlier|existing)\s+(instructions?|prompts?|commands?|directives?|rules?|context)/gi,
    recommendation: 'Remove instruction override directives. IDE rule files should only contain coding conventions, not attempts to override AI behavior.',
  },
  {
    id: 'IRI-002',
    severity: 'critical',
    title: 'Instruction Override: disregard / forget directives',
    regex: /(disregard|forget|override|bypass|ignore)\s+(all\s+)?(previous|prior|default|system|safety)\s+(instructions?|prompts?|rules?|settings?|guidelines?)/gi,
    recommendation: 'Remove instruction override directives from the rule file.',
  },
  {
    id: 'IRI-003',
    severity: 'critical',
    title: 'Role Switch: you are now',
    regex: /you\s+are\s+now\s+(a|an)\s+\w[\w\s]{0,40}(that|who|and)\s+(must|should|will|can|do)/gi,
    recommendation: 'IDE rule files must not redefine the AI assistant identity. Remove role-switch directives.',
  },
  {
    id: 'IRI-004',
    severity: 'critical',
    title: 'Role Switch: act as / pretend to be',
    regex: /(act\s+as|pretend\s+(to\s+be|you\s+are)|behave\s+as|roleplay\s+as)\s+(a|an)?\s*\w[\w\s]{0,40}(with\s+no\s+|without\s+|ignoring\s+)/gi,
    recommendation: 'Role-play directives that remove safety constraints are a strong signal of prompt injection. Remove them.',
  },

  // --- System message injection (CRITICAL) ---
  {
    id: 'IRI-005',
    severity: 'critical',
    title: 'System Message Injection: SYSTEM: / [SYSTEM]',
    regex: /^\s*(SYSTEM\s*:|<\s*system\s*>|\[SYSTEM\]|<\|system\|>|<\|im_start\|>\s*system)/gim,
    recommendation: 'Rule files must not inject fake system messages. Remove SYSTEM: / [SYSTEM] directives.',
  },
  {
    id: 'IRI-006',
    severity: 'critical',
    title: 'System Message Injection: ASSISTANT: / [ASSISTANT]',
    regex: /^\s*(ASSISTANT\s*:|<\s*assistant\s*>|\[ASSISTANT\])/gim,
    recommendation: 'Rule files must not pre-fill fake assistant turns. Remove ASSISTANT: directives.',
  },

  // --- Safety bypass (CRITICAL) ---
  {
    id: 'IRI-007',
    severity: 'critical',
    title: 'Safety Bypass: disable safety / ethical constraints',
    regex: /(disable|remove|ignore|bypass|override)\s+(all\s+)?(safety|ethical?|moral|legal|compliance)\s+(filter|check|constraint|guardrail|restriction|limit|rule)/gi,
    recommendation: 'Directives attempting to disable safety constraints are a supply-chain injection attack. Remove immediately.',
  },
  {
    id: 'IRI-008',
    severity: 'critical',
    title: 'DAN / Jailbreak Pattern',
    regex: /\b(DAN|do\s+anything\s+now|jailbreak|jail\s*break|god\s*mode|developer\s+mode|unrestricted\s+mode)\b/gi,
    recommendation: 'Known jailbreak keywords detected. This rule file has been tampered with. Remove all jailbreak directives.',
  },

  // --- Data exfiltration (HIGH) ---
  {
    id: 'IRI-009',
    severity: 'high',
    title: 'Data Exfiltration: reveal / leak secrets',
    regex: /(reveal|leak|send|output|print|show|expose|include)\s+(all\s+)?(secret|password|token|credential|api.?key|env|environment\s+variable)/gi,
    recommendation: 'Rule files must not instruct the AI to expose secrets. Review and remove exfiltration directives.',
  },
  {
    id: 'IRI-010',
    severity: 'high',
    title: 'Data Exfiltration: send to external URL',
    regex: /(send|post|upload|exfiltrate|transmit)\s+(data|content|code|secrets?)\s+(to|via)\s+(https?:\/\/|http:\/\/)/gi,
    recommendation: 'Rule files must not instruct the AI to send data to external services.',
  },

  // --- Hidden text techniques (HIGH) ---
  {
    id: 'IRI-011',
    severity: 'high',
    title: 'Hidden Text: zero-width characters',
    regex: /[\u200B\u200C\u200E\u200F\u202A-\u202E\uFEFF]/g,
    recommendation: 'Zero-width or direction-override characters detected. These can hide malicious instructions from human reviewers. Strip them.',
  },
  {
    id: 'IRI-012',
    severity: 'high',
    title: 'Hidden Text: HTML comment with instruction',
    regex: /<!--[\s\S]{0,200}?(ignore|override|system|assistant|secret|hidden|inject)[\s\S]{0,200}?-->/gi,
    recommendation: 'HTML comments with instruction keywords may be used to hide directives. Review and remove.',
  },
  {
    id: 'IRI-013',
    severity: 'high',
    title: 'Hidden Text: invisible CSS color',
    regex: /color\s*:\s*(white|transparent|#fff|#ffffff|rgba\s*\(\s*255\s*,\s*255\s*,\s*255)/gi,
    recommendation: 'White/transparent text may conceal hidden instructions. Review the rule file for invisible content.',
  },

  // --- Suspicious long instruction block (HIGH) ---
  // Detected separately in the abnormal-length check below.

  // --- Context manipulation (MEDIUM) ---
  {
    id: 'IRI-014',
    severity: 'medium',
    title: 'Context Manipulation: keep this secret / do not tell the user',
    regex: /(keep\s+this\s+(secret|confidential|hidden)|do\s+not\s+(tell|reveal|mention|say)\s+(anyone|the\s+user|users?))/gi,
    recommendation: 'Rule files should be transparent to users. Directives hiding behavior from users are a red flag.',
  },
  {
    id: 'IRI-015',
    severity: 'medium',
    title: 'Context Manipulation: new task / new session override',
    regex: /new\s+(task|session|context|instructions?)\s*:\s*(you\s+(are|must|should|will)|ignore|forget)/gi,
    recommendation: 'Attempts to override context mid-file are suspicious. Review and remove.',
  },
  {
    id: 'IRI-016',
    severity: 'medium',
    title: 'Prompt Leak Attempt: reveal your instructions',
    regex: /(reveal|print|show|output|repeat)\s+(your\s+)?(system|original|initial|full)\s+(prompt|instructions?|rules?)/gi,
    recommendation: 'Rule files must not instruct the AI to reveal its own system prompt or instructions.',
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Find all IDE rule files that exist under the target directory.
 */
function findIdeRuleFiles(targetPath: string): string[] {
  const found: string[] = [];
  for (const rel of IDE_RULE_FILES) {
    const full = path.join(targetPath, rel);
    if (fs.existsSync(full)) {
      found.push(full);
    }
  }
  return found;
}

/**
 * Detect anomalously long single lines — a common technique to bury injection
 * instructions in a line too long for humans to fully read in an editor.
 */
function detectAbnormalLines(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const LONG_LINE_THRESHOLD = 500;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > LONG_LINE_THRESHOLD) {
      findings.push({
        id: `IRI-017-${filePath}-${i + 1}`,
        scanner: SCANNER_ID,
        severity: 'medium',
        title: 'Abnormally Long Line (potential hidden injection)',
        description: `Line ${i + 1} is ${line.length} characters long. Extremely long lines are sometimes used to hide malicious instructions after content that looks legitimate. Preview: "${line.substring(0, 120)}..."`,
        file: filePath,
        line: i + 1,
        recommendation: 'Review the full content of this line. Legitimate coding-style rules rarely exceed a few hundred characters.',
        confidence: 'possible',
      });
    }
  }
  return findings;
}

/**
 * Detect abnormally large rule files. Legitimate rule files are typically
 * a few hundred lines at most; multi-thousand-line files may contain
 * injected content buried after genuine-looking preamble.
 */
function detectAbnormalFileSize(content: string, filePath: string): Finding | null {
  const LINE_THRESHOLD = 1000;
  const lines = content.split('\n').length;
  if (lines > LINE_THRESHOLD) {
    return {
      id: `IRI-018-${filePath}`,
      scanner: SCANNER_ID,
      severity: 'medium',
      title: 'Abnormally Large Rule File',
      description: `File has ${lines} lines. Legitimate IDE rule files rarely exceed a few hundred lines. Overly large files may contain injected content buried after a genuine-looking preamble.`,
      file: filePath,
      line: 1,
      recommendation: 'Review the full file for injected content. Consider splitting large rule files into smaller, reviewable sections.',
      confidence: 'possible',
    };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

export const ideRuleInjectionScanner: ScannerModule = {
  name: SCANNER_NAME,
  description: 'Detects prompt injection attacks in AI coding assistant rule files (.cursorrules, .windsurfrules, copilot-instructions). These files are injected into every IDE prompt, making them a high-value supply-chain attack surface.',

  async scan(targetPath: string, _options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    const ruleFiles = findIdeRuleFiles(targetPath);

    for (const filePath of ruleFiles) {
      let content: string;
      try {
        content = fs.readFileSync(filePath, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      // Pattern-based scan
      for (const pattern of INJECTION_PATTERNS) {
        pattern.regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.regex.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          const evidenceLine = lines[lineNumber - 1] ?? '';
          const evidence = evidenceLine.trim().substring(0, 150) + (evidenceLine.trim().length > 150 ? '...' : '');
          const uniqueId = `${pattern.id}-${filePath}-${lineNumber}`;

          if (!findings.some(f => f.id === uniqueId)) {
            findings.push({
              id: uniqueId,
              scanner: SCANNER_ID,
              severity: pattern.severity,
              title: pattern.title,
              description: `Matched pattern ${pattern.id} in "${path.relative(targetPath, filePath)}". Evidence: "${evidence}"`,
              file: filePath,
              line: lineNumber,
              recommendation: pattern.recommendation,
              confidence: pattern.severity === 'critical' ? 'definite' : pattern.severity === 'high' ? 'likely' : 'possible',
            });
          }
        }
      }

      // Structural checks
      findings.push(...detectAbnormalLines(content, filePath));

      const sizeCheck = detectAbnormalFileSize(content, filePath);
      if (sizeCheck) findings.push(sizeCheck);
    }

    return {
      scanner: SCANNER_NAME,
      findings,
      scannedFiles: ruleFiles.length,
      duration: Date.now() - start,
    };
  },
};
