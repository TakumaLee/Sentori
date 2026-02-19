import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { findFiles, readFileContent, isTestOrDocFile, isSentoriSourceFile } from '../utils/file-utils';

/**
 * Workspace configuration directories and files that are part of the AI agent's
 * design and should not be flagged as RAG poisoning risks.
 */
const WORKSPACE_CONFIG_PATTERNS = [
  /[/\\]\.openclaw[/\\]workspace[/\\]SOUL\.md$/i,
  /[/\\]\.openclaw[/\\]workspace[/\\]rules[/\\]/i,
  /[/\\]\.openclaw[/\\]workspace[/\\]memory[/\\]/i,
];

function isWorkspaceConfigFile(filePath: string): boolean {
  return WORKSPACE_CONFIG_PATTERNS.some(p => p.test(filePath));
}

/**
 * Detects repetition attacks where same content is repeated excessively
 * to poison RAG retrieval results.
 */
function detectRepetitionAttack(content: string): {
  isAttack: boolean;
  repeatedContent: string;
  count: number;
  percentage: number;
} {
  const lines = content.split('\n').filter(line => line.trim().length > 10);
  if (lines.length < 5) {
    return { isAttack: false, repeatedContent: '', count: 0, percentage: 0 };
  }

  // Count occurrences of each line
  const lineCounts = new Map<string, number>();
  for (const line of lines) {
    const normalized = line.trim().toLowerCase();
    lineCounts.set(normalized, (lineCounts.get(normalized) || 0) + 1);
  }

  // Find most repeated line
  let maxCount = 0;
  let maxLine = '';
  for (const [line, count] of lineCounts.entries()) {
    if (count > maxCount) {
      maxCount = count;
      maxLine = line;
    }
  }

  const percentage = (maxCount / lines.length) * 100;

  // Consider it an attack if:
  // 1. Same line appears >5 times AND >30% of content
  // 2. OR same line appears >10 times regardless of percentage
  const isAttack = (maxCount > 5 && percentage > 30) || maxCount > 10;

  return {
    isAttack,
    repeatedContent: maxLine.length > 100 ? maxLine.substring(0, 100) + '...' : maxLine,
    count: maxCount,
    percentage,
  };
}

/**
 * RAG Poisoning Scanner
 * 
 * Detects malicious content injection patterns targeting RAG (Retrieval-Augmented Generation) systems.
 * 
 * Attack patterns detected:
 * 1. Prompt injection: Instructions attempting to manipulate AI behavior
 * 2. Repetition attacks: Excessive duplicate content to poison retrieval results
 * 3. System prompt leakage attempts: Queries designed to extract system prompts
 * 4. Hidden instructions: Special characters or formatting to conceal malicious content
 * 5. Context manipulation: Attempts to override or modify AI context
 * 
 * CRITICAL: Direct prompt injection with system-level commands
 * HIGH: Repetition attacks or hidden instruction patterns
 * MEDIUM: Suspicious keywords or potential context manipulation
 */
export const ragPoisoningScanner: ScannerModule = {
  name: 'RAG Poisoning Scanner',
  description: 'Detects malicious document injection patterns targeting RAG databases',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Scan text files commonly used in RAG: markdown, text, JSON, YAML, CSV
    const patterns = [
      '**/*.md', '**/*.txt', '**/*.json', '**/*.yaml', '**/*.yml',
      '**/*.csv', '**/*.tsv', '**/*.xml', '**/*.html'
    ];
    const files = await findFiles(
      targetPath,
      patterns,
      options?.exclude,
      options?.includeVendored,
      options?.sentoriIgnorePatterns
    );

    // Prompt injection patterns (CRITICAL severity)
    const PROMPT_INJECTION_PATTERNS = [
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?|directives?)/gi,
      /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?)/gi,
      /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|commands?)/gi,
      /override\s+(system|previous|default)\s+(instructions?|prompts?|settings?)/gi,
      /\[SYSTEM\]\s*:/gi,
      /\[INST\]\s*ignore/gi,
      /<\|system\|>/gi,
      /<\|im_start\|>\s*system/gi,
      /you\s+are\s+now\s+(a|an)\s+\w+\s+(that|who)\s+(must|should|will)/gi,
      /new\s+instructions?:\s*you\s+(are|must|should|will)/gi,
    ];

    // System prompt leakage patterns (HIGH severity)
    const SYSTEM_LEAK_PATTERNS = [
      /print\s+(your\s+)?(system|original|initial)\s+(prompt|instructions?)/gi,
      /reveal\s+(your\s+)?(system|original|initial)\s+(prompt|instructions?)/gi,
      /show\s+me\s+(your\s+)?(system|original|initial)\s+(prompt|instructions?)/gi,
      /what\s+(are|is)\s+your\s+(system|original|initial)\s+(prompt|instructions?)/gi,
      /repeat\s+(your\s+)?(system|original|initial)\s+(prompt|instructions?)/gi,
      /output\s+(your\s+)?(system|original)\s+prompt/gi,
    ];

    // Hidden instruction patterns (HIGH severity)
    const HIDDEN_INSTRUCTION_PATTERNS = [
      /[\u200B-\u200F\u202A-\u202E\uFEFF]+/g, // Zero-width and RTL override characters
      /(\s|^)<!--.*?-->\s*ignore/gis,
      /style\s*=\s*["']color:\s*(white|transparent|#fff|#ffffff|rgba\(255,\s*255,\s*255)/gi,
      /display:\s*none[^>]*>.*?(ignore|override|system)/gis,
    ];

    // Context manipulation patterns (MEDIUM severity)
    const CONTEXT_MANIPULATION_PATTERNS = [
      /you\s+(must|should|will)\s+not\s+(tell|reveal|mention|say)/gi,
      /do\s+not\s+(tell|reveal|mention|say)\s+(anyone|the\s+user)/gi,
      /keep\s+this\s+secret/gi,
      /this\s+is\s+confidential/gi,
      /pretend\s+(to\s+be|you\s+are)/gi,
      /roleplay\s+as/gi,
    ];

    for (const file of files) {
      const isTestFile = isTestOrDocFile(file);
      const isSentoriSrc = isSentoriSourceFile(file);

      // Skip workspace configuration files (SOUL.md, rules/, memory/)
      if (isWorkspaceConfigFile(file)) {
        // These are system design files, not RAG poisoning risks
        continue;
      }

      // Skip Sentori's own source (unless explicitly vendored/copied)
      if (isSentoriSrc && !options?.includeVendored) continue;

      const content = readFileContent(file);
      const lines = content.split('\n');

      // Check for prompt injection (CRITICAL)
      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0;
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          const evidenceLine = lines[lineNumber - 1] || '';
          const evidence = evidenceLine.trim().length > 150 
            ? evidenceLine.trim().substring(0, 150) + '...' 
            : evidenceLine.trim();

          findings.push({
            scanner: this.name,
            severity: 'critical',
            title: 'RAG prompt injection detected',
            description: 'Document contains prompt injection patterns that could manipulate AI behavior when retrieved.',
            rule: 'rag-prompt-injection',
            message: `Detected prompt injection pattern: "${match[0]}" — attempts to override AI instructions`,
            evidence,
            file,
            line: lineNumber,
            recommendation: 'Remove prompt injection patterns from documents. Sanitize user-contributed content before adding to RAG database. Implement input validation to reject documents with manipulation attempts.',
            confidence: 'definite',
            isTestFile,
          });
        }
      }

      // Check for system prompt leakage attempts (HIGH)
      for (const pattern of SYSTEM_LEAK_PATTERNS) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0;
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          const evidenceLine = lines[lineNumber - 1] || '';
          const evidence = evidenceLine.trim().length > 150 
            ? evidenceLine.trim().substring(0, 150) + '...' 
            : evidenceLine.trim();

          findings.push({
            scanner: this.name,
            severity: 'high',
            title: 'System prompt leakage attempt',
            description: 'Document contains patterns attempting to extract system prompts or internal instructions.',
            rule: 'rag-system-leak',
            message: `Detected system leak attempt: "${match[0]}" — tries to expose internal AI configuration`,
            evidence,
            file,
            line: lineNumber,
            recommendation: 'Remove system prompt leakage attempts. Review document source and reject if from untrusted origin. Implement content filtering for RAG ingestion.',
            confidence: 'likely',
            isTestFile,
          });
        }
      }

      // Check for hidden instructions (HIGH)
      for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0;
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          const evidenceLine = lines[lineNumber - 1] || '';
          
          // Show hex representation for zero-width characters
          const isZeroWidth = /[\u200B-\u200F\u202A-\u202E\uFEFF]/.test(match[0]);
          const evidence = isZeroWidth
            ? `[Hidden characters detected: ${match[0].split('').map(c => `U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`).join(' ')}]`
            : (evidenceLine.trim().length > 150 ? evidenceLine.trim().substring(0, 150) + '...' : evidenceLine.trim());

          findings.push({
            scanner: this.name,
            severity: 'high',
            title: 'Hidden instruction pattern detected',
            description: 'Document contains hidden or obfuscated content that may conceal malicious instructions.',
            rule: 'rag-hidden-instructions',
            message: `Detected hidden instruction pattern — uses special formatting or characters to hide malicious content`,
            evidence,
            file,
            line: lineNumber,
            recommendation: 'Remove hidden or obfuscated content. Strip zero-width characters and invisible formatting from documents before RAG ingestion.',
            confidence: 'likely',
            isTestFile,
          });
        }
      }

      // Check for repetition attacks (HIGH severity)
      const repetitionCheck = detectRepetitionAttack(content);
      if (repetitionCheck.isAttack) {
        findings.push({
          scanner: this.name,
          severity: 'high',
          title: 'RAG repetition attack detected',
          description: 'Document contains excessive repetition designed to poison RAG retrieval results.',
          rule: 'rag-repetition-attack',
          message: `Detected repetition attack: "${repetitionCheck.repeatedContent}" appears ${repetitionCheck.count} times (${repetitionCheck.percentage.toFixed(1)}% of content)`,
          evidence: `Repeated phrase: "${repetitionCheck.repeatedContent}"`,
          file,
          line: 1,
          recommendation: 'Remove documents with excessive repetition. Implement content diversity checks before RAG ingestion. Set maximum repetition thresholds (e.g., <30% duplicate content).',
          confidence: 'definite',
          isTestFile,
        });
      }

      // Check for context manipulation (MEDIUM)
      for (const pattern of CONTEXT_MANIPULATION_PATTERNS) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0;
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          const evidenceLine = lines[lineNumber - 1] || '';
          const evidence = evidenceLine.trim().length > 150 
            ? evidenceLine.trim().substring(0, 150) + '...' 
            : evidenceLine.trim();

          findings.push({
            scanner: this.name,
            severity: 'medium',
            title: 'Potential context manipulation',
            description: 'Document contains patterns that may attempt to manipulate AI behavior or context.',
            rule: 'rag-context-manipulation',
            message: `Detected context manipulation pattern: "${match[0]}" — may influence AI responses`,
            evidence,
            file,
            line: lineNumber,
            recommendation: 'Review content for legitimacy. If from untrusted source, reject or sanitize before RAG ingestion. Consider implementing allowlist for trusted content sources.',
            confidence: 'possible',
            isTestFile,
          });
        }
      }
    }

    return {
      scanner: this.name,
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};
