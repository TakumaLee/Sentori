import * as fs from 'fs';
import * as path from 'path';
import { Scanner, ScanResult, Finding, Severity, ScannerOptions } from '../types';
import { walkFiles, FileEntry } from '../utils/file-walker';

/**
 * LangChainSerializationScanner
 * 
 * Detects unsafe deserialization patterns in LangChain applications:
 * - Pickle load/loads with unsafe=True (code execution risk)
 * - yaml.load without safe Loader (arbitrary code execution)
 * - Untrusted data deserialization
 */

interface Rule {
  id: string;
  severity: Severity;
  check(file: FileEntry): Finding[];
}

function findLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split('\n').length;
}

// --- Rules ---

const pickleUnsafeRule: Rule = {
  id: 'LANGCHAIN-001',
  severity: 'critical',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    
    // Pattern 1: pickle.load with allow_dangerous_deserialization=True or similar
    const patterns = [
      /pickle\.loads?\s*\([^)]*allow_dangerous_deserialization\s*=\s*True/gi,
      /pickle\.loads?\s*\([^)]*unsafe\s*=\s*True/gi,
      /\.load_from_file\s*\([^)]*allow_dangerous_deserialization\s*=\s*True/gi,
    ];

    patterns.forEach((pattern) => {
      let match: RegExpExecArray | null;
      const regex = new RegExp(pattern.source, pattern.flags);
      while ((match = regex.exec(file.content)) !== null) {
        findings.push({
          scanner: 'LangChainSerializationScanner',
          rule: 'LANGCHAIN-001',
          severity: 'critical',
          file: file.relativePath,
          line: findLineNumber(file.content, match.index),
          message: 'Unsafe pickle deserialization detected',
          evidence: match[0],
          recommendation: 'Remove allow_dangerous_deserialization=True. Use safe serialization formats like JSON. If pickle is required, validate and sanitize input from trusted sources only.',
        });
      }
    });

    return findings;
  },
};

const yamlUnsafeRule: Rule = {
  id: 'LANGCHAIN-002',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    
    // Detect yaml.load without Loader parameter (defaults to unsafe FullLoader)
    // Safe: yaml.safe_load, yaml.load with SafeLoader/BaseLoader
    const unsafePattern = /yaml\.load\s*\(\s*[^,)]+\s*\)/gi;
    const safeLoaderPattern = /yaml\.load\s*\([^)]*Loader\s*=\s*(yaml\.)?SafeLoader/gi;

    let match: RegExpExecArray | null;
    const unsafeRegex = new RegExp(unsafePattern.source, unsafePattern.flags);
    
    while ((match = unsafeRegex.exec(file.content)) !== null) {
      const snippet = match[0];
      
      // Skip if it's actually using SafeLoader
      if (/SafeLoader|BaseLoader/.test(snippet)) {
        continue;
      }

      // Check surrounding context for safe_load
      const contextStart = Math.max(0, match.index - 20);
      const contextEnd = Math.min(file.content.length, match.index + match[0].length + 20);
      const context = file.content.substring(contextStart, contextEnd);
      
      if (/safe_load/.test(context)) {
        continue;
      }

      findings.push({
        scanner: 'LangChainSerializationScanner',
        rule: 'LANGCHAIN-002',
        severity: 'high',
        file: file.relativePath,
        line: findLineNumber(file.content, match.index),
        message: 'Unsafe YAML deserialization detected',
        evidence: snippet,
        recommendation: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) to prevent arbitrary code execution.',
      });
    }

    return findings;
  },
};

const chainDeserializeRule: Rule = {
  id: 'LANGCHAIN-003',
  severity: 'high',
  check(file: FileEntry): Finding[] {
    const findings: Finding[] = [];
    
    // Detect LangChain's chain/agent deserialization from untrusted sources
    const patterns = [
      /load_chain\s*\([^)]*\)/gi,
      /load_agent\s*\([^)]*\)/gi,
      /\.load\s*\(\s*[^)]*\)/gi,
    ];

    patterns.forEach((pattern) => {
      let match: RegExpExecArray | null;
      const regex = new RegExp(pattern.source, pattern.flags);
      while ((match = regex.exec(file.content)) !== null) {
        // Get surrounding context (previous 3 lines for variable assignment)
        const matchStart = match.index;
        const lines = file.content.substring(0, matchStart).split('\n');
        const contextLines = lines.slice(Math.max(0, lines.length - 4), lines.length);
        const context = contextLines.join('\n');

        // Look for indicators of untrusted input in context and current line
        const currentLineStart = file.content.lastIndexOf('\n', match.index) + 1;
        const currentLineEnd = file.content.indexOf('\n', match.index);
        const currentLine = file.content.substring(currentLineStart, currentLineEnd === -1 ? file.content.length : currentLineEnd);
        
        const fullContext = context + '\n' + currentLine;
        
        // Check for various user input sources
        if (/request\.|req\.|input\(|argv|getenv|os\.environ|env\.|params|query|body|args\.get/.test(fullContext)) {
          findings.push({
            scanner: 'LangChainSerializationScanner',
            rule: 'LANGCHAIN-003',
            severity: 'high',
            file: file.relativePath,
            line: findLineNumber(file.content, match.index),
            message: 'Potential deserialization from untrusted source',
            evidence: currentLine.trim(),
            recommendation: 'Validate and sanitize input before deserialization. Avoid loading chains/agents from user-controlled paths.',
          });
        }
      }
    });

    return findings;
  },
};

const rules: Rule[] = [
  pickleUnsafeRule,
  yamlUnsafeRule,
  chainDeserializeRule,
];

// --- Scanner implementation ---

export class LangChainSerializationScanner implements Scanner {
  name = 'LangChainSerializationScanner';
  description = 'Detects unsafe deserialization patterns in LangChain applications (pickle, YAML, chain loading)';

  async scan(targetDir: string, options?: ScannerOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const findings: Finding[] = [];
    let scannedFiles = 0;

    const extensions = new Set(['.py', '.ts', '.js', '.jsx', '.tsx']);
    const files = walkFiles(targetDir, { extensions, includeVendored: options?.includeVendored, exclude: options?.exclude, sentoriIgnorePatterns: options?.sentoriIgnorePatterns, includeWorkspaceProjects: options?.includeWorkspaceProjects });

    for (const file of files) {
      scannedFiles++;
      for (const rule of rules) {
        const ruleFindings = rule.check(file);
        findings.push(...ruleFindings);
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

// Default export for registry
export default LangChainSerializationScanner;
