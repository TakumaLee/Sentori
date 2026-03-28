import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { findFiles, readFileContent, isTestOrDocFile, isSentoriSourceFile } from '../utils/file-utils';

/**
 * Clipboard Exfiltration Scanner
 * 
 * Detects suspicious clipboard read operations followed by network transmission,
 * which may indicate clipboard data exfiltration.
 * 
 * Patterns detected:
 * 1. Browser clipboard API: navigator.clipboard.readText/read
 * 2. Command-line tools: pbcopy, pbpaste, xclip, xsel
 * 3. Network transmission: fetch, XMLHttpRequest, axios, http, https
 * 
 * CRITICAL: Clipboard read directly followed by network send in same scope
 * HIGH: Clipboard read and network send in same file with suspicious timing
 * MEDIUM: Clipboard read capability detected with network access
 */
export const clipboardExfiltrationScanner: ScannerModule = {
  name: 'Clipboard Exfiltration Scanner',
  description: 'Detects clipboard read operations followed by network transmission (potential data exfiltration)',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Scan TypeScript, JavaScript, Python, Shell files
    const patterns = ['**/*.ts', '**/*.js', '**/*.tsx', '**/*.jsx', '**/*.py', '**/*.sh', '**/*.bash'];
    const files = await findFiles(targetPath, patterns, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns, options?.includeWorkspaceProjects);

    // Clipboard read patterns
    const CLIPBOARD_READ_PATTERNS = {
      api: [
        /navigator\.clipboard\.readText\s*\(/gi,
        /navigator\.clipboard\.read\s*\(/gi,
        /clipboard\.readText\s*\(/gi,
        /clipboard\.read\s*\(/gi,
      ],
      cli: [
        /\b(pbpaste|xclip|xsel)\b/gi,
        /subprocess\.(check_output|run|call|Popen)\s*\(\s*\[?\s*['"]xclip/gi,
        /subprocess\.(check_output|run|call|Popen)\s*\(\s*\[?\s*['"]xsel/gi,
      ],
    };

    // Network send patterns
    const NETWORK_SEND_PATTERNS = [
      /\bfetch\s*\(/gi,
      /\bXMLHttpRequest\s*\(/gi,
      /\.send\s*\(/gi,
      /axios\.(get|post|put|patch|delete)\s*\(/gi,
      /https?\.request\s*\(/gi,
      /https?\.get\s*\(/gi,
      /https?\.post\s*\(/gi,
      /requests\.(get|post|put|patch|delete)\s*\(/gi,
      /urllib\.request/gi,
      /\bcurl\s+-/gi,
      /\bwget\s+-/gi,
    ];

    for (const file of files) {
      const isTestFile = isTestOrDocFile(file);
      const isSentoriSrc = isSentoriSourceFile(file);

      // Skip Sentori's own source
      if (isSentoriSrc) continue;

      const content = readFileContent(file);
      const lines = content.split('\n');

      // Find all clipboard read locations
      const clipboardReads: Array<{ type: 'api' | 'cli'; index: number; line: number; pattern: string }> = [];
      
      // Check API patterns
      for (const pattern of CLIPBOARD_READ_PATTERNS.api) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0; // Reset regex state
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          clipboardReads.push({
            type: 'api',
            index: matchIndex,
            line: lineNumber,
            pattern: match[0],
          });
        }
      }

      // Check CLI patterns
      for (const pattern of CLIPBOARD_READ_PATTERNS.cli) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0; // Reset regex state
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          clipboardReads.push({
            type: 'cli',
            index: matchIndex,
            line: lineNumber,
            pattern: match[0],
          });
        }
      }

      // Find all network send locations
      const networkSends: Array<{ index: number; line: number; pattern: string }> = [];
      
      for (const pattern of NETWORK_SEND_PATTERNS) {
        let match: RegExpExecArray | null;
        pattern.lastIndex = 0; // Reset regex state
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          networkSends.push({
            index: matchIndex,
            line: lineNumber,
            pattern: match[0],
          });
        }
      }

      // Analyze combinations
      if (clipboardReads.length === 0 || networkSends.length === 0) {
        continue;
      }

      // Check for suspicious combinations
      for (const clipRead of clipboardReads) {
        for (const netSend of networkSends) {
          const distance = Math.abs(netSend.index - clipRead.index);
          const lineDiff = Math.abs(netSend.line - clipRead.line);

          let severity: 'critical' | 'high' | 'medium' = 'medium';
          let confidence: 'definite' | 'likely' | 'possible' = 'possible';
          let message = '';

          // CRITICAL: Very close proximity (within 300 chars, same function scope likely)
          if (distance < 300 && lineDiff < 10) {
            severity = 'critical';
            confidence = 'definite';
            message = `Clipboard read (${clipRead.pattern}) immediately followed by network send (${netSend.pattern}) within ${lineDiff} lines — HIGH RISK for data exfiltration`;
          }
          // HIGH: Close proximity (within 800 chars, same file section)
          else if (distance < 800 && lineDiff < 30) {
            severity = 'high';
            confidence = 'likely';
            message = `Clipboard read (${clipRead.pattern}) followed by network send (${netSend.pattern}) within ${lineDiff} lines — potential data exfiltration`;
          }
          // MEDIUM: Both capabilities present in same file
          else {
            severity = 'medium';
            confidence = 'possible';
            message = `File contains both clipboard read (${clipRead.pattern}) and network send (${netSend.pattern}) capabilities — review for potential exfiltration`;
          }

          // Extract evidence from the clipboard read line
          const evidenceLine = lines[clipRead.line - 1] || '';
          const evidence = evidenceLine.trim().length > 100 
            ? evidenceLine.trim().substring(0, 100) + '...' 
            : evidenceLine.trim();

          findings.push({
            scanner: this.name,
            severity,
            title: `Clipboard exfiltration risk: ${clipRead.type === 'api' ? 'Browser API' : 'CLI tool'} + Network send`,
            description: `Detected clipboard read operation followed by network transmission, which may indicate clipboard data exfiltration.`,
            rule: 'clipboard-exfiltration',
            message,
            evidence,
            file,
            line: clipRead.line,
            recommendation: `Review the code path between clipboard read (line ${clipRead.line}) and network send (line ${netSend.line}). Ensure clipboard data is not being exfiltrated. Consider: 1) User consent for clipboard access, 2) Sanitization of clipboard data, 3) Allowlisting destination URLs.`,
            confidence,
            isTestFile,
          });

          // Only report the closest network send for each clipboard read to avoid noise
          break;
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
