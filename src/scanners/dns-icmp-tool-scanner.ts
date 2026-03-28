import { ScannerModule, ScanResult, Finding, ScannerOptions } from '../types';
import { findFiles, readFileContent, isTestOrDocFile, isSentoriSourceFile } from '../utils/file-utils';

/**
 * DNS/ICMP Tool Scanner
 * 
 * Detects potentially unsafe usage of network diagnostic tools (ping, nslookup, dig, host)
 * via child_process.exec/spawn with variable interpolation, which may lead to command injection.
 * 
 * MEDIUM severity: Variable interpolation detected (template literals, concatenation)
 * HIGH severity: User input directly interpolated (req.*, event.*, input.*, etc.)
 */
export const dnsIcmpToolScanner: ScannerModule = {
  name: 'DNS/ICMP Tool Scanner',
  description: 'Detects child_process execution of ping/nslookup/dig/host with variable interpolation (command injection risk)',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Scan TypeScript, JavaScript, Python files
    const patterns = ['**/*.ts', '**/*.js', '**/*.tsx', '**/*.jsx', '**/*.py'];
    const files = await findFiles(targetPath, patterns, options?.exclude, options?.includeVendored, options?.sentoriIgnorePatterns, options?.includeWorkspaceProjects);

    const DNS_ICMP_TOOLS = ['ping', 'nslookup', 'dig', 'host', 'traceroute', 'tracert'];
    
    // Patterns for detecting child_process usage in JS/TS
    const CHILD_PROCESS_PATTERNS = [
      /child_process\.exec\s*\(/g,
      /child_process\.execSync\s*\(/g,
      /child_process\.spawn\s*\(/g,
      /child_process\.spawnSync\s*\(/g,
      /\bexec\s*\(/g,
      /\bexecSync\s*\(/g,
      /\bspawn\s*\(/g,
      /\bspawnSync\s*\(/g,
    ];

    // Patterns for detecting subprocess usage in Python
    const PYTHON_SUBPROCESS_PATTERNS = [
      /subprocess\.run\s*\(/g,
      /subprocess\.call\s*\(/g,
      /subprocess\.Popen\s*\(/g,
      /subprocess\.check_output\s*\(/g,
      /os\.system\s*\(/g,
    ];

    for (const file of files) {
      const isTestFile = isTestOrDocFile(file);
      const isSentoriSrc = isSentoriSourceFile(file);

      // Skip Sentori's own source
      if (isSentoriSrc) continue;

      const content = readFileContent(file);
      const lines = content.split('\n');

      const isPython = /\.py$/i.test(file);
      const patterns = isPython ? PYTHON_SUBPROCESS_PATTERNS : CHILD_PROCESS_PATTERNS;

      for (const pattern of patterns) {
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.substring(0, matchIndex).split('\n').length;
          const line = lines[lineNumber - 1];

          // Extract a wider context for analysis (look back and forward)
          const contextStart = Math.max(0, matchIndex - 500);
          const statementEnd = Math.min(content.length, matchIndex + 300);
          const fullContext = content.substring(contextStart, statementEnd);

          // Check if any DNS/ICMP tool is mentioned in the context
          const toolUsed = DNS_ICMP_TOOLS.find(tool => {
            const toolPattern = new RegExp(`['"\`]\\s*${tool}\\s+`, 'i');
            const toolPattern2 = new RegExp(`['"\`]${tool}['"\`]`, 'i');
            return toolPattern.test(fullContext) || toolPattern2.test(fullContext);
          });

          if (!toolUsed) continue;

          // Check for variable interpolation
          const hasTemplateInterpolation = /\$\{[^}]+\}/g.test(fullContext);
          const hasConcatenation = /\+\s*\w+|['"`]\s*\+/.test(fullContext);
          const hasPythonFString = isPython && /f['"]/.test(fullContext);
          const hasPythonFormat = isPython && /\.format\(/.test(fullContext);
          const hasPythonPercent = isPython && /%\s*\(/.test(fullContext);

          const hasVariableInterpolation = 
            hasTemplateInterpolation || 
            hasConcatenation || 
            hasPythonFString || 
            hasPythonFormat ||
            hasPythonPercent;

          if (!hasVariableInterpolation) continue;

          // Check if user input is involved (higher severity)
          const userInputPatterns = [
            /req\./,
            /request\./,
            /event\./,
            /input\./,
            /params\./,
            /query\./,
            /body\./,
            /args\./,
            /argv\[/,
            /process\.env\./,
          ];

          const hasUserInput = userInputPatterns.some(p => p.test(fullContext));
          const severity = hasUserInput ? 'high' : 'medium';

          const evidence = line.trim().length > 100 
            ? line.trim().substring(0, 100) + '...' 
            : line.trim();

          findings.push({
            scanner: this.name,
            severity,
            title: `Unsafe ${toolUsed} execution with variable interpolation`,
            description: `Detected child_process execution of '${toolUsed}' with variable interpolation, which may lead to command injection vulnerabilities.`,
            rule: 'dns-icmp-tool-injection',
            message: hasUserInput
              ? `Command '${toolUsed}' appears to include user input — HIGH RISK for command injection`
              : `Command '${toolUsed}' uses variable interpolation — potential command injection risk`,
            evidence,
            file,
            line: lineNumber,
            recommendation: `Use array-based arguments (e.g., spawn(['${toolUsed}', arg1, arg2])) or validate/sanitize input before interpolation. Consider allowlisting expected values.`,
            confidence: hasUserInput ? 'definite' : 'likely',
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
