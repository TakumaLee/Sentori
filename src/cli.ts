#!/usr/bin/env node

import * as path from 'path';
import { createDefaultRegistry } from './index';
import { Finding, ScanReport } from './types';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '\x1b[41m\x1b[37m',
  HIGH: '\x1b[31m',
  MEDIUM: '\x1b[33m',
  LOW: '\x1b[36m',
};
const RESET = '\x1b[0m';

function printReport(report: ScanReport): void {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  AgentShield Scan Report`);
  console.log(`${'='.repeat(60)}`);
  console.log(`  Target:    ${report.target}`);
  console.log(`  Timestamp: ${report.timestamp}`);
  console.log(`${'─'.repeat(60)}`);

  for (const result of report.results) {
    console.log(`\n  Scanner: ${result.scanner}`);
    console.log(`  Files scanned: ${result.filesScanned} | Duration: ${result.duration}ms`);

    if (result.findings.length === 0) {
      console.log(`  ✅ No issues found`);
      continue;
    }

    for (const f of result.findings) {
      const color = SEVERITY_COLORS[f.severity] || '';
      console.log(`\n  ${color}[${f.severity}]${RESET} ${f.rule}: ${f.message}`);
      console.log(`    File: ${f.file}:${f.line}`);
      console.log(`    Evidence: ${f.evidence}`);
    }
  }

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`  Summary: ${report.totalFindings} findings`);
  console.log(`    CRITICAL: ${report.criticalCount} | HIGH: ${report.highCount} | MEDIUM: ${report.mediumCount} | LOW: ${report.lowCount}`);
  console.log(`${'='.repeat(60)}\n`);
}

async function main(): Promise<void> {
  const targetDir = process.argv[2] || process.cwd();
  const iocPath = process.argv[3];
  const registry = createDefaultRegistry(iocPath);
  const report = await registry.runAll(path.resolve(targetDir));
  printReport(report);
  process.exit(report.criticalCount > 0 ? 2 : report.highCount > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
