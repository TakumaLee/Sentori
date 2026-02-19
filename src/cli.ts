#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { createDefaultRegistry } from './index';
import { printReport, writeJsonReport } from './utils/reporter';
import { calculateSummary } from './utils/scorer';
import { ScannerModule } from './types';

// ─── Profile filtering ──────────────────────────────────────────────────────

export type ProfileType = 'agent' | 'general' | 'mobile';

const AGENT_ONLY_SCANNERS = new Set([
  'Defense Analyzer',
  'Red Team Simulator',
  'Prompt Injection Tester',
  'MCP Config Auditor',
]);

const GENERAL_SCANNERS = new Set([
  'Secret Leak Scanner',
  'Permission Analyzer',
  'Skill Auditor',
]);

const MOBILE_SCANNERS = new Set([
  'Secret Leak Scanner',
  'Permission Analyzer',
]);

/**
 * Filter a list of ScannerModules to only those relevant for a given profile.
 * - agent:   all scanners (full AI-agent security audit)
 * - general: secrets, permissions, skills
 * - mobile:  secrets, permissions only
 */
export function filterScannersByProfile(
  scanners: ScannerModule[],
  profile: ProfileType
): ScannerModule[] {
  if (profile === 'agent') return scanners;
  const allowlist = profile === 'mobile' ? MOBILE_SCANNERS : GENERAL_SCANNERS;
  return scanners.filter((s) => allowlist.has(s.name));
}

function getVersion(): string {
  try {
    const pkgPath = path.resolve(__dirname, '..', 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    return pkg.version as string;
  } catch {
    return '0.0.0';
  }
}

function printHelp(): void {
  console.log('');
  console.log(chalk.bold.cyan('  🛡️  Sentori') + chalk.gray(` v${getVersion()}`));
  console.log(chalk.white('  AI Agent Security Scanner — MCP-focused security for the agentic era'));
  console.log('');
  console.log(chalk.bold('  Usage:'));
  console.log(chalk.gray('    npx @nexylore/sentori [scan] [target-dir] [options]'));
  console.log('');
  console.log(chalk.bold('  Options:'));
  console.log(chalk.gray('    --help, -h         Show help'));
  console.log(chalk.gray('    --version, -v      Show version'));
  console.log(chalk.gray('    --json             Output JSON report to stdout'));
  console.log(chalk.gray('    --output, -o FILE  Save report to file (auto-detects JSON by extension)'));
  console.log(chalk.gray('    --ioc PATH         Path to external IOC blocklist JSON file'));
  console.log(chalk.gray('    --deep-scan        Enable OCR scanning of image files (slow)'));
  console.log('');
  console.log(chalk.bold('  Examples:'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --output report.json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --ioc ./custom-ioc.json'));
  console.log('');
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log(getVersion());
    process.exit(0);
  }

  // Parse flags
  const jsonMode = args.includes('--json');
  const deepScan = args.includes('--deep-scan');
  if (deepScan) {
    process.env.SENTORI_DEEP_SCAN = '1';
  }

  let outputPath: string | undefined;
  const outputIdx = args.findIndex((a) => a === '--output' || a === '-o');
  if (outputIdx !== -1 && args[outputIdx + 1]) {
    outputPath = args[outputIdx + 1];
  }

  let iocPath: string | undefined;
  const iocIdx = args.findIndex((a) => a === '--ioc');
  if (iocIdx !== -1 && args[iocIdx + 1]) {
    iocPath = args[iocIdx + 1];
  }

  // Collect positional args (not flags or flag values)
  const flagValuePositions = new Set<number>();
  for (const flag of ['--output', '-o', '--ioc']) {
    const idx = args.findIndex((a) => a === flag);
    if (idx !== -1) flagValuePositions.add(idx + 1);
  }
  let positional = args.filter(
    (a, i) => !a.startsWith('-') && !flagValuePositions.has(i)
  );

  // Support `sentori scan [dir]` subcommand
  if (positional[0] === 'scan') {
    positional = positional.slice(1);
  }

  const targetDir = path.resolve(positional[0] || process.cwd());
  // Legacy: second positional was ioc path
  if (!iocPath && positional[1]) {
    iocPath = positional[1];
  }

  if (!fs.existsSync(targetDir)) {
    console.error(chalk.red(`  ✗ Target directory not found: ${targetDir}`));
    process.exit(1);
  }

  const version = getVersion();

  if (!jsonMode) {
    console.log('');
    console.log(chalk.bold.cyan('  🛡️  Sentori') + chalk.gray(` v${version}`));
    console.log(chalk.gray(`  Scanning: ${targetDir}`));
    console.log('');
  }

  const registry = createDefaultRegistry(iocPath);

  const report = await registry.runAll(targetDir, (step, total, name, result) => {
    if (jsonMode) return;
    const pct = Math.round((step / total) * 100);
    const filled = Math.round((step / total) * 20);
    const empty = 20 - filled;
    const bar = chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));

    if (!result) {
      // Starting scanner
      process.stdout.write(`\r  ${bar} ${pct}% · ${name}...`);
    } else {
      // Completed scanner
      const findingsColor = result.findings.length > 0 ? chalk.yellow(String(result.findings.length)) : chalk.green('0');
      process.stdout.write(`\r  ${bar} ${pct}% · ${name} ${chalk.gray('→')} ${findingsColor} findings ${chalk.gray(`(${result.duration}ms)`)}   \n`);
    }
  });

  // Ensure summary is populated (registry.runAll now always sets it, but be safe)
  if (!report.summary) {
    report.summary = calculateSummary(report.results);
  }
  report.version = version;

  if (jsonMode) {
    // Output JSON to stdout
    console.log(JSON.stringify(report, null, 2));
  } else if (outputPath && (outputPath.endsWith('.json'))) {
    // Save JSON to file, print summary to console
    printReport(report);
    writeJsonReport(report, outputPath);
  } else if (outputPath) {
    // Save JSON to file (any extension treated as JSON)
    printReport(report);
    writeJsonReport(report, outputPath);
  } else {
    // Default: pretty print
    printReport(report);
  }

  // Exit code: 2 = critical, 1 = high, 0 = ok
  const s = report.summary;
  process.exit(s.critical > 0 ? 2 : s.high > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(chalk.red('Fatal error:'), err);
  process.exit(1);
});
