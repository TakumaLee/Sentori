#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { minimatch } from 'minimatch';
import { createDefaultRegistry } from './index';
import { printReport, writeJsonReport, buildSarifReport, writeSarifReport } from './utils/reporter';
import { calculateSummary } from './utils/scorer';
import { ScannerModule, ScanReport } from './types';
import { loadSentoriConfig, SentoriConfig } from './config/sentori-config';
import { customRulesScanner } from './scanners/custom-rules-scanner';

// ─── .sentori.yml config application ─────────────────────────────────────────

/**
 * Apply ignore entries and severity overrides from .sentori.yml to a completed
 * scan report. Does not mutate the input; returns a new report object.
 */
function applyConfig(report: ScanReport, config: SentoriConfig): ScanReport {
  const { ignore, overrides } = config;

  const results = report.results.map((result) => {
    let findings = result.findings;

    // 1. Severity overrides — must run before ignore so overrides apply to kept findings
    if (overrides.length > 0) {
      findings = findings.map((f) => {
        for (const ov of overrides) {
          if (ov.scanner !== result.scanner) continue;
          if (ov.rule !== undefined && ov.rule !== f.rule) continue;
          return { ...f, severity: ov.severity };
        }
        return f;
      });
    }

    // 2. Ignore filters — suppress findings where ALL specified fields match
    if (ignore.length > 0) {
      findings = findings.filter((f) => {
        for (const ig of ignore) {
          const scannerMatch = ig.scanner === undefined || ig.scanner === result.scanner;
          const ruleMatch = ig.rule === undefined || ig.rule === f.rule;
          const fileMatch =
            ig.file === undefined ||
            (f.file !== undefined && minimatch(f.file, ig.file, { matchBase: false }));

          if (scannerMatch && ruleMatch && fileMatch) return false; // suppress
        }
        return true; // keep
      });
    }

    return { ...result, findings };
  });

  return { ...report, results };
}

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
  console.log(chalk.gray('    --format FORMAT    Output format: pretty (default), json, sarif'));
  console.log(chalk.gray('    --output, -o FILE  Save report to file (auto-detects format by extension)'));
  console.log(chalk.gray('    --ioc PATH         Path to external IOC blocklist JSON file'));
  console.log(chalk.gray('    --deep-scan        Enable OCR scanning of image files (slow)'));
  console.log(chalk.gray('    --profile PROFILE  Filter scanners by profile: agent (default), general, mobile'));
  console.log('');
  console.log(chalk.bold('  Examples:'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --format sarif'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --output report.json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --output results.sarif'));
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
  let outputFormat: 'pretty' | 'json' | 'sarif' = 'pretty';
  const formatIdx = args.findIndex((a) => a === '--format');
  if (formatIdx !== -1 && args[formatIdx + 1]) {
    const fmt = args[formatIdx + 1];
    if (fmt === 'json' || fmt === 'sarif') outputFormat = fmt;
  }
  if (args.includes('--json')) outputFormat = 'json'; // backward compat
  const jsonMode = outputFormat === 'json';
  const sarifMode = outputFormat === 'sarif';

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

  let profile: ProfileType = 'agent';
  const profileIdx = args.findIndex((a) => a === '--profile');
  if (profileIdx !== -1 && args[profileIdx + 1]) {
    const p = args[profileIdx + 1];
    if (p === 'agent' || p === 'general' || p === 'mobile') {
      profile = p;
    } else {
      console.error(chalk.red(`  ✗ Invalid --profile value: "${p}". Must be one of: agent, general, mobile`));
      process.exit(1);
    }
  }

  // Collect positional args (not flags or flag values)
  const flagValuePositions = new Set<number>();
  for (const flag of ['--output', '-o', '--ioc', '--format', '--profile']) {
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

  if (!jsonMode && !sarifMode) {
    console.log('');
    console.log(chalk.bold.cyan('  🛡️  Sentori') + chalk.gray(` v${version}`));
    console.log(chalk.gray(`  Scanning: ${targetDir}`));
    console.log('');
  }

  const registry = createDefaultRegistry(iocPath);

  // Apply profile filter — must happen before runAll so skipped scanners are never loaded
  if (profile !== 'agent') {
    const filtered = filterScannersByProfile(registry.getScanners() as import('./types').ScannerModule[], profile);
    registry.setScanners(filtered as import('./types').Scanner[]);
  }

  // Load .sentori.yml from target directory
  let sentoriConfig: SentoriConfig | null = null;
  try {
    sentoriConfig = loadSentoriConfig(targetDir);
    if (sentoriConfig && !jsonMode && !sarifMode) {
      const ruleCount = sentoriConfig.rules.length;
      const ignoreCount = sentoriConfig.ignore.length;
      const overrideCount = sentoriConfig.overrides.length;
      if (ruleCount + ignoreCount + overrideCount > 0) {
        console.log(chalk.gray(`  Config: ${ruleCount} rules, ${ignoreCount} ignores, ${overrideCount} overrides`));
        console.log('');
      }
    }
  } catch (err) {
    if (!jsonMode && !sarifMode) {
      console.warn(chalk.yellow(`  ⚠ .sentori.yml parse error: ${(err as Error).message}`));
    }
  }

  // Register custom rules scanner if rules are defined
  if (sentoriConfig && sentoriConfig.rules.length > 0) {
    registry.register(customRulesScanner(sentoriConfig.rules) as unknown as import('./types').Scanner);
  }

  let report = await registry.runAll(targetDir, (step, total, name, result) => {
    if (jsonMode || sarifMode) return;
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

  // Apply .sentori.yml ignore filters and severity overrides
  if (sentoriConfig && (sentoriConfig.ignore.length > 0 || sentoriConfig.overrides.length > 0)) {
    report = applyConfig(report, sentoriConfig);
  }

  // Ensure summary is populated (registry.runAll now always sets it, but be safe)
  // Always recalculate after config application to reflect filtered findings
  report.summary = calculateSummary(report.results);
  report.version = version;

  if (sarifMode && outputPath) {
    // --format sarif --output file.sarif
    printReport(report);
    writeSarifReport(report, outputPath);
  } else if (sarifMode) {
    // --format sarif → stdout
    console.log(JSON.stringify(buildSarifReport(report), null, 2));
  } else if (jsonMode) {
    // --json → stdout
    console.log(JSON.stringify(report, null, 2));
  } else if (outputPath && outputPath.endsWith('.sarif')) {
    // auto-detect .sarif extension
    printReport(report);
    writeSarifReport(report, outputPath);
  } else if (outputPath) {
    // Save JSON to file
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
