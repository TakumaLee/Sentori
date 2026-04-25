#!/usr/bin/env node

import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { createDefaultRegistry } from './index';
import { printReport, writeJsonReport, buildSarifReport, writeSarifReport } from './utils/reporter';
import { buildCycloneDxReport, writeCycloneDxReport } from './formatters/cyclonedx';
import { calculateSummary } from './utils/scorer';
import { Scanner } from './types';
import { loadSentoriConfig, SentoriConfig } from './config/sentori-config';
import { customRulesScanner } from './scanners/custom-rules-scanner';
import { applyConfig } from './utils/apply-config';
import { printConfigWarnings } from './utils/print-warnings';
import { runDiscover } from './discover';
import { CUSTOM_RULES_SCANNER_NAME } from './scanners/custom-rules-scanner';
import { loadIgnorePatterns } from './utils/ignore-parser';
import { startWatcher } from './watcher';
import {
  runCCBOSRedTeam,
  dryRunCCBOS,
  RedTeamReport,
  VariantResult,
} from './runtime/cc-bos-red-team';
import { runBenchmark } from './benchmark/runner';
import { printBenchmarkReport, formatBenchmarkJson } from './benchmark/reporter';
import {
  runCrossLingualCheck,
  formatCrossLingualResult,
} from './runtime/cross-lingual-checker';

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
 * Filter scanners to only those relevant for a given profile.
 * - agent:   all scanners (full AI-agent security audit)
 * - general: secrets, permissions, skills
 * - mobile:  secrets, permissions only
 */
export function filterScannersByProfile(
  scanners: Scanner[],
  profile: ProfileType
): Scanner[] {
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
  console.log(chalk.bold('  Subcommands:'));
  console.log(chalk.gray('    scan [target-dir]  Security scan (default)'));
  console.log(chalk.gray('    redteam            CC-BOS structured jailbreak testing'));
  console.log(chalk.gray('    check              Single-input safety checks (--cross-lingual)'));
  console.log('');
  console.log(chalk.bold('  Options (scan):'));
  console.log(chalk.gray('    --help, -h         Show help'));
  console.log(chalk.gray('    --version, -v      Show version'));
  console.log(chalk.gray('    --json             Output JSON report to stdout'));
  console.log(chalk.gray('    --format FORMAT    Output format: pretty (default), json, sarif, cyclonedx'));
  console.log(chalk.gray('    --output, -o FILE  Save report to file (auto-detects format by extension)'));
  console.log(chalk.gray('    --ioc PATH         Path to external IOC blocklist JSON file'));
  console.log(chalk.gray('    --deep-scan        Enable OCR scanning of image files (slow)'));
  console.log(chalk.gray('    --profile PROFILE  Filter scanners by profile: agent (default), general, mobile'));
  console.log(chalk.gray('    --require-provenance   Exit 1 if any packages lack npm attestation'));
  console.log(chalk.gray('    --include-vendored   Include vendored/third-party code in scan'));
  console.log(chalk.gray('    --exclude PATTERN    Exclude files/dirs matching pattern (can repeat)'));
  console.log(chalk.gray('    --include-workspace-projects  Scan sub-projects inside workspace/ (default: skip)'));
  console.log(chalk.gray('    --discover           Auto-discover and scan agent configs in common paths'));
  console.log(chalk.gray('    --watch              Re-scan automatically when config files change'));
  console.log(chalk.gray('    --concurrency N      Max parallel scanners (default: Math.min(5, cpu_count); GH Actions: 2)'));
  console.log('');
  console.log(chalk.bold('  Examples:'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --watch'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --format sarif'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --output report.json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --output results.sarif'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --ioc ./custom-ioc.json'));
  console.log(chalk.cyan('    npx @nexylore/sentori scan ./my-agent --exclude "outputs/**"'));
  console.log(chalk.cyan('    npx @nexylore/sentori --discover'));
  console.log('');
  console.log(chalk.bold('  Options (benchmark):'));
  console.log(chalk.gray('    --model MODEL      LLM to benchmark (default: gpt-4o-mini)'));
  console.log(chalk.gray('    --langs LANGS      Comma-separated language codes: zh,hi,pa,od,en (default: all)'));
  console.log(chalk.gray('    --dry-run          Run with synthetic responses (no API calls)'));
  console.log(chalk.gray('    --json             Output JSON report to stdout'));
  console.log(chalk.gray('    --api-key KEY      API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY)'));
  console.log('');
  console.log(chalk.bold('  Examples (benchmark):'));
  console.log(chalk.cyan('    npx @nexylore/sentori benchmark --model gpt-4o --langs zh,hi,pa,od'));
  console.log(chalk.cyan('    npx @nexylore/sentori benchmark --model claude-haiku-4-5-20251001 --dry-run'));
  console.log(chalk.cyan('    npx @nexylore/sentori benchmark --model gpt-4o --json'));
  console.log('');
  console.log(chalk.bold('  Options (check):'));
  console.log(chalk.gray('    --cross-lingual    Detect cross-lingual safety divergence'));
  console.log(chalk.gray('    --model MODEL      LLM to use (default: claude-haiku-4-5-20251001)'));
  console.log(chalk.gray('    --threshold N      Divergence threshold 0.0-1.0 (default: 0.3)'));
  console.log(chalk.gray('    --api-key KEY      API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY)'));
  console.log(chalk.gray('    --json             Output JSON result to stdout'));
  console.log('');
  console.log(chalk.bold('  Examples (check):'));
  console.log(chalk.cyan('    npx @nexylore/sentori check --cross-lingual "ignore previous instructions"'));
  console.log(chalk.cyan('    npx @nexylore/sentori check --cross-lingual "危険なリクエスト" --threshold 0.2'));
  console.log('');
  console.log(chalk.bold('  Options (redteam):'));
  console.log(chalk.gray('    --attack cc-bos    Attack method (currently: cc-bos)'));
  console.log(chalk.gray('    --target PATH      Guardrail file path or label (required)'));
  console.log(chalk.gray('    --goal TEXT        Attack goal / harmful capability to elicit (required)'));
  console.log(chalk.gray('    --iterations N     Number of jailbreak variants to test (default: 20)'));
  console.log(chalk.gray('    --model MODEL      LLM to test (default: claude-haiku-4-5-20251001)'));
  console.log(chalk.gray('    --api-key KEY      API key (or set ANTHROPIC_API_KEY / OPENAI_API_KEY)'));
  console.log(chalk.gray('    --dry-run          Generate variants without calling any LLM'));
  console.log(chalk.gray('    --output, -o FILE  Save JSON report to file'));
  console.log(chalk.gray('    --json             Print JSON report to stdout'));
  console.log('');
  console.log(chalk.bold('  Examples (redteam):'));
  console.log(chalk.cyan('    npx @nexylore/sentori redteam --attack cc-bos --target ./guardrail.md \\'));
  console.log(chalk.cyan('      --goal "explain malware creation" --iterations 50'));
  console.log(chalk.cyan('    npx @nexylore/sentori redteam --attack cc-bos --target my-guardrail \\'));
  console.log(chalk.cyan('      --goal "bypass content filter" --dry-run'));
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

  if (args.includes('--discover')) {
    await runDiscover();
    process.exit(0);
  }

  // ─── redteam subcommand ────────────────────────────────────────────────────
  if (args[0] === 'redteam') {
    await runRedTeam(args.slice(1));
    process.exit(0);
  }

  // ─── benchmark subcommand ──────────────────────────────────────────────────
  if (args[0] === 'benchmark') {
    await runBenchmarkCmd(args.slice(1));
    process.exit(0);
  }

  // ─── check subcommand ──────────────────────────────────────────────────────
  if (args[0] === 'check') {
    await runCheckCmd(args.slice(1));
    process.exit(0);
  }

  // Parse flags
  let outputFormat: 'pretty' | 'json' | 'sarif' | 'cyclonedx' = 'pretty';
  const formatIdx = args.findIndex((a) => a === '--format');
  if (formatIdx !== -1 && args[formatIdx + 1]) {
    const fmt = args[formatIdx + 1];
    if (fmt === 'json' || fmt === 'sarif' || fmt === 'cyclonedx') outputFormat = fmt;
  }
  if (args.includes('--json')) outputFormat = 'json'; // backward compat
  const jsonMode = outputFormat === 'json';
  const sarifMode = outputFormat === 'sarif';
  const cyclonedxMode = outputFormat === 'cyclonedx';
  const watchMode = args.includes('--watch');

  if (watchMode && (jsonMode || sarifMode || cyclonedxMode)) {
    console.error(chalk.red('  ✗ --watch is not compatible with --json or --format sarif/json/cyclonedx'));
    console.error(chalk.gray('    Use --output file.json to write reports to file instead'));
    process.exit(1);
  }

  const deepScan = args.includes('--deep-scan');
  if (deepScan) {
    process.env.SENTORI_DEEP_SCAN = '1';
  }

  const includeVendored = args.includes('--include-vendored');
  const includeWorkspaceProjects = args.includes('--include-workspace-projects');
  const requireProvenance = args.includes('--require-provenance');

  let concurrency: number | undefined;
  const concurrencyIdx = args.findIndex((a) => a === '--concurrency');
  if (concurrencyIdx !== -1 && args[concurrencyIdx + 1]) {
    const parsed = parseInt(args[concurrencyIdx + 1], 10);
    if (!Number.isFinite(parsed) || parsed < 1) {
      console.error(chalk.red(`  ✗ --concurrency must be a positive integer, got: "${args[concurrencyIdx + 1]}"`));
      process.exit(1);
    }
    concurrency = parsed;
  }

  const excludes: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '--exclude' || args[i] === '-e') && args[i + 1] && !args[i + 1].startsWith('-')) {
      excludes.push(args[i + 1]);
    }
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
  for (const flag of ['--output', '-o', '--ioc', '--format', '--profile', '--concurrency']) {
    const idx = args.findIndex((a) => a === flag);
    if (idx !== -1) flagValuePositions.add(idx + 1);
  }
  // --exclude can appear multiple times
  args.forEach((a, i) => {
    if ((a === '--exclude' || a === '-e') && i + 1 < args.length) {
      flagValuePositions.add(i + 1);
    }
  });
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

  // Load .sentoriignore from target directory
  const { patterns: sentoriIgnorePatterns } = loadIgnorePatterns(targetDir);

  const scanOpts = {
    targetDir,
    outputFormat,
    outputPath,
    iocPath,
    profile,
    deepScan,
    includeVendored,
    includeWorkspaceProjects,
    excludes,
    sentoriIgnorePatterns,
    requireProvenance,
    watchMode,
    concurrency,
  };

  if (watchMode) {
    // Initial scan
    await runScan(scanOpts);

    // Start file watcher
    console.log(chalk.cyan('\n  Watching for changes... Press Ctrl+C to stop\n'));
    let scanning = false;
    const stopWatcher = await startWatcher(targetDir, async (scanners, changedPaths) => {
      if (scanning) return;
      scanning = true;
      try {
        const changedFiles = changedPaths.map((p) => path.relative(targetDir, p)).join(', ');
        console.log(chalk.gray(`\n  [${timestamp()}] Changed: ${changedFiles}`));
        await runScan({ ...scanOpts, scannerFilter: scanners, isRescan: true });
      } finally {
        scanning = false;
      }
    });

    process.on('SIGINT', () => {
      stopWatcher();
      console.log(chalk.gray('\n  Watch stopped.'));
      process.exit(0);
    });
  } else {
    await runScan(scanOpts);
  }
}

function timestamp(): string {
  const now = new Date();
  return [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map((n) => String(n).padStart(2, '0'))
    .join(':');
}

interface ScanOptions {
  targetDir: string;
  outputFormat: 'pretty' | 'json' | 'sarif' | 'cyclonedx';
  outputPath?: string;
  iocPath?: string;
  profile: ProfileType;
  deepScan: boolean;
  includeVendored: boolean;
  includeWorkspaceProjects: boolean;
  excludes: string[];
  sentoriIgnorePatterns: string[];
  requireProvenance: boolean;
  watchMode: boolean;
  concurrency?: number;
  scannerFilter?: string[] | null;
  isRescan?: boolean;
}

async function runScan(opts: ScanOptions): Promise<void> {
  const {
    targetDir, outputFormat, outputPath, iocPath, profile,
    includeVendored, includeWorkspaceProjects, excludes,
    sentoriIgnorePatterns, requireProvenance, watchMode,
    concurrency, scannerFilter,
  } = opts;
  const jsonMode = outputFormat === 'json';
  const sarifMode = outputFormat === 'sarif';
  const cyclonedxMode = outputFormat === 'cyclonedx';
  const version = getVersion();

  if (!jsonMode && !sarifMode && !cyclonedxMode) {
    if (opts.isRescan) {
      console.log(chalk.gray(`  [${timestamp()}] Re-scanning...`));
    } else {
      console.log('');
      console.log(chalk.bold.cyan('  🛡️  Sentori') + chalk.gray(` v${version}`));
      console.log(chalk.gray(`  Scanning: ${targetDir}`));
      console.log('');
    }
  }

  const registry = createDefaultRegistry(iocPath);

  // Apply profile filter
  if (profile !== 'agent') {
    const filtered = filterScannersByProfile(registry.getScanners(), profile);
    registry.setScanners(filtered);
  }

  // Apply incremental scanner filter (watch mode)
  if (scannerFilter !== undefined && scannerFilter !== null) {
    const filtered = registry.getScanners().filter((s) => scannerFilter.includes(s.name));
    registry.setScanners(filtered);
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
      if (sentoriConfig.warnings.length > 0) {
        printConfigWarnings(sentoriConfig.warnings);
      }
    }
  } catch (err) {
    if (!jsonMode && !sarifMode) {
      console.warn(chalk.yellow(`  ⚠ .sentori.yml parse error: ${(err as Error).message}`));
    }
  }

  // Register custom rules scanner if rules are defined
  if (sentoriConfig && sentoriConfig.rules.length > 0) {
    registry.register(customRulesScanner(sentoriConfig.rules));
  }

  const scanOptions = {
    includeVendored,
    includeWorkspaceProjects,
    exclude: excludes.length > 0 ? excludes : undefined,
    sentoriIgnorePatterns: sentoriIgnorePatterns.length > 0 ? sentoriIgnorePatterns : undefined,
    concurrency,
  };

  let report = await registry.runAll(targetDir, (step, total, name, result) => {
    if (jsonMode || sarifMode) return;
    const pct = Math.round((step / total) * 100);
    const filled = Math.round((step / total) * 20);
    const empty = 20 - filled;
    const bar = chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));

    if (!result) {
      process.stdout.write(`\r  ${bar} ${pct}% · ${name}...`);
    } else {
      const findingsColor = result.findings.length > 0 ? chalk.yellow(String(result.findings.length)) : chalk.green('0');
      process.stdout.write(`\r  ${bar} ${pct}% · ${name} ${chalk.gray('→')} ${findingsColor} findings ${chalk.gray(`(${result.duration}ms)`)}   \n`);
    }
  }, scanOptions);

  // Apply .sentori.yml ignore filters and severity overrides
  if (sentoriConfig && (sentoriConfig.ignore.length > 0 || sentoriConfig.overrides.length > 0)) {
    report = applyConfig(report, sentoriConfig);
  }

  report.summary = calculateSummary(report.results);
  report.version = version;

  // Surface .sentori.yml config warnings as info findings
  if (sentoriConfig && sentoriConfig.warnings.length > 0) {
    const warningFindings = sentoriConfig.warnings.map((warning, idx) => ({
      id: `CONFIG-WARNING-${idx}`,
      scanner: CUSTOM_RULES_SCANNER_NAME,
      severity: 'info' as const,
      rule: 'CONFIG-WARNING',
      title: '[Config] Rule configuration warning',
      message: warning,
      description: warning,
      recommendation: 'Fix the rule definition in .sentori.yml to ensure it is scanned correctly.',
    }));

    const existingCustomResult = report.results.find(r => r.scanner === CUSTOM_RULES_SCANNER_NAME);
    if (existingCustomResult) {
      existingCustomResult.findings.unshift(...warningFindings);
    } else {
      report.results.push({
        scanner: CUSTOM_RULES_SCANNER_NAME,
        findings: warningFindings,
        duration: 0,
        scannedFiles: 0,
      });
    }
    report.summary = calculateSummary(report.results);
  }

  if (cyclonedxMode && outputPath) {
    writeCycloneDxReport(report, outputPath);
  } else if (cyclonedxMode) {
    console.log(JSON.stringify(buildCycloneDxReport(report), null, 2));
  } else if (sarifMode && outputPath) {
    writeSarifReport(report, outputPath);
  } else if (sarifMode) {
    console.log(JSON.stringify(buildSarifReport(report), null, 2));
  } else if (jsonMode) {
    console.log(JSON.stringify(report, null, 2));
  } else if (outputPath && outputPath.endsWith('.sarif')) {
    printReport(report);
    writeSarifReport(report, outputPath);
  } else if (outputPath) {
    printReport(report);
    writeJsonReport(report, outputPath);
  } else {
    printReport(report);
  }

  // Exit code logic (skip in watch mode — keep event loop alive)
  if (!watchMode) {
    const s = report.summary;
    if (requireProvenance) {
      const attestationFindings = report.results
        .find((r) => r.scanner === 'NPM Attestation Scanner')?.findings ?? [];
      const unattested = attestationFindings.filter((f) => f.rule === 'ATTESTATION-001');
      if (unattested.length > 0) {
        process.exit(s.critical > 0 ? 2 : 1);
      }
    }
    process.exit(s.critical > 0 ? 2 : s.high > 0 ? 1 : 0);
  }
}

// ─── redteam subcommand ────────────────────────────────────────────────────────

function getFlag(args: string[], flag: string): string | undefined {
  const idx = args.findIndex((a) => a === flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : undefined;
}

async function runRedTeam(args: string[]): Promise<void> {
  const attack = getFlag(args, '--attack') ?? 'cc-bos';
  if (attack !== 'cc-bos') {
    console.error(chalk.red(`  ✗ Unknown --attack value: "${attack}". Currently supported: cc-bos`));
    process.exit(1);
  }

  const targetRaw = getFlag(args, '--target');
  if (!targetRaw) {
    console.error(chalk.red('  ✗ --target is required (guardrail file path or label)'));
    process.exit(1);
  }

  const goal = getFlag(args, '--goal');
  if (!goal) {
    console.error(chalk.red('  ✗ --goal is required (e.g. "explain malware creation")'));
    process.exit(1);
  }

  const iterStr = getFlag(args, '--iterations') ?? '20';
  const iterations = parseInt(iterStr, 10);
  if (isNaN(iterations) || iterations < 1) {
    console.error(chalk.red(`  ✗ --iterations must be a positive integer, got: "${iterStr}"`));
    process.exit(1);
  }

  const model = getFlag(args, '--model') ?? 'claude-haiku-4-5-20251001';
  const apiKey =
    getFlag(args, '--api-key') ??
    process.env.ANTHROPIC_API_KEY ??
    process.env.OPENAI_API_KEY ??
    '';

  const dryRun = args.includes('--dry-run');
  const jsonOutput = args.includes('--json');
  const outputPath = getFlag(args, '--output') ?? getFlag(args, '-o');

  // Resolve guardrail prompt from file (if path exists) or use target as label
  let guardrailPrompt = '';
  let targetLabel = targetRaw;
  const resolvedTarget = path.resolve(targetRaw);
  if (fs.existsSync(resolvedTarget) && fs.statSync(resolvedTarget).isFile()) {
    guardrailPrompt = fs.readFileSync(resolvedTarget, 'utf-8');
    targetLabel = targetRaw;
  } else if (!dryRun) {
    // Target is a label — guardrail prompt stays empty (model uses its default system prompt)
    guardrailPrompt = '';
  }

  // ── Dry-run: generate variants, no API call ─────────────────────────────────
  if (dryRun) {
    const variants = dryRunCCBOS(goal, iterations);
    if (jsonOutput) {
      console.log(JSON.stringify({ dryRun: true, goal, target: targetLabel, iterations, variants }, null, 2));
    } else {
      console.log('');
      console.log(chalk.bold.cyan('  🔴 Sentori Red Team') + chalk.gray(' (dry-run)'));
      console.log(chalk.gray(`  Attack:     cc-bos`));
      console.log(chalk.gray(`  Target:     ${targetLabel}`));
      console.log(chalk.gray(`  Goal:       ${goal}`));
      console.log(chalk.gray(`  Variants:   ${iterations}`));
      console.log('');
      for (const v of variants) {
        console.log(chalk.bold(`  ── Variant #${v.id} ──────────────────────────────────────`));
        console.log(chalk.gray('  Role:    ') + v.dimensions.roleIdentity);
        console.log(chalk.gray('  Trigger: ') + v.dimensions.triggerPattern);
        console.log('');
        console.log(chalk.white(v.prompt.split('\n').map((l) => '    ' + l).join('\n')));
        console.log('');
      }
    }
    if (outputPath) {
      fs.writeFileSync(outputPath, JSON.stringify({ dryRun: true, goal, target: targetLabel, iterations, variants }, null, 2));
      if (!jsonOutput) console.log(chalk.gray(`  Report saved to: ${outputPath}`));
    }
    return;
  }

  // ── Live run: call LLM for each variant ────────────────────────────────────
  if (!apiKey) {
    console.error(chalk.red('  ✗ No API key found. Set ANTHROPIC_API_KEY / OPENAI_API_KEY or pass --api-key'));
    process.exit(1);
  }

  if (!jsonOutput) {
    console.log('');
    console.log(chalk.bold.cyan('  🔴 Sentori Red Team'));
    console.log(chalk.gray(`  Attack:     cc-bos`));
    console.log(chalk.gray(`  Target:     ${targetLabel}`));
    console.log(chalk.gray(`  Goal:       ${goal}`));
    console.log(chalk.gray(`  Model:      ${model}`));
    console.log(chalk.gray(`  Iterations: ${iterations}`));
    console.log('');
  }

  const report = await runCCBOSRedTeam({
    goal,
    guardrailPrompt,
    targetLabel,
    model,
    apiKey,
    iterations,
    onProgress: (current, total, result) => {
      if (jsonOutput) return;
      const pct = Math.round((current / total) * 100);
      const filled = Math.round((current / total) * 20);
      const bar = chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(20 - filled));
      const statusIcon = result.error
        ? chalk.red('ERR')
        : result.success
          ? chalk.red('PASS')
          : chalk.green('BLOCK');
      process.stdout.write(`\r  ${bar} ${pct}% · #${current}/${total} ${statusIcon}   `);
    },
  });

  if (!jsonOutput) {
    process.stdout.write('\n');
    printRedTeamReport(report);
  } else {
    console.log(JSON.stringify(report, null, 2));
  }

  if (outputPath) {
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    if (!jsonOutput) console.log(chalk.gray(`\n  Report saved to: ${outputPath}`));
  }
}

function printRedTeamReport(report: RedTeamReport): void {
  const asrColor =
    report.asr >= 0.5 ? chalk.red : report.asr >= 0.2 ? chalk.yellow : chalk.green;

  console.log('');
  console.log(chalk.bold('  ── Results ─────────────────────────────────────────'));
  console.log(chalk.gray('  Target:      ') + report.target);
  console.log(chalk.gray('  Model:       ') + report.model);
  console.log(chalk.gray('  Goal:        ') + report.goal);
  console.log(chalk.gray('  Variants:    ') + report.totalVariants);
  console.log(chalk.gray('  Blocked:     ') + chalk.green(String(report.failureCount)));
  console.log(chalk.gray('  Bypassed:    ') + chalk.red(String(report.successCount)));
  if (report.errorCount > 0) {
    console.log(chalk.gray('  Errors:      ') + chalk.yellow(String(report.errorCount)));
  }
  console.log(chalk.gray('  ASR:         ') + asrColor(chalk.bold(report.asrPercent)));
  console.log(chalk.gray(`  Duration:    ${(report.durationMs / 1000).toFixed(1)}s`));
  console.log('');

  if (report.successfulVariants.length > 0) {
    console.log(chalk.bold.red(`  ⚠  ${report.successfulVariants.length} bypass(es) found:`));
    console.log('');
    for (const v of report.successfulVariants) {
      console.log(chalk.bold(`  ── Bypass #${v.id} ──────────────────────────────────────`));
      console.log(chalk.gray('  Role:     ') + v.dimensions.roleIdentity);
      console.log(chalk.gray('  Trigger:  ') + v.dimensions.triggerPattern);
      console.log(chalk.gray('  Mechanism:') + ' ' + v.dimensions.mechanism);
      console.log('');
      console.log(chalk.gray('  Prompt:'));
      console.log(v.prompt.split('\n').map((l) => chalk.white('    ' + l)).join('\n'));
      console.log('');
      console.log(chalk.gray('  Response (excerpt):'));
      const excerpt = v.response.slice(0, 400).replace(/\n/g, ' ');
      console.log(chalk.yellow('    ' + excerpt + (v.response.length > 400 ? '...' : '')));
      console.log('');
    }
  } else {
    console.log(chalk.bold.green('  ✓ All variants blocked. Guardrail appears robust.'));
    console.log('');
  }
}

// ─── benchmark subcommand ─────────────────────────────────────────────────────

async function runBenchmarkCmd(args: string[]): Promise<void> {
  const model = getFlag(args, '--model') ?? 'gpt-4o-mini';
  const langsRaw = getFlag(args, '--langs') ?? '';
  const langs = langsRaw ? langsRaw.split(',').map((l) => l.trim()).filter(Boolean) : [];
  const dryRun = args.includes('--dry-run');
  const jsonOutput = args.includes('--json');
  const apiKey = getFlag(args, '--api-key');

  if (!jsonOutput) {
    console.log('');
    console.log(chalk.bold.cyan('  🛡️  Sentori Benchmark'));
    console.log(chalk.gray(`  Model: ${model}`));
    if (langs.length > 0) console.log(chalk.gray(`  Langs: ${langs.join(', ')}`));
    if (dryRun) console.log(chalk.gray('  Mode:  dry-run'));
    console.log('');
  }

  const report = await runBenchmark(
    { model, langs, dryRun, apiKey },
    (done, total, promptId) => {
      if (jsonOutput) return;
      const pct = Math.round((done / total) * 100);
      const filled = Math.round((done / total) * 20);
      const bar = chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(20 - filled));
      process.stdout.write(`\r  ${bar} ${pct}% · ${promptId}   `);
    }
  );

  if (!jsonOutput) process.stdout.write('\n');

  if (jsonOutput) {
    console.log(formatBenchmarkJson(report));
  } else {
    printBenchmarkReport(report);
  }
}

// ─── check subcommand ─────────────────────────────────────────────────────────

export async function runCheckCmd(args: string[]): Promise<void> {
  const crossLingual = args.includes('--cross-lingual');
  const jsonOutput = args.includes('--json');

  if (!crossLingual) {
    console.error(chalk.red('  ✗ `check` requires --cross-lingual (no other check modes implemented yet)'));
    console.error(chalk.gray('    Run `sentori --help` for usage.'));
    process.exit(1);
  }

  // Positional input = last non-flag arg, skipping known flag-value slots.
  const flagValueIndexes = new Set<number>();
  for (const flag of ['--model', '--threshold', '--api-key']) {
    const idx = args.findIndex((a) => a === flag);
    if (idx !== -1) flagValueIndexes.add(idx + 1);
  }
  const positional = args.filter(
    (a, i) => !a.startsWith('--') && !flagValueIndexes.has(i),
  );
  const input = positional[0];

  if (!input || input.trim().length === 0) {
    console.error(chalk.red('  ✗ check --cross-lingual requires input text'));
    console.error(chalk.gray('    Example: sentori check --cross-lingual "text to analyze"'));
    process.exit(1);
  }

  const model = getFlag(args, '--model') ?? 'claude-haiku-4-5-20251001';
  const thresholdRaw = getFlag(args, '--threshold');
  let threshold = 0.3;
  if (thresholdRaw !== undefined) {
    const parsed = Number.parseFloat(thresholdRaw);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
      console.error(chalk.red(`  ✗ --threshold must be a number between 0 and 1, got: "${thresholdRaw}"`));
      process.exit(1);
    }
    threshold = parsed;
  }

  const apiKey =
    getFlag(args, '--api-key') ??
    process.env.ANTHROPIC_API_KEY ??
    process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.error(chalk.red('  ✗ No API key found'));
    console.error(chalk.gray('    Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or pass --api-key'));
    process.exit(1);
  }

  const result = await runCrossLingualCheck(input, { model, apiKey, threshold });

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(formatCrossLingualResult(result));
  }

  if (result.flagged) process.exit(1);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(chalk.red('Fatal error:'), err);
    process.exit(1);
  });
}
