import * as fs from 'fs';
import * as path from 'path';
import chalk from 'chalk';
import { ScanReport, Finding, Severity } from '../types';

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  info: '🔵',
};

const SEVERITY_COLORS: Record<Severity, (text: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.hex('#FF8C00').bold,
  medium: chalk.yellow,
  info: chalk.blue,
};

const DIVIDER = chalk.cyan('  ' + '━'.repeat(54));

/**
 * Normalize a finding to ensure title/description/recommendation are populated,
 * even if the scanner used the legacy rule/message/evidence fields.
 */
function normalizeFinding(f: Finding): Finding {
  return {
    ...f,
    title: f.title || f.rule || f.message || 'Unknown',
    description: f.description || f.message || f.evidence || '',
    recommendation: f.recommendation || f.evidence || 'Review this finding.',
  };
}

/**
 * Render an ASCII progress bar colored by score.
 */
function progressBar(score: number, width = 10): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const color =
    score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
  return color('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
}

export function printReport(report: ScanReport): void {
  const s = report.summary!;

  console.log('');
  console.log(DIVIDER);
  console.log(
    chalk.bold.cyan('  🛡️  Sentori') +
    chalk.gray(` v${report.version ?? ''}`) +
    chalk.gray('  Security Report')
  );
  console.log(DIVIDER);
  console.log(chalk.gray(`  Target:    ${report.target}`));
  console.log(chalk.gray(`  Timestamp: ${report.timestamp}`));
  console.log(chalk.gray(`  Scanners:  ${report.results.length} active`));
  console.log(DIVIDER);
  console.log('');

  if (s.totalFindings === 0) {
    console.log(chalk.green.bold('  ✅ No vulnerabilities found! Your agent looks secure.'));
    console.log('');
  } else {
    // Per-scanner findings
    for (const result of report.results) {
      if (result.findings.length === 0) continue;

      const filesCount = result.scannedFiles;
      console.log(
        chalk.bold.white(`  ── ${result.scanner} ──`) +
        chalk.gray(` (${filesCount} files, ${result.duration}ms)`)
      );
      console.log('');

      for (const finding of result.findings) {
        printFinding(normalizeFinding(finding));
      }
    }
  }

  printSummaryBar(report);
}

function printFinding(finding: Finding): void {
  const icon = SEVERITY_ICONS[finding.severity];
  const colorFn = SEVERITY_COLORS[finding.severity];
  const sevLabel = colorFn(finding.severity.toUpperCase().padEnd(8));

  console.log(`  ${icon} ${sevLabel} ${chalk.white.bold(finding.title ?? '')}`);
  if (finding.description) {
    console.log(chalk.gray(`     ${finding.description}`));
  }
  if (finding.file) {
    const loc = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    console.log(chalk.gray(`     📁 ${loc}`));
  }
  if (finding.recommendation) {
    console.log(chalk.green(`     💡 ${finding.recommendation}`));
  }
  console.log('');
}

function printSummaryBar(report: ScanReport): void {
  const s = report.summary!;

  console.log(DIVIDER);
  console.log('');

  const gradeColor =
    s.score >= 80
      ? chalk.green.bold
      : s.score >= 60
      ? chalk.yellow.bold
      : chalk.red.bold;

  console.log(
    `  ${chalk.bold('Security Grade:')} ${gradeColor(s.grade)} ${chalk.gray(`(${s.score}/100)`)}`
  );
  console.log('');

  // One-line findings count (npm audit style)
  if (s.totalFindings === 0) {
    console.log(`  ${chalk.green('found 0 vulnerabilities')}`);
  } else {
    const parts = [
      s.critical > 0 ? `${SEVERITY_ICONS.critical} ${s.critical} critical` : null,
      s.high > 0 ? `${SEVERITY_ICONS.high} ${s.high} high` : null,
      s.medium > 0 ? `${SEVERITY_ICONS.medium} ${s.medium} medium` : null,
      s.info > 0 ? `${SEVERITY_ICONS.info} ${s.info} info` : null,
    ].filter(Boolean);
    const label = s.totalFindings === 1 ? 'vulnerability' : 'vulnerabilities';
    console.log(`  found ${chalk.bold(String(s.totalFindings))} ${label} (${parts.join('  ')})`);
  }
  console.log('');

  const durationSec = (s.duration / 1000).toFixed(1);
  console.log(
    chalk.gray(`  ⏱️  Completed in ${durationSec}s  |  ${s.scannedFiles} files scanned`)
  );
  console.log('');

  if (s.critical > 0) {
    console.log(chalk.red.bold('  ⚠️  CRITICAL issues found! Address these immediately.'));
  } else if (s.high > 0) {
    console.log(chalk.hex('#FF8C00')('  ⚠️  High severity issues require attention.'));
  } else if (s.medium > 0) {
    console.log(chalk.yellow('  ⚠️  Medium severity issues found. Review when possible.'));
  } else if (s.score >= 90) {
    console.log(chalk.green('  ✨ Great security posture! Keep it up.'));
  }

  console.log('');
  console.log(DIVIDER);
  console.log('');
}

// ─── SARIF 2.1.0 output ──────────────────────────────────────────────────────

function toSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function toRuleId(f: Finding): string {
  if (f.id) return f.id;
  const scanner = f.scanner.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase();
  const title = (f.title || f.rule || 'UNKNOWN').replace(/[^a-zA-Z0-9]/g, '-').toUpperCase();
  return `${scanner}/${title}`.slice(0, 64);
}

export function buildSarifReport(report: ScanReport): object {
  const version = report.version ?? '0.0.0';

  const allFindings: Finding[] = [];
  for (const result of report.results) {
    for (const f of result.findings) {
      allFindings.push(normalizeFinding(f));
    }
  }

  // Deduplicated rules map
  const rulesMap = new Map<string, object>();
  for (const f of allFindings) {
    const ruleId = toRuleId(f);
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: (f.title ?? 'Unknown').replace(/\s+/g, ''),
        shortDescription: { text: f.title ?? 'Unknown' },
        fullDescription: { text: f.description || f.title || 'Unknown' },
        defaultConfiguration: { level: toSarifLevel(f.severity) },
        ...(f.recommendation ? { help: { text: f.recommendation } } : {}),
      });
    }
  }

  const results = allFindings.map((f) => {
    const entry: Record<string, unknown> = {
      ruleId: toRuleId(f),
      level: toSarifLevel(f.severity),
      message: { text: f.description || f.title || 'Security finding detected' },
    };
    if (f.file) {
      entry.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file.replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' },
            ...(f.line ? { region: { startLine: f.line } } : {}),
          },
        },
      ];
    }
    return entry;
  });

  const fileSet = new Set<string>();
  for (const f of allFindings) {
    if (f.file) fileSet.add(f.file.replace(/\\/g, '/'));
  }
  const artifacts = Array.from(fileSet).map((uri) => ({
    location: { uri, uriBaseId: '%SRCROOT%' },
  }));

  return {
    version: '2.1.0',
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentori',
            version,
            informationUri: 'https://www.npmjs.com/package/@nexylore/sentori',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
        artifacts,
        invocations: [
          {
            executionSuccessful: true,
            commandLine: `sentori scan ${report.target}`,
          },
        ],
      },
    ],
  };
}

export function writeSarifReport(report: ScanReport, outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(buildSarifReport(report), null, 2), 'utf-8');
  console.log(chalk.gray(`  📄 SARIF report saved to: ${outputPath}`));
  console.log('');
}

export function writeJsonReport(report: ScanReport, outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
  console.log(chalk.gray(`  📄 JSON report saved to: ${outputPath}`));
  console.log('');
}
