import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import chalk from 'chalk';
import { ScanReport, Finding } from '../types';

function normalizeFinding(f: Finding): Finding {
  return {
    ...f,
    title: f.title || f.rule || f.message || 'Unknown',
    description: f.description || f.message || f.evidence || '',
    recommendation: f.recommendation || f.evidence || 'Review this finding.',
  };
}

function toCdxSeverity(severity: string): string {
  const map: Record<string, string> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    info: 'info',
  };
  return map[severity] ?? 'unknown';
}

function generateVulnId(f: Finding): string {
  if (f.id) return f.id;
  const scanner = (f.scanner ?? 'UNKNOWN').toUpperCase().replace(/[^A-Z0-9]/g, '-');
  const raw = (f.scanner ?? '') + (f.title ?? '') + (f.file ?? '') + String(f.line ?? '');
  const hash = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 8);
  return `SENTORI-${scanner}-${hash}`;
}

export function buildCycloneDxReport(report: ScanReport): object {
  const version = report.version ?? '0.0.0';
  const targetName = path.basename(report.target) || report.target;
  const targetBomRef = 'target-project';
  const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

  const allFindings: Finding[] = [];
  for (const result of report.results) {
    for (const f of result.findings) {
      allFindings.push(normalizeFinding(f));
    }
  }

  const vulnerabilities = allFindings.map((f) => {
    const vulnId = generateVulnId(f);
    const bomRef = `vuln-${crypto.randomUUID()}`;
    const location = f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : undefined;

    const analysis: Record<string, string> = {
      state: f.isTestFile ? 'not_affected' : 'in_triage',
      detail: f.isTestFile
        ? 'Finding is in a test file; not affected in production.'
        : 'Detected by automated scanner. Manual review pending.',
    };
    if (f.isTestFile) {
      analysis.justification = 'test_code';
    }

    const properties: Array<{ name: string; value: string }> = [
      { name: 'sentori:scanner', value: f.scanner },
      { name: 'sentori:title', value: f.title },
    ];
    if (f.rule) properties.push({ name: 'sentori:rule', value: f.rule });
    if (f.confidence) properties.push({ name: 'sentori:confidence', value: f.confidence });
    if (location) properties.push({ name: 'sentori:location', value: location });
    properties.push({ name: 'sentori:isTestFile', value: String(!!f.isTestFile) });
    properties.push({ name: 'sentori:isThirdParty', value: String(!!f.isThirdParty) });

    const vuln: Record<string, unknown> = {
      'bom-ref': bomRef,
      id: vulnId,
      source: {
        name: `Sentori / ${f.scanner}`,
        url: 'https://www.npmjs.com/package/@nexylore/sentori',
      },
      ratings: [
        {
          source: { name: 'Sentori' },
          severity: toCdxSeverity(f.severity),
          method: 'other',
          justification: `Detected by automated scanner: ${f.scanner}`,
        },
      ],
      description: f.description,
      analysis,
      affects: [
        {
          ref: targetBomRef,
          versions: [{ version, status: 'affected' }],
        },
      ],
      properties,
    };

    // TODO: CWE mapping — requires rule-to-cwe.ts lookup table (future PR)

    if (f.evidence) vuln.detail = f.evidence;
    if (f.recommendation) vuln.recommendation = f.recommendation;

    return vuln;
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    serialNumber,
    metadata: {
      timestamp: report.timestamp,
      tools: [
        {
          vendor: 'Nexylore',
          name: 'Sentori',
          version,
        },
      ],
      component: {
        type: 'application',
        'bom-ref': targetBomRef,
        name: targetName,
        version: '0.0.0',
      },
    },
    components: [
      {
        type: 'application',
        'bom-ref': targetBomRef,
        name: targetName,
        version: '0.0.0',
        description: 'AI agent being scanned by Sentori',
      },
    ],
    vulnerabilities,
  };
}

export function writeCycloneDxReport(report: ScanReport, outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(outputPath, JSON.stringify(buildCycloneDxReport(report), null, 2), 'utf-8');
  console.log(chalk.gray(`  📄 CycloneDX report saved to: ${outputPath}`));
  console.log('');
}
