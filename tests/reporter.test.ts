import * as fs from 'fs';
import * as path from 'path';
import { printReport, writeJsonReport, buildSarifReport, writeSarifReport } from '../src/utils/reporter';
import { ScanReport } from '../src/types';

const TEMP_DIR = path.join(__dirname, '__temp_reporter__');

beforeAll(() => {
  if (!fs.existsSync(TEMP_DIR)) {
    fs.mkdirSync(TEMP_DIR, { recursive: true });
  }
});

afterAll(() => {
  fs.rmSync(TEMP_DIR, { recursive: true, force: true });
});

function makeReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return {
    version: '0.1.0',
    timestamp: '2025-01-01T00:00:00Z',
    target: '/test/path',
    results: [],
    summary: {
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      info: 0,
      grade: 'A+',
      score: 100,
      scannedFiles: 5,
      duration: 100,
    },
    ...overrides,
  };
}

describe('Reporter', () => {
  // === printReport ===
  describe('printReport', () => {
    let consoleSpy: jest.SpyInstance;

    beforeEach(() => {
      consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    });

    afterEach(() => {
      consoleSpy.mockRestore();
    });

    test('prints clean report with no findings', () => {
      const report = makeReport();
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('Sentori');
      expect(output).toContain('No vulnerabilities found');
      expect(output).toContain('A+');
    });

    test('prints findings grouped by scanner', () => {
      const report = makeReport({
        results: [{
          scanner: 'Test Scanner',
          scannedFiles: 3,
          duration: 50,
          findings: [{
            id: 'T-1',
            scanner: 'test',
            severity: 'critical',
            title: 'Critical Bug',
            description: 'A critical issue',
            file: '/test/file.ts',
            line: 10,
            recommendation: 'Fix it',
          }],
        }],
        summary: {
          totalFindings: 1,
          critical: 1,
          high: 0,
          medium: 0,
          info: 0,
          grade: 'B',
          score: 85,
          scannedFiles: 3,
          duration: 50,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('Test Scanner');
      expect(output).toContain('Critical Bug');
      expect(output).toContain('CRITICAL');
      expect(output).toContain('Fix it');
    });

    test('prints high severity findings and warning', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 1,
          duration: 10,
          findings: [{
            id: 'H-1',
            scanner: 'test',
            severity: 'high',
            title: 'High Issue',
            description: 'desc',
            recommendation: 'rec',
          }],
        }],
        summary: {
          totalFindings: 1,
          critical: 0,
          high: 1,
          medium: 0,
          info: 0,
          grade: 'A-',
          score: 92,
          scannedFiles: 1,
          duration: 10,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('High severity issues');
    });

    test('prints medium and info severity findings', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 1,
          duration: 10,
          findings: [
            { id: 'M-1', scanner: 'test', severity: 'medium', title: 'Medium', description: 'd', recommendation: 'r' },
            { id: 'I-1', scanner: 'test', severity: 'info', title: 'Info', description: 'd', recommendation: 'r' },
          ],
        }],
        summary: {
          totalFindings: 2,
          critical: 0,
          high: 0,
          medium: 1,
          info: 1,
          grade: 'A',
          score: 98,
          scannedFiles: 1,
          duration: 10,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('Medium');
      expect(output).toContain('Info');
    });

    test('prints great security posture for score >= 90', () => {
      const report = makeReport({
        summary: {
          totalFindings: 0,
          critical: 0,
          high: 0,
          medium: 0,
          info: 0,
          grade: 'A+',
          score: 100,
          scannedFiles: 5,
          duration: 100,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('Great security posture');
    });

    test('prints critical warning for critical findings', () => {
      const report = makeReport({
        results: [{
          scanner: 'S',
          scannedFiles: 1,
          duration: 10,
          findings: [{
            id: 'C-1', scanner: 'test', severity: 'critical',
            title: 'Crit', description: 'd', recommendation: 'r',
          }],
        }],
        summary: {
          totalFindings: 1,
          critical: 1,
          high: 0,
          medium: 0,
          info: 0,
          grade: 'B',
          score: 85,
          scannedFiles: 1,
          duration: 10,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('CRITICAL issues found');
    });

    test('prints file location with line number', () => {
      const report = makeReport({
        results: [{
          scanner: 'S',
          scannedFiles: 1,
          duration: 10,
          findings: [{
            id: 'F-1', scanner: 'test', severity: 'medium',
            title: 'File issue', description: 'd',
            file: '/test/file.ts', line: 42,
            recommendation: 'r',
          }],
        }],
        summary: {
          totalFindings: 1, critical: 0, high: 0, medium: 1, info: 0,
          grade: 'A', score: 98, scannedFiles: 1, duration: 10,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('/test/file.ts:42');
    });

    test('prints file location without line number', () => {
      const report = makeReport({
        results: [{
          scanner: 'S',
          scannedFiles: 1,
          duration: 10,
          findings: [{
            id: 'F-2', scanner: 'test', severity: 'info',
            title: 'No line', description: 'd',
            file: '/test/file.ts',
            recommendation: 'r',
          }],
        }],
        summary: {
          totalFindings: 1, critical: 0, high: 0, medium: 0, info: 1,
          grade: 'A+', score: 100, scannedFiles: 1, duration: 10,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('/test/file.ts');
    });

    test('skips scanner sections with no findings', () => {
      const report = makeReport({
        results: [
          { scanner: 'Empty Scanner', scannedFiles: 5, duration: 10, findings: [] },
          {
            scanner: 'Has Findings', scannedFiles: 1, duration: 10,
            findings: [{ id: 'X', scanner: 't', severity: 'info', title: 'T', description: 'd', recommendation: 'r' }],
          },
        ],
        summary: {
          totalFindings: 1, critical: 0, high: 0, medium: 0, info: 1,
          grade: 'A+', score: 100, scannedFiles: 6, duration: 20,
        },
      });
      printReport(report);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).not.toContain('Empty Scanner');
      expect(output).toContain('Has Findings');
    });
  });

  // === writeJsonReport ===
  describe('writeJsonReport', () => {
    let consoleSpy: jest.SpyInstance;

    beforeEach(() => {
      consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    });

    afterEach(() => {
      consoleSpy.mockRestore();
    });

    test('writes JSON report to file', () => {
      const report = makeReport();
      const outputPath = path.join(TEMP_DIR, 'report.json');
      writeJsonReport(report, outputPath);

      expect(fs.existsSync(outputPath)).toBe(true);
      const content = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
      expect(content.version).toBe('0.1.0');
      expect(content.target).toBe('/test/path');
    });

    test('creates parent directories if missing', () => {
      const report = makeReport();
      const outputPath = path.join(TEMP_DIR, 'sub', 'dir', 'report.json');
      writeJsonReport(report, outputPath);

      expect(fs.existsSync(outputPath)).toBe(true);
    });

    test('prints confirmation message', () => {
      const report = makeReport();
      const outputPath = path.join(TEMP_DIR, 'confirm-report.json');
      writeJsonReport(report, outputPath);

      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('JSON report saved');
    });

    test('overwrites existing file', () => {
      const outputPath = path.join(TEMP_DIR, 'overwrite.json');
      writeJsonReport(makeReport({ target: '/first' }), outputPath);
      writeJsonReport(makeReport({ target: '/second' }), outputPath);

      const content = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
      expect(content.target).toBe('/second');
    });
  });

  // === buildSarifReport ===
  describe('buildSarifReport', () => {
    test('returns valid SARIF 2.1.0 structure', () => {
      const report = makeReport();
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.$schema).toContain('sarif-schema-2.1.0');
      expect(Array.isArray(sarif.runs)).toBe(true);
      const runs = sarif.runs as Record<string, unknown>[];
      expect(runs).toHaveLength(1);
    });

    test('tool driver contains Sentori name and version', () => {
      const report = makeReport({ version: '0.8.1' });
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      const tool = runs[0].tool as Record<string, unknown>;
      const driver = tool.driver as Record<string, unknown>;
      expect(driver.name).toBe('Sentori');
      expect(driver.version).toBe('0.8.1');
    });

    test('maps critical/high findings to SARIF error level', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 1,
          duration: 10,
          findings: [
            { id: 'C-1', scanner: 'scanner', severity: 'critical', title: 'Crit', description: 'desc', recommendation: 'fix' },
            { id: 'H-1', scanner: 'scanner', severity: 'high', title: 'High', description: 'desc', recommendation: 'fix' },
          ],
        }],
        summary: { totalFindings: 2, critical: 1, high: 1, medium: 0, info: 0, grade: 'F', score: 20, scannedFiles: 1, duration: 10 },
      });
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      const results = runs[0].results as Record<string, unknown>[];
      expect(results[0].level).toBe('error');
      expect(results[1].level).toBe('error');
    });

    test('maps medium findings to SARIF warning level', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 1,
          duration: 10,
          findings: [
            { id: 'M-1', scanner: 'scanner', severity: 'medium', title: 'Med', description: 'desc', recommendation: 'fix' },
          ],
        }],
        summary: { totalFindings: 1, critical: 0, high: 0, medium: 1, info: 0, grade: 'B', score: 80, scannedFiles: 1, duration: 10 },
      });
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      const results = runs[0].results as Record<string, unknown>[];
      expect(results[0].level).toBe('warning');
    });

    test('maps info findings to SARIF note level', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 1,
          duration: 10,
          findings: [
            { id: 'I-1', scanner: 'scanner', severity: 'info', title: 'Info', description: 'desc', recommendation: 'fix' },
          ],
        }],
        summary: { totalFindings: 1, critical: 0, high: 0, medium: 0, info: 1, grade: 'A+', score: 100, scannedFiles: 1, duration: 10 },
      });
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      const results = runs[0].results as Record<string, unknown>[];
      expect(results[0].level).toBe('note');
    });

    test('includes file location with line number', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 1,
          duration: 10,
          findings: [
            { id: 'F-1', scanner: 'scanner', severity: 'high', title: 'Issue', description: 'desc', recommendation: 'fix', file: 'src/foo.ts', line: 42 },
          ],
        }],
        summary: { totalFindings: 1, critical: 0, high: 1, medium: 0, info: 0, grade: 'A', score: 90, scannedFiles: 1, duration: 10 },
      });
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      const results = runs[0].results as Record<string, unknown>[];
      const locations = results[0].locations as Record<string, unknown>[];
      const physLoc = (locations[0].physicalLocation as Record<string, unknown>);
      const artifactLoc = physLoc.artifactLocation as Record<string, unknown>;
      const region = physLoc.region as Record<string, unknown>;
      expect(artifactLoc.uri).toBe('src/foo.ts');
      expect(artifactLoc.uriBaseId).toBe('%SRCROOT%');
      expect(region.startLine).toBe(42);
    });

    test('deduplicates rules', () => {
      const report = makeReport({
        results: [{
          scanner: 'Scanner',
          scannedFiles: 2,
          duration: 10,
          findings: [
            { id: 'RULE-1', scanner: 'scanner', severity: 'high', title: 'Same Rule', description: 'desc', recommendation: 'fix' },
            { id: 'RULE-1', scanner: 'scanner', severity: 'high', title: 'Same Rule', description: 'desc', recommendation: 'fix', file: 'other.ts' },
          ],
        }],
        summary: { totalFindings: 2, critical: 0, high: 2, medium: 0, info: 0, grade: 'A', score: 90, scannedFiles: 2, duration: 10 },
      });
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      const driver = (runs[0].tool as Record<string, unknown>).driver as Record<string, unknown>;
      const rules = driver.rules as unknown[];
      // Two findings with same ruleId → only one rule entry
      expect(rules).toHaveLength(1);
      // But two results
      const results = runs[0].results as unknown[];
      expect(results).toHaveLength(2);
    });

    test('no findings produces empty results array', () => {
      const report = makeReport();
      const sarif = buildSarifReport(report) as Record<string, unknown>;
      const runs = sarif.runs as Record<string, unknown>[];
      expect((runs[0].results as unknown[]).length).toBe(0);
      expect((runs[0].artifacts as unknown[]).length).toBe(0);
    });
  });

  // === writeSarifReport ===
  describe('writeSarifReport', () => {
    let consoleSpy: jest.SpyInstance;

    beforeEach(() => {
      consoleSpy = jest.spyOn(console, 'log').mockImplementation();
    });

    afterEach(() => {
      consoleSpy.mockRestore();
    });

    test('writes valid SARIF JSON to file', () => {
      const report = makeReport({ version: '0.8.1' });
      const outputPath = path.join(TEMP_DIR, 'report.sarif');
      writeSarifReport(report, outputPath);

      expect(fs.existsSync(outputPath)).toBe(true);
      const content = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
      expect(content.version).toBe('2.1.0');
    });

    test('creates parent directories if missing', () => {
      const report = makeReport();
      const outputPath = path.join(TEMP_DIR, 'sub', 'sarif', 'report.sarif');
      writeSarifReport(report, outputPath);
      expect(fs.existsSync(outputPath)).toBe(true);
    });

    test('prints confirmation message', () => {
      const report = makeReport();
      const outputPath = path.join(TEMP_DIR, 'confirm.sarif');
      writeSarifReport(report, outputPath);
      const output = consoleSpy.mock.calls.map(c => c[0]).join('\n');
      expect(output).toContain('SARIF report saved');
    });
  });
});
