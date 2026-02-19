import * as fs from 'fs';
import * as path from 'path';
import { printReport, writeJsonReport } from '../src/utils/reporter';
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
});
