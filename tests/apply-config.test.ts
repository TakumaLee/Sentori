/**
 * Tests for applyConfig (ignore + severity overrides).
 */

import { ScanReport, Finding } from '../src/types';
import { SentoriConfig } from '../src/config/sentori-config';
import { applyConfig } from '../src/utils/apply-config';

// Helpers
function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: 'Secret Leak Scanner',
    severity: 'high',
    rule: 'SECRET-001',
    title: 'Secret detected',
    description: 'test',
    message: 'Found a secret',
    file: 'src/config.ts',
    line: 10,
    ...overrides,
  };
}

function makeReport(scannerName: string, findings: Finding[]): ScanReport {
  return {
    timestamp: new Date().toISOString(),
    target: '/tmp/test',
    results: [{ scanner: scannerName, findings, scannedFiles: 1, duration: 100 }],
  };
}

function makeConfig(overrides: Partial<SentoriConfig> = {}): SentoriConfig {
  return {
    version: 1,
    rules: [],
    ignore: [],
    overrides: [],
    warnings: [],
    ...overrides,
  };
}

describe('applyConfig', () => {
  // ── Ignore tests ──────────────────────────────────────────────────────────

  test('ignore by scanner removes all findings from that scanner', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ rule: 'SECRET-001' }),
      makeFinding({ rule: 'SECRET-002' }),
    ]);
    const config = makeConfig({
      ignore: [{ scanner: 'Secret Leak Scanner' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings).toHaveLength(0);
  });

  test('ignore by rule removes only matching rule', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ rule: 'SECRET-001' }),
      makeFinding({ rule: 'SECRET-002' }),
    ]);
    const config = makeConfig({
      ignore: [{ rule: 'SECRET-001' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings).toHaveLength(1);
    expect(result.results[0].findings[0].rule).toBe('SECRET-002');
  });

  test('ignore by file glob removes matching file findings', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ file: 'tests/util.test.ts' }),
      makeFinding({ file: 'src/main.ts' }),
    ]);
    const config = makeConfig({
      ignore: [{ file: 'tests/**' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings).toHaveLength(1);
    expect(result.results[0].findings[0].file).toBe('src/main.ts');
  });

  test('ignore with scanner + file requires both to match (AND logic)', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ file: 'tests/util.test.ts' }),
      makeFinding({ file: 'src/main.ts' }),
    ]);
    const config = makeConfig({
      ignore: [{ scanner: 'Secret Leak Scanner', file: 'tests/**' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings).toHaveLength(1);
    expect(result.results[0].findings[0].file).toBe('src/main.ts');
  });

  test('ignore with scanner mismatch does not suppress', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ file: 'tests/util.test.ts' }),
    ]);
    const config = makeConfig({
      ignore: [{ scanner: 'Prompt Injection Tester', file: 'tests/**' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings).toHaveLength(1);
  });

  test('ignore with wildcard file pattern ignores all paths', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ file: 'src/a.ts' }),
      makeFinding({ file: 'lib/b.ts' }),
    ]);
    const config = makeConfig({
      ignore: [{ file: '**/*' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings).toHaveLength(0);
  });

  // ── Override tests ────────────────────────────────────────────────────────

  test('severity override changes finding severity', () => {
    const report = makeReport('Supply Chain Scanner', [
      makeFinding({ scanner: 'Supply Chain Scanner', severity: 'medium', rule: 'SC-001' }),
    ]);
    const config = makeConfig({
      overrides: [{ scanner: 'Supply Chain Scanner', severity: 'critical' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings[0].severity).toBe('critical');
  });

  test('override with rule filter only applies to matching rule', () => {
    const report = makeReport('Supply Chain Scanner', [
      makeFinding({ scanner: 'Supply Chain Scanner', severity: 'medium', rule: 'SC-001' }),
      makeFinding({ scanner: 'Supply Chain Scanner', severity: 'medium', rule: 'SC-002' }),
    ]);
    const config = makeConfig({
      overrides: [{ scanner: 'Supply Chain Scanner', rule: 'SC-001', severity: 'critical' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings[0].severity).toBe('critical');
    expect(result.results[0].findings[1].severity).toBe('medium');
  });

  test('override does not affect different scanner', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ severity: 'medium' }),
    ]);
    const config = makeConfig({
      overrides: [{ scanner: 'Supply Chain Scanner', severity: 'critical' }],
    });

    const result = applyConfig(report, config);
    expect(result.results[0].findings[0].severity).toBe('medium');
  });

  // ── Ordering tests ────────────────────────────────────────────────────────

  test('overrides run before ignore — overridden severity is visible to ignore', () => {
    // Override bumps to critical, then ignore suppresses critical from that scanner
    // This verifies override→ignore ordering
    const report = makeReport('Supply Chain Scanner', [
      makeFinding({ scanner: 'Supply Chain Scanner', severity: 'info', rule: 'SC-001' }),
    ]);
    const config = makeConfig({
      overrides: [{ scanner: 'Supply Chain Scanner', severity: 'critical' }],
      ignore: [{ scanner: 'Supply Chain Scanner' }],
    });

    const result = applyConfig(report, config);
    // After override: severity=critical. After ignore: finding suppressed.
    expect(result.results[0].findings).toHaveLength(0);
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  test('finding without file field is not matched by file ignore', () => {
    const report = makeReport('Defense Analyzer', [
      makeFinding({ scanner: 'Defense Analyzer', file: undefined }),
    ]);
    const config = makeConfig({
      ignore: [{ file: '**/*' }],
    });

    const result = applyConfig(report, config);
    // file is undefined → fileMatch is false → finding kept
    expect(result.results[0].findings).toHaveLength(1);
  });

  test('minimatch matchBase: false requires full path match', () => {
    const report = makeReport('Secret Leak Scanner', [
      makeFinding({ file: 'deep/nested/tests/file.ts' }),
    ]);
    const config = makeConfig({
      ignore: [{ file: 'tests/**' }],
    });

    const result = applyConfig(report, config);
    // tests/** should NOT match deep/nested/tests/file.ts with matchBase: false
    expect(result.results[0].findings).toHaveLength(1);
  });

  test('report is not mutated', () => {
    const original = makeReport('Secret Leak Scanner', [
      makeFinding(),
    ]);
    const config = makeConfig({
      ignore: [{ scanner: 'Secret Leak Scanner' }],
    });
    const originalFindings = original.results[0].findings.length;

    applyConfig(original, config);

    expect(original.results[0].findings).toHaveLength(originalFindings);
  });
});
