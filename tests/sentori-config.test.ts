import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadSentoriConfig } from '../src/config/sentori-config';

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-config-test-'));
}

function writeConfig(dir: string, content: string, filename = '.sentori.yml'): void {
  fs.writeFileSync(path.join(dir, filename), content, 'utf-8');
}

afterEach(() => {
  // cleanup is best-effort; OS will reap tmpdir eventually
});

describe('loadSentoriConfig', () => {
  test('returns null when no config file exists', () => {
    const dir = makeTmpDir();
    expect(loadSentoriConfig(dir)).toBeNull();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('parses valid YAML with rules, ignore, and overrides', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
rules:
  - id: aws-key
    pattern: "AKIA[0-9A-Z]{16}"
    severity: critical
    message: "Hardcoded AWS key"
    files: "**/*.ts"
ignore:
  - scanner: "Secret Leak Scanner"
  - rule: "PINJ-001"
    file: "tests/**"
overrides:
  - scanner: "Supply Chain Scanner"
    severity: high
  - scanner: "Supply Chain Scanner"
    rule: BASE64_HIDDEN_CMD
    severity: critical
`);
    const config = loadSentoriConfig(dir);
    expect(config).not.toBeNull();
    expect(config!.version).toBe(1);

    // rules
    expect(config!.rules).toHaveLength(1);
    expect(config!.rules[0]).toEqual({
      id: 'aws-key',
      pattern: 'AKIA[0-9A-Z]{16}',
      severity: 'critical',
      message: 'Hardcoded AWS key',
      files: '**/*.ts',
    });

    // ignore
    expect(config!.ignore).toHaveLength(2);
    expect(config!.ignore[0]).toEqual({ scanner: 'Secret Leak Scanner' });
    expect(config!.ignore[1]).toEqual({ rule: 'PINJ-001', file: 'tests/**' });

    // overrides
    expect(config!.overrides).toHaveLength(2);
    expect(config!.overrides[0]).toEqual({ scanner: 'Supply Chain Scanner', severity: 'high', rule: undefined });
    expect(config!.overrides[1]).toEqual({
      scanner: 'Supply Chain Scanner',
      rule: 'BASE64_HIDDEN_CMD',
      severity: 'critical',
    });

    expect(config!.warnings).toHaveLength(0);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('skips rule missing required fields and adds warning', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
rules:
  - id: incomplete
    pattern: "foo"
    # missing severity and message
`);
    const config = loadSentoriConfig(dir);
    expect(config!.rules).toHaveLength(0);
    expect(config!.warnings).toHaveLength(1);
    expect(config!.warnings[0]).toContain('incomplete');
    expect(config!.warnings[0]).toContain('severity, message');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('skips rule with invalid severity and adds warning', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
rules:
  - id: bad-sev
    pattern: "secret"
    severity: ultra
    message: "bad severity"
`);
    const config = loadSentoriConfig(dir);
    expect(config!.rules).toHaveLength(0);
    expect(config!.warnings).toHaveLength(1);
    expect(config!.warnings[0]).toContain('invalid severity');
    expect(config!.warnings[0]).toContain('ultra');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('throws on invalid YAML syntax', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
  bad: yaml:
    - [broken
`);
    expect(() => loadSentoriConfig(dir)).toThrow();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('reads .sentori.yaml (alternate extension)', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
rules:
  - id: alt-ext
    pattern: "test"
    severity: info
    message: "alt extension test"
`, '.sentori.yaml');
    const config = loadSentoriConfig(dir);
    expect(config).not.toBeNull();
    expect(config!.rules).toHaveLength(1);
    expect(config!.rules[0].id).toBe('alt-ext');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('defaults version to 1 when omitted', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
rules: []
`);
    const config = loadSentoriConfig(dir);
    expect(config!.version).toBe(1);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('ignores non-object entries in rules array', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
rules:
  - "just a string"
  - 42
  - id: valid
    pattern: "ok"
    severity: info
    message: "valid rule"
`);
    const config = loadSentoriConfig(dir);
    expect(config!.rules).toHaveLength(1);
    expect(config!.rules[0].id).toBe('valid');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('skips ignore entry with no relevant fields', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
ignore:
  - foo: bar
  - scanner: "Valid Scanner"
`);
    const config = loadSentoriConfig(dir);
    expect(config!.ignore).toHaveLength(1);
    expect(config!.ignore[0].scanner).toBe('Valid Scanner');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('adds ReDoS warning for nested-quantifier pattern while still accepting rule', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
rules:
  - id: redos-risk
    pattern: "(a+)+"
    severity: info
    message: "nested quantifier"
`);
    const config = loadSentoriConfig(dir);
    // Rule is accepted (not skipped)
    expect(config!.rules).toHaveLength(1);
    expect(config!.rules[0].id).toBe('redos-risk');
    // Warning is emitted
    expect(config!.warnings).toHaveLength(1);
    expect(config!.warnings[0]).toContain('ReDoS');
    expect(config!.warnings[0]).toContain('redos-risk');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('skips override with missing scanner or invalid severity', () => {
    const dir = makeTmpDir();
    writeConfig(dir, `
version: 1
overrides:
  - severity: high
  - scanner: "Valid"
    severity: banana
  - scanner: "Valid"
    severity: medium
`);
    const config = loadSentoriConfig(dir);
    expect(config!.overrides).toHaveLength(1);
    expect(config!.overrides[0].scanner).toBe('Valid');
    expect(config!.overrides[0].severity).toBe('medium');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
