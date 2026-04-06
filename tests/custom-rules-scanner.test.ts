import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runCustomRules, CUSTOM_RULES_SCANNER_NAME, detectRedos } from '../src/scanners/custom-rules-scanner';
import { CustomRule } from '../src/config/sentori-config';

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'custom-rules-test-'));
}

function writeFile(dir: string, relPath: string, content: string): void {
  const fullPath = path.join(dir, relPath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content, 'utf-8');
}

function makeRule(overrides: Partial<CustomRule> = {}): CustomRule {
  return {
    id: 'test-rule',
    pattern: 'AKIA[0-9A-Z]{16}',
    severity: 'critical',
    message: 'AWS key detected',
    ...overrides,
  };
}

describe('detectRedos', () => {
  test('returns null for safe patterns', () => {
    const safe = [
      'AKIA[0-9A-Z]{16}',
      '([a-z])+',
      '\\w+',
      '(ab){3}',
      '(foo)?',
      '(?=foo)bar',
      '(?:abc){1,3}',
      // alternation WITHOUT an outer repeating quantifier is safe
      '(a|b)',
    ];
    for (const p of safe) {
      expect(detectRedos(p)).toBeNull();
    }
  });

  test('flags nested quantifier (\w+)+', () => {
    expect(detectRedos('(\\w+)+')).not.toBeNull();
  });

  test('flags nested quantifier (a*)*', () => {
    expect(detectRedos('(a*)*')).not.toBeNull();
  });

  test('flags nested quantifier (a+)*', () => {
    expect(detectRedos('(a+)*')).not.toBeNull();
  });

  test('flags non-capturing group with nested quantifier (?:\\w+)+', () => {
    expect(detectRedos('(?:\\w+)+')).not.toBeNull();
  });

  test('flags alternation with inner quantifiers ([a-z]+|[0-9]+)+', () => {
    expect(detectRedos('([a-z]+|[0-9]+)+')).not.toBeNull();
  });

  test('flags unbounded {n,} inside quantified group (\\w{2,})+', () => {
    expect(detectRedos('(\\w{2,})+')).not.toBeNull();
  });

  test('does not flag escaped quantifier chars in character class', () => {
    // [+*] inside a character class is literal — not a quantifier
    expect(detectRedos('([+*])+')).toBeNull();
  });

  test('error message mentions position and body snippet', () => {
    const reason = detectRedos('(\\w+)+');
    expect(reason).toMatch(/nested quantifier/i);
    expect(reason).toMatch(/catastrophic backtracking/i);
  });

  // Alternation under a repeating quantifier — textbook ReDoS vectors
  test('flags alternation under outer + quantifier (cat|dog)+', () => {
    expect(detectRedos('(cat|dog)+')).not.toBeNull();
  });

  test('flags alternation under outer + quantifier (a|b)+', () => {
    expect(detectRedos('(a|b)+')).not.toBeNull();
  });

  test('flags alternation with multiple alternatives under outer + quantifier (foo|bar|baz)+', () => {
    expect(detectRedos('(foo|bar|baz)+')).not.toBeNull();
  });
});

describe('runCustomRules', () => {
  test('pattern match returns finding with correct line number and evidence', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'config.ts', 'line1\nconst key = "AKIAIOSFODNN7EXAMPLE";\nline3');
    const rule = makeRule();

    const result = await runCustomRules(dir, [rule]);

    expect(result.scanner).toBe(CUSTOM_RULES_SCANNER_NAME);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].line).toBe(2);
    expect(result.findings[0].evidence).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.findings[0].rule).toBe('test-rule');
    expect(result.findings[0].severity).toBe('critical');
    expect(result.findings[0].file).toBe('config.ts');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('returns empty findings when pattern does not match', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'clean.ts', 'const safe = "hello world";');
    const rule = makeRule();

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(0);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('invalid regex returns info-level finding instead of throwing', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'file.ts', 'anything');
    const rule = makeRule({ id: 'bad-regex', pattern: '[invalid(' });

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe('info');
    expect(result.findings[0].title).toContain('Invalid regex');
    expect(result.findings[0].rule).toBe('bad-regex');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('files glob filter restricts which files are scanned', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'src/app.ts', 'AKIAIOSFODNN7EXAMPLE1');
    writeFile(dir, 'src/app.py', 'AKIAIOSFODNN7EXAMPLE2');
    const rule = makeRule({ files: '**/*.ts' });

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].file).toContain('app.ts');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('skips binary extension files', async () => {
    const dir = makeTmpDir();
    // Write text content with a binary extension
    writeFile(dir, 'image.png', 'AKIAIOSFODNN7EXAMPLE1');
    writeFile(dir, 'real.ts', 'AKIAIOSFODNN7EXAMPLE2');
    const rule = makeRule();

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].file).toBe('real.ts');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('skips files larger than 1MB', async () => {
    const dir = makeTmpDir();
    // Create a file just over 1MB
    const bigContent = 'AKIAIOSFODNN7EXAMPLE1\n' + 'x'.repeat(1_048_577);
    writeFile(dir, 'big.ts', bigContent);
    writeFile(dir, 'small.ts', 'AKIAIOSFODNN7EXAMPLE2');
    const rule = makeRule();

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].file).toBe('small.ts');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('zero-length regex match does not cause infinite loop', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'file.ts', 'abc');
    // Empty-string match regex
    const rule = makeRule({ id: 'zero-len', pattern: '(?:)' });

    const result = await runCustomRules(dir, [rule]);

    // Should complete without hanging; at most one finding per line for zero-length
    expect(result.findings.length).toBeGreaterThanOrEqual(0);
    expect(result.duration).toBeDefined();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('timeout produces an info finding and does not hang', async () => {
    const dir = makeTmpDir();
    // File with many lines so the inter-line timeout check fires
    writeFile(dir, 'big.ts', Array.from({ length: 200 }, (_, i) => `line${i}`).join('\n'));
    const rule = makeRule({ id: 'timeout-rule', pattern: 'line\\d+' });

    // Simulate elapsed time: first Date.now() returns 0 (start), subsequent calls return 10 000ms
    let callCount = 0;
    const realDateNow = Date.now;
    Date.now = jest.fn(() => (callCount++ === 0 ? 0 : 10_000));

    try {
      const result = await runCustomRules(dir, [rule]);
      const timeoutFindings = result.findings.filter((f) => f.title?.includes('timeout'));
      expect(timeoutFindings).toHaveLength(1);
      expect(timeoutFindings[0].severity).toBe('info');
      expect(timeoutFindings[0].rule).toBe('timeout-rule');
      expect(timeoutFindings[0].message).toContain('results may be incomplete');
    } finally {
      Date.now = realDateNow;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('ReDoS pattern is rejected before compilation with info-level finding', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'file.ts', 'anything');
    const rule = makeRule({ id: 'redos-rule', pattern: '(\\w+)+' });

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe('info');
    expect(result.findings[0].title).toContain('ReDoS risk');
    expect(result.findings[0].rule).toBe('redos-rule');
    expect(result.findings[0].evidence).toBe('(\\w+)+');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('multiple matches on same line produce multiple findings', async () => {
    const dir = makeTmpDir();
    writeFile(dir, 'multi.ts', 'AKIAIOSFODNN7EXAMPLE1 AKIAIOSFODNN7EXAMPLE2');
    const rule = makeRule();

    const result = await runCustomRules(dir, [rule]);

    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].line).toBe(1);
    expect(result.findings[1].line).toBe(1);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
