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

      '(a|b)',    // alternation without outer quantifier — safe
