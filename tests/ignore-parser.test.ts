import { parseIgnoreFile, loadIgnorePatterns, ignoreToGlobPatterns, shouldIgnoreFile, DEFAULT_SENTORI_IGNORE } from '../src/utils/ignore-parser';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Ignore Parser', () => {
  describe('parseIgnoreFile', () => {
    it('should parse basic patterns', () => {
      const content = `
# Comment line
node_modules/
*.test.*
dist/
`;
      const patterns = parseIgnoreFile(content);
      expect(patterns).toEqual(['node_modules/', '*.test.*', 'dist/']);
    });

    it('should skip empty lines and comments', () => {
      const content = `
# This is a comment
foo/

# Another comment
bar/
`;
      const patterns = parseIgnoreFile(content);
      expect(patterns).toEqual(['foo/', 'bar/']);
    });

    it('should handle negation patterns', () => {
      const content = `!node_modules/\n*.log`;
      const patterns = parseIgnoreFile(content);
      expect(patterns).toEqual(['!node_modules/', '*.log']);
    });

    it('should handle empty content', () => {
      expect(parseIgnoreFile('')).toEqual([]);
    });
  });

  describe('DEFAULT_SENTORI_IGNORE', () => {
    it('should include standard defaults', () => {
      expect(DEFAULT_SENTORI_IGNORE).toContain('node_modules/');
      expect(DEFAULT_SENTORI_IGNORE).toContain('*.test.*');
      expect(DEFAULT_SENTORI_IGNORE).toContain('tests/');
      expect(DEFAULT_SENTORI_IGNORE).toContain('coverage/');
      expect(DEFAULT_SENTORI_IGNORE).toContain('.git/');
      expect(DEFAULT_SENTORI_IGNORE).toContain('__tests__/');
      expect(DEFAULT_SENTORI_IGNORE).toContain('__test__/');
    });
  });

  describe('loadIgnorePatterns', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('should return defaults when no .sentoriignore exists', () => {
      const { patterns, hasFile } = loadIgnorePatterns(tmpDir);
      expect(hasFile).toBe(false);
      expect(patterns).toEqual(DEFAULT_SENTORI_IGNORE);
    });

    it('should merge user patterns with defaults', () => {
      fs.writeFileSync(path.join(tmpDir, '.sentoriignore'), 'custom-dir/\n*.log\n');
      const { patterns, hasFile } = loadIgnorePatterns(tmpDir);
      expect(hasFile).toBe(true);
      expect(patterns).toContain('custom-dir/');
      expect(patterns).toContain('*.log');
      // Defaults still present
      expect(patterns).toContain('node_modules/');
    });

    it('should handle negation to remove defaults', () => {
      fs.writeFileSync(path.join(tmpDir, '.sentoriignore'), '!tests/\n');
      const { patterns } = loadIgnorePatterns(tmpDir);
      expect(patterns).not.toContain('tests/');
      // Other defaults still present
      expect(patterns).toContain('node_modules/');
    });
  });

  describe('ignoreToGlobPatterns', () => {
    it('should convert directory patterns', () => {
      const globs = ignoreToGlobPatterns(['node_modules/']);
      expect(globs).toContain('**/node_modules/**');
    });

    it('should convert file glob patterns', () => {
      const globs = ignoreToGlobPatterns(['*.test.*']);
      expect(globs).toContain('**/*.test.*');
    });

    it('should handle plain names as directories', () => {
      const globs = ignoreToGlobPatterns(['dist']);
      expect(globs).toContain('**/dist/**');
    });

    it('should pass through glob patterns with paths', () => {
      const globs = ignoreToGlobPatterns(['src/**/*.spec.ts']);
      expect(globs).toContain('src/**/*.spec.ts');
    });
  });

  describe('shouldIgnoreFile', () => {
    it('should match directory patterns', () => {
      expect(shouldIgnoreFile('src/tests/foo.ts', ['tests/'])).toBe(true);
      expect(shouldIgnoreFile('node_modules/bar/index.js', ['node_modules/'])).toBe(true);
    });

    it('should match file glob patterns', () => {
      expect(shouldIgnoreFile('src/foo.test.ts', ['*.test.*'])).toBe(true);
      expect(shouldIgnoreFile('src/foo.spec.js', ['*.spec.*'])).toBe(true);
    });

    it('should not match non-matching files', () => {
      expect(shouldIgnoreFile('src/index.ts', ['*.test.*'])).toBe(false);
      expect(shouldIgnoreFile('src/main.js', ['tests/'])).toBe(false);
    });

    it('should match __tests__ directory', () => {
      expect(shouldIgnoreFile('src/__tests__/foo.ts', ['__tests__/'])).toBe(true);
    });

    it('should match .git directory', () => {
      expect(shouldIgnoreFile('.git/config', ['.git/'])).toBe(true);
    });

    it('should match coverage directory', () => {
      expect(shouldIgnoreFile('coverage/lcov.info', ['coverage/'])).toBe(true);
    });
  });
});
