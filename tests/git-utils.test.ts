import { isGitTracked, isGitIgnored, isLocallyProtected, getGitTrackingStatus } from '../src/utils/git-utils';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';

describe('Git Utils', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-git-test-'));
    // Initialize a git repo
    execSync('git init', { cwd: tmpDir, stdio: 'pipe' });
    execSync('git config user.email "test@test.com"', { cwd: tmpDir, stdio: 'pipe' });
    execSync('git config user.name "Test"', { cwd: tmpDir, stdio: 'pipe' });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('isGitTracked', () => {
    it('should return true for tracked files', () => {
      const filePath = path.join(tmpDir, 'tracked.txt');
      fs.writeFileSync(filePath, 'content');
      execSync('git add tracked.txt', { cwd: tmpDir, stdio: 'pipe' });
      execSync('git commit -m "add"', { cwd: tmpDir, stdio: 'pipe' });
      expect(isGitTracked(filePath)).toBe(true);
    });

    it('should return false for untracked files', () => {
      const filePath = path.join(tmpDir, 'untracked.txt');
      fs.writeFileSync(filePath, 'content');
      expect(isGitTracked(filePath)).toBe(false);
    });

    it('should return null for non-git directories', () => {
      const nonGitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-nogit-'));
      const filePath = path.join(nonGitDir, 'file.txt');
      fs.writeFileSync(filePath, 'content');
      expect(isGitTracked(filePath)).toBe(null);
      fs.rmSync(nonGitDir, { recursive: true, force: true });
    });
  });

  describe('isGitIgnored', () => {
    it('should return true for gitignored files', () => {
      fs.writeFileSync(path.join(tmpDir, '.gitignore'), '*.secret\n');
      execSync('git add .gitignore', { cwd: tmpDir, stdio: 'pipe' });
      execSync('git commit -m "add gitignore"', { cwd: tmpDir, stdio: 'pipe' });
      const secretFile = path.join(tmpDir, 'config.secret');
      fs.writeFileSync(secretFile, 'secret');
      expect(isGitIgnored(secretFile)).toBe(true);
    });

    it('should return false for non-ignored files', () => {
      const filePath = path.join(tmpDir, 'normal.txt');
      fs.writeFileSync(filePath, 'content');
      expect(isGitIgnored(filePath)).toBe(false);
    });
  });

  describe('isLocallyProtected', () => {
    it('should return true for untracked + gitignored files', () => {
      fs.writeFileSync(path.join(tmpDir, '.gitignore'), '.env\n');
      execSync('git add .gitignore', { cwd: tmpDir, stdio: 'pipe' });
      execSync('git commit -m "add gitignore"', { cwd: tmpDir, stdio: 'pipe' });
      const envFile = path.join(tmpDir, '.env');
      fs.writeFileSync(envFile, 'API_KEY=sk-123');
      expect(isLocallyProtected(envFile)).toBe(true);
    });

    it('should return false for tracked files', () => {
      const filePath = path.join(tmpDir, 'config.json');
      fs.writeFileSync(filePath, '{"key": "value"}');
      execSync('git add config.json', { cwd: tmpDir, stdio: 'pipe' });
      execSync('git commit -m "add config"', { cwd: tmpDir, stdio: 'pipe' });
      expect(isLocallyProtected(filePath)).toBe(false);
    });

    it('should return false for untracked but not gitignored files', () => {
      const filePath = path.join(tmpDir, 'new-file.txt');
      fs.writeFileSync(filePath, 'content');
      expect(isLocallyProtected(filePath)).toBe(false);
    });
  });

  describe('getGitTrackingStatus', () => {
    it('should batch check multiple files', () => {
      const tracked = path.join(tmpDir, 'tracked.txt');
      const untracked = path.join(tmpDir, 'untracked.txt');
      fs.writeFileSync(tracked, 'a');
      fs.writeFileSync(untracked, 'b');
      execSync('git add tracked.txt', { cwd: tmpDir, stdio: 'pipe' });
      execSync('git commit -m "add"', { cwd: tmpDir, stdio: 'pipe' });

      const status = getGitTrackingStatus(tmpDir, [tracked, untracked]);
      expect(status.get(tracked)).toBe('tracked');
      expect(status.get(untracked)).toBe('untracked');
    });

    it('should return unknown for non-git directories', () => {
      const nonGitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-nogit-'));
      const filePath = path.join(nonGitDir, 'file.txt');
      fs.writeFileSync(filePath, 'content');
      const status = getGitTrackingStatus(nonGitDir, [filePath]);
      expect(status.get(filePath)).toBe('unknown');
      fs.rmSync(nonGitDir, { recursive: true, force: true });
    });
  });
});
