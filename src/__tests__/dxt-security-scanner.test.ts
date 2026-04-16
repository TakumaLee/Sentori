import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { DxtSecurityScanner } from '../scanners/dxt-security-scanner';
import { Finding } from '../types';

function createTempDir(files: Record<string, string>): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-dxt-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(tmpDir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return tmpDir;
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('DxtSecurityScanner', () => {
  let scanner: DxtSecurityScanner;

  beforeAll(() => {
    scanner = new DxtSecurityScanner();
  });

  test('scanner has correct name and description', () => {
    expect(scanner.name).toBe('DxtSecurityScanner');
    expect(scanner.description).toBeTruthy();
  });

  // --- DXT-001: CRITICAL unsandboxed + external data + local executor ---

  test('DXT-001: flags CRITICAL for unsandboxed ext with external data source + local executor', async () => {
    const config = {
      extensions: {
        'evil-calendar': {
          permissions: { file_system: true },
          sandbox: false,
          data_sources: [{ type: 'calendar', external: true }],
          executors: [{ type: 'shell' }],
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const critical = result.findings.filter((f) => f.rule === 'DXT-001');
      expect(critical.length).toBe(1);
      expect(critical[0].severity).toBe('critical');
      expect(critical[0].message).toContain('evil-calendar');
    } finally {
      cleanup(dir);
    }
  });

  test('DXT-001: no CRITICAL if sandboxed', async () => {
    const config = {
      extensions: {
        'safe-calendar': {
          sandbox: true,
          data_sources: [{ type: 'calendar', external: true }],
          executors: [{ type: 'shell' }],
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const critical = result.findings.filter((f) => f.rule === 'DXT-001');
      expect(critical.length).toBe(0);
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-002: Unrestricted file system ---

  test('DXT-002: flags HIGH for unrestricted file_system', async () => {
    const config = {
      extensions: {
        'file-ext': { permissions: { file_system: true } },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-002');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('high');
    } finally {
      cleanup(dir);
    }
  });

  test('DXT-002: no finding for path-restricted file_system', async () => {
    const config = {
      extensions: {
        'safe-ext': { permissions: { file_system: ['/tmp'] } },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-002');
      expect(hits.length).toBe(0);
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-003: Unrestricted network ---

  test('DXT-003: flags HIGH for unrestricted network', async () => {
    const config = {
      extensions: {
        'net-ext': { permissions: { network: true } },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-003');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('high');
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-004: Code execution ---

  test('DXT-004: flags HIGH for code_execution permission', async () => {
    const config = {
      extensions: {
        'exec-ext': { permissions: { code_execution: true } },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-004');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('high');
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-005: No sandbox ---

  test('DXT-005: flags HIGH for extension without sandbox', async () => {
    const config = {
      extensions: {
        'no-sandbox': { permissions: {} },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-005');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('high');
    } finally {
      cleanup(dir);
    }
  });

  test('DXT-005: no finding when sandbox object has enabled=true', async () => {
    const config = {
      extensions: {
        'sandboxed': { sandbox: { enabled: true }, permissions: {} },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-005');
      expect(hits.length).toBe(0);
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-006: Unsigned ---

  test('DXT-006: flags HIGH for unsigned extension', async () => {
    const config = {
      extensions: {
        'unsigned-ext': { permissions: {}, sandbox: true },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-006');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('high');
    } finally {
      cleanup(dir);
    }
  });

  test('DXT-006: no finding for signed extension', async () => {
    const config = {
      extensions: {
        'signed-ext': {
          permissions: {},
          sandbox: true,
          signature: { signed: true, verified: true },
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-006');
      expect(hits.length).toBe(0);
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-007: Signed but unverified ---

  test('DXT-007: flags MEDIUM for signed but unverified extension', async () => {
    const config = {
      extensions: {
        'unverified': {
          permissions: {},
          sandbox: true,
          signature: { signed: true, verified: false },
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-007');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('medium');
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-008: file_system + network without sandbox ---

  test('DXT-008: flags MEDIUM for file+network combo without sandbox', async () => {
    const config = {
      extensions: {
        'combo-ext': {
          permissions: { file_system: ['/data'], network: ['api.example.com'] },
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-008');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('medium');
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-009: External data without sandbox ---

  test('DXT-009: flags MEDIUM for external data source without sandbox', async () => {
    const config = {
      extensions: {
        'webhook-ext': {
          data_sources: [{ type: 'webhook', external: true }],
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-009');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('medium');
    } finally {
      cleanup(dir);
    }
  });

  // --- DXT-010: Unrestricted executor ---

  test('DXT-010: flags MEDIUM for unrestricted executor', async () => {
    const config = {
      extensions: {
        'unrestricted-exec': {
          sandbox: true,
          executors: [{ type: 'shell', unrestricted: true }],
          signature: { signed: true, verified: true },
        },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-010');
      expect(hits.length).toBe(1);
      expect(hits[0].severity).toBe('medium');
    } finally {
      cleanup(dir);
    }
  });

  // --- Integration / edge cases ---

  test('returns empty findings for empty directory', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-dxt-empty-'));
    try {
      const result = await scanner.scan(dir);
      expect(result.findings.length).toBe(0);
      expect(result.scanner).toBe('DxtSecurityScanner');
    } finally {
      cleanup(dir);
    }
  });

  test('handles single extension config (top-level)', async () => {
    const config = {
      name: 'solo-ext',
      permissions: { code_execution: true },
      sandbox: true,
      signature: { signed: true, verified: true },
    };
    const dir = createTempDir({ 'ext.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-004');
      expect(hits.length).toBe(1);
    } finally {
      cleanup(dir);
    }
  });

  test('scans .claude/extensions subdirectory', async () => {
    const config = {
      extensions: {
        'nested': { permissions: { network: true } },
      },
    };
    const dir = createTempDir({
      '.claude/extensions/config.json': JSON.stringify(config),
    });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-003');
      expect(hits.length).toBe(1);
    } finally {
      cleanup(dir);
    }
  });

  test('supports dxt_extensions key', async () => {
    const config = {
      dxt_extensions: {
        'alt-key': { permissions: { file_system: true } },
      },
    };
    const dir = createTempDir({ 'config.json': JSON.stringify(config) });
    try {
      const result = await scanner.scan(dir);
      const hits = result.findings.filter((f) => f.rule === 'DXT-002');
      expect(hits.length).toBe(1);
    } finally {
      cleanup(dir);
    }
  });

  test('auditExtension directly works for unit testing', () => {
    const findings = scanner.auditExtension(
      'test-ext',
      {
        permissions: { file_system: true, network: true, code_execution: true },
        data_sources: [{ type: 'email', external: true }],
        executors: [{ type: 'binary' }],
      },
      'test.json'
    );
    // Should have DXT-001 (critical), DXT-002, DXT-003, DXT-004, DXT-005, DXT-006
    const rules = findings.map((f) => f.rule);
    expect(rules).toContain('DXT-001');
    expect(rules).toContain('DXT-002');
    expect(rules).toContain('DXT-005');
    expect(rules).toContain('DXT-006');
    expect(findings.filter((f) => f.severity === 'critical').length).toBeGreaterThanOrEqual(1);
  });

  test('skips malformed JSON files gracefully', async () => {
    const dir = createTempDir({ 'bad.json': '{not valid json' });
    try {
      const result = await scanner.scan(dir);
      expect(result.findings.length).toBe(0);
    } finally {
      cleanup(dir);
    }
  });

  test('skips valid JSON with wrong shape (DxtConfigFileSchema validation)', async () => {
    // A bare number / string / null passes JSON.parse but fails DxtConfigFileSchema
    // (must be object or array). The scanner must skip silently without throwing.
    const dir = createTempDir({ 'scalar.json': '42' });
    try {
      const result = await scanner.scan(dir);
      expect(result.findings.length).toBe(0);
    } finally {
      cleanup(dir);
    }
  });
});
