import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  a2aSecurityScanner,
  auditAuthentication,
  auditEndpoints,
  auditCapabilities,
  auditInputModes,
} from '../src/scanners/a2a-security-scanner';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function tmpFile(content: object): string {
  const f = path.join(os.tmpdir(), `agent-card-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  fs.writeFileSync(f, JSON.stringify(content), 'utf8');
  return f;
}

function tmpDir(files: Record<string, object>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'a2a-test-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), JSON.stringify(content), 'utf8');
  }
  return dir;
}

// ─── A2A-001: missing authentication ─────────────────────────────────────────

describe('auditAuthentication', () => {
  it('A2A-001: flags missing authentication', () => {
    const findings = auditAuthentication({}, 'test.json');
    expect(findings.some(f => f.id === 'A2A-001')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-001')?.severity).toBe('critical');
  });

  it('A2A-001: flags null authentication', () => {
    const findings = auditAuthentication({ authentication: null as unknown as undefined }, 'test.json');
    expect(findings.some(f => f.id === 'A2A-001')).toBe(true);
  });

  it('A2A-001-empty: flags empty schemes array', () => {
    const findings = auditAuthentication({ authentication: { schemes: [] } }, 'test.json');
    expect(findings.some(f => f.id === 'A2A-001-empty')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-001-empty')?.severity).toBe('critical');
  });

  it('A2A-002: flags anonymous scheme', () => {
    const findings = auditAuthentication({ authentication: { schemes: ['anonymous'] } }, 'test.json');
    expect(findings.some(f => f.id === 'A2A-002')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-002')?.severity).toBe('high');
  });

  it('A2A-002: flags none scheme (case-insensitive)', () => {
    const findings = auditAuthentication({ authentication: { schemes: ['None'] } }, 'test.json');
    expect(findings.some(f => f.id === 'A2A-002')).toBe(true);
  });

  it('A2A-003: flags Basic auth scheme', () => {
    const findings = auditAuthentication({ authentication: { schemes: ['basic'] } }, 'test.json');
    expect(findings.some(f => f.id === 'A2A-003')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-003')?.severity).toBe('medium');
  });

  it('no finding for Bearer auth', () => {
    const findings = auditAuthentication({ authentication: { schemes: ['Bearer'] } }, 'test.json');
    expect(findings.filter(f => f.id?.startsWith('A2A-00'))).toHaveLength(0);
  });

  it('handles array of authentication entries', () => {
    const findings = auditAuthentication(
      { authentication: [{ schemes: ['Bearer'] }, { schemes: ['anonymous'] }] },
      'test.json',
    );
    expect(findings.some(f => f.id === 'A2A-002')).toBe(true);
  });
});

// ─── A2A-004 / A2A-005: HTTP endpoints ────────────────────────────────────────

describe('auditEndpoints', () => {
  it('A2A-004: flags http:// top-level URL', () => {
    const findings = auditEndpoints({ url: 'http://example.com/agent' }, false, 'test');
    expect(findings.some(f => f.id === 'A2A-004')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-004')?.severity).toBe('critical');
  });

  it('no A2A-004 for https:// URL', () => {
    const findings = auditEndpoints({ url: 'https://example.com/agent' }, false, 'test');
    expect(findings.some(f => f.id === 'A2A-004')).toBe(false);
  });

  it('A2A-005: flags card fetched over HTTP', () => {
    const findings = auditEndpoints({}, true, 'http://example.com/.well-known/agent.json');
    expect(findings.some(f => f.id === 'A2A-005')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-005')?.severity).toBe('critical');
  });

  it('no A2A-005 when fetched over HTTPS', () => {
    const findings = auditEndpoints({}, false, 'https://example.com/.well-known/agent.json');
    expect(findings.some(f => f.id === 'A2A-005')).toBe(false);
  });

  it('flags HTTP skill endpoint', () => {
    const card = { skills: [{ id: 'search', url: 'http://example.com/search' }] };
    const findings = auditEndpoints(card, false, 'test');
    expect(findings.some(f => f.id?.startsWith('A2A-004-skill'))).toBe(true);
  });

  it('does not flag HTTPS skill endpoint', () => {
    const card = { skills: [{ id: 'search', url: 'https://example.com/search' }] };
    const findings = auditEndpoints(card, false, 'test');
    expect(findings.some(f => f.id?.startsWith('A2A-004-skill'))).toBe(false);
  });
});

// ─── A2A-006 / A2A-007: capabilities ──────────────────────────────────────────

describe('auditCapabilities', () => {
  it('A2A-006: flags all-three broad capabilities enabled', () => {
    const card = {
      capabilities: { streaming: true, pushNotifications: true, stateTransitionHistory: true },
    };
    const findings = auditCapabilities(card, 'test');
    expect(findings.some(f => f.id === 'A2A-006')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-006')?.severity).toBe('high');
  });

  it('no A2A-006 when only two capabilities enabled', () => {
    const card = { capabilities: { streaming: true, pushNotifications: true } };
    const findings = auditCapabilities(card, 'test');
    expect(findings.some(f => f.id === 'A2A-006')).toBe(false);
  });

  it('A2A-007: flags pushNotifications alone', () => {
    const card = { capabilities: { pushNotifications: true } };
    const findings = auditCapabilities(card, 'test');
    expect(findings.some(f => f.id === 'A2A-007')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-007')?.severity).toBe('medium');
  });

  it('no findings when capabilities is absent', () => {
    expect(auditCapabilities({}, 'test')).toHaveLength(0);
  });

  it('no findings when all capabilities are false', () => {
    const card = {
      capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false },
    };
    expect(auditCapabilities(card, 'test')).toHaveLength(0);
  });
});

// ─── A2A-008 / A2A-009: inputModes ────────────────────────────────────────────

describe('auditInputModes', () => {
  it('A2A-008: flags application/javascript in defaultInputModes', () => {
    const card = { defaultInputModes: ['application/json', 'application/javascript'] };
    const findings = auditInputModes(card, 'test');
    expect(findings.some(f => f.id?.startsWith('A2A-008'))).toBe(true);
    expect(findings.find(f => f.id?.startsWith('A2A-008'))?.severity).toBe('high');
  });

  it('A2A-008: flags text/x-sh in skill inputModes', () => {
    const card = { skills: [{ id: 'exec', inputModes: ['text/x-sh'] }] };
    const findings = auditInputModes(card, 'test');
    expect(findings.some(f => f.id?.startsWith('A2A-008'))).toBe(true);
  });

  it('A2A-008: flags application/octet-stream', () => {
    const card = { defaultInputModes: ['application/octet-stream'] };
    const findings = auditInputModes(card, 'test');
    expect(findings.some(f => f.id?.startsWith('A2A-008'))).toBe(true);
  });

  it('A2A-009: flags wildcard * inputMode', () => {
    const card = { defaultInputModes: ['*'] };
    const findings = auditInputModes(card, 'test');
    expect(findings.some(f => f.id === 'A2A-009')).toBe(true);
    expect(findings.find(f => f.id === 'A2A-009')?.severity).toBe('high');
  });

  it('A2A-009: flags wildcard */* inputMode', () => {
    const card = { defaultInputModes: ['*/*'] };
    const findings = auditInputModes(card, 'test');
    expect(findings.some(f => f.id === 'A2A-009')).toBe(true);
  });

  it('no findings for safe inputModes', () => {
    const card = { defaultInputModes: ['text/plain', 'application/json'] };
    expect(auditInputModes(card, 'test')).toHaveLength(0);
  });

  it('no findings when inputModes absent', () => {
    expect(auditInputModes({}, 'test')).toHaveLength(0);
  });
});

// ─── Input mode: file path ────────────────────────────────────────────────────

describe('scan() — file input mode', () => {
  it('returns findings from a JSON file on disk', async () => {
    const f = tmpFile({ authentication: null });
    try {
      const result = await a2aSecurityScanner.scan(f);
      expect(result.scannedFiles).toBe(1);
      expect(result.findings.some(x => x.id === 'A2A-001')).toBe(true);
    } finally {
      fs.unlinkSync(f);
    }
  });

  it('returns empty findings for a clean card', async () => {
    const f = tmpFile({
      url: 'https://example.com/agent',
      authentication: { schemes: ['Bearer'] },
      capabilities: { streaming: false },
    });
    try {
      const result = await a2aSecurityScanner.scan(f);
      expect(result.scannedFiles).toBe(1);
      expect(result.findings.filter(x => x.severity !== 'info')).toHaveLength(0);
    } finally {
      fs.unlinkSync(f);
    }
  });

  it('all findings have confidence=definite', async () => {
    const f = tmpFile({ authentication: null, url: 'http://bad.example.com' });
    try {
      const result = await a2aSecurityScanner.scan(f);
      for (const finding of result.findings) {
        expect(finding.confidence).toBe('definite');
      }
    } finally {
      fs.unlinkSync(f);
    }
  });
});

// ─── Input mode: directory ────────────────────────────────────────────────────

describe('scan() — directory input mode', () => {
  it('discovers and scans agent.json files in a directory', async () => {
    const dir = tmpDir({ 'agent.json': { authentication: null } });
    try {
      const result = await a2aSecurityScanner.scan(dir);
      expect(result.scannedFiles).toBe(1);
      expect(result.findings.some(x => x.id === 'A2A-001')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('discovers agent-card.json files too', async () => {
    const dir = tmpDir({ 'agent-card.json': { authentication: { schemes: ['Bearer'] }, url: 'http://plain.example' } });
    try {
      const result = await a2aSecurityScanner.scan(dir);
      expect(result.scannedFiles).toBe(1);
      expect(result.findings.some(x => x.id === 'A2A-004')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('scans multiple agent cards and aggregates findings', async () => {
    const dir = tmpDir({
      'agent.json': { authentication: null },
      'agent-card.json': { authentication: { schemes: ['anonymous'] } },
    });
    try {
      const result = await a2aSecurityScanner.scan(dir);
      expect(result.scannedFiles).toBe(2);
      expect(result.findings.some(x => x.id === 'A2A-001')).toBe(true);
      expect(result.findings.some(x => x.id === 'A2A-002')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('returns zero scannedFiles for directory with no agent cards', async () => {
    const dir = tmpDir({ 'config.json': { foo: 'bar' } });
    try {
      const result = await a2aSecurityScanner.scan(dir);
      expect(result.scannedFiles).toBe(0);
      expect(result.findings).toHaveLength(0);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── Input mode: URL (unreachable → A2A-000 info finding) ────────────────────

describe('scan() — URL input mode', () => {
  it('A2A-000: emits info finding for unreachable URL', async () => {
    // Use a non-routable IP to guarantee a connection failure
    const result = await a2aSecurityScanner.scan('http://192.0.2.1/.well-known/agent.json');
    expect(result.findings.some(f => f.id === 'A2A-000' && f.severity === 'info')).toBe(true);
  }, 12000);

  it('A2A-000: emits info finding for invalid JSON from URL-like target', async () => {
    // A non-existent domain will also fail and produce an A2A-000 finding
    const result = await a2aSecurityScanner.scan('https://this-host-does-not-exist-sentori-test.invalid');
    expect(result.findings.some(f => f.id === 'A2A-000' && f.severity === 'info')).toBe(true);
  }, 12000);
});

// ─── ScanResult shape ─────────────────────────────────────────────────────────

describe('ScanResult metadata', () => {
  it('result includes scanner name and duration', async () => {
    const f = tmpFile({ authentication: { schemes: ['Bearer'] } });
    try {
      const result = await a2aSecurityScanner.scan(f);
      expect(result.scanner).toBe('A2A Security Scanner');
      expect(typeof result.duration).toBe('number');
      expect(result.duration).toBeGreaterThanOrEqual(0);
    } finally {
      fs.unlinkSync(f);
    }
  });
});
