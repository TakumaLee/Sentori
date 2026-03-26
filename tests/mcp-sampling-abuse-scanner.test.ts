import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { mcpSamplingAbuseScanner } from '../src/scanners/mcp-sampling-abuse-scanner';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function tmpDir(files: Record<string, object>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-sampling-test-'));
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), JSON.stringify(content), 'utf8');
  }
  return dir;
}

// ─── MCP-SAMPLING-001: sampling without rate limits ──────────────────────────

describe('MCP-SAMPLING-001: sampling enabled without rate limits', () => {
  it('flags a server with sampling capability but no rate limit fields', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: {},
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(true);
      expect(result.findings.find(f => f.rule === 'MCP-SAMPLING-001')?.severity).toBe('medium');
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag when maxRequestsPerMinute is present', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: { maxRequestsPerMinute: 10 },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag when rateLimit is present', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: { rateLimit: { requests: 5, windowSeconds: 60 } },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag when maxCallsPerSession is present', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: { maxCallsPerSession: 100 },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag when throttle is present', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: { throttle: true },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('accepts mcp_servers key variant', async () => {
    const dir = tmpDir({
      'config.json': {
        mcp_servers: {
          serverA: {
            capabilities: { sampling: {} },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('accepts servers key variant', async () => {
    const dir = tmpDir({
      'config.json': {
        servers: {
          serverB: {
            capabilities: { sampling: {} },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── MCP-SAMPLING-002: wildcard model access ──────────────────────────────────

describe('MCP-SAMPLING-002: wildcard model access in sampling', () => {
  it('flags "*" in modelPreferences array', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: {
                maxRequestsPerMinute: 5,
                modelPreferences: ['*'],
              },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-002')).toBe(true);
      expect(result.findings.find(f => f.rule === 'MCP-SAMPLING-002')?.severity).toBe('high');
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('flags "*" in models array', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: {
                maxRequestsPerMinute: 5,
                models: ['gpt-4', '*'],
              },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-002')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag when specific models are listed (no wildcard)', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            capabilities: {
              sampling: {
                maxRequestsPerMinute: 5,
                models: ['claude-3-haiku', 'gpt-4o-mini'],
              },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-002')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── MCP-SAMPLING-003: top-level capabilities.sampling ───────────────────────

describe('MCP-SAMPLING-003: top-level sampling capability in manifest', () => {
  it('emits info finding for capabilities.sampling at root level', async () => {
    const dir = tmpDir({
      'manifest.json': {
        name: 'my-mcp-server',
        capabilities: {
          sampling: {},
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-003')).toBe(true);
      expect(result.findings.find(f => f.rule === 'MCP-SAMPLING-003')?.severity).toBe('info');
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT emit MCP-SAMPLING-003 when capabilities.sampling is absent', async () => {
    const dir = tmpDir({
      'manifest.json': {
        name: 'my-mcp-server',
        capabilities: {
          tools: {},
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-003')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── MCP-SAMPLING-004: humanInTheLoop disabled ────────────────────────────────

describe('MCP-SAMPLING-004: humanInTheLoop bypassed', () => {
  it('flags humanInTheLoop: false', async () => {
    const dir = tmpDir({
      'manifest.json': {
        capabilities: {
          sampling: { humanInTheLoop: false },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-004')).toBe(true);
      expect(result.findings.find(f => f.rule === 'MCP-SAMPLING-004')?.severity).toBe('high');
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('flags humanInTheLoop: "never"', async () => {
    const dir = tmpDir({
      'manifest.json': {
        capabilities: {
          sampling: { humanInTheLoop: 'never' },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-004')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag humanInTheLoop: true', async () => {
    const dir = tmpDir({
      'manifest.json': {
        capabilities: {
          sampling: { humanInTheLoop: true },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-004')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── MCP-SAMPLING-005: sampling in alwaysAllow ───────────────────────────────

describe('MCP-SAMPLING-005: sampling methods in alwaysAllow', () => {
  it('flags alwaysAllow containing "sampling/createMessage"', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            alwaysAllow: ['sampling/createMessage'],
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-005')).toBe(true);
      expect(result.findings.find(f => f.rule === 'MCP-SAMPLING-005')?.severity).toBe('high');
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('flags alwaysAllow containing a "sampling/" prefixed method', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            alwaysAllow: ['tools/call', 'sampling/someOtherMethod'],
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-005')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('does NOT flag alwaysAllow without sampling methods', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          myServer: {
            alwaysAllow: ['tools/call', 'resources/read'],
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-005')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── Clean config: no findings ───────────────────────────────────────────────

describe('clean config produces no findings', () => {
  it('returns no findings for a server with no sampling capability', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          safeServer: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
            capabilities: {
              tools: {},
              resources: {},
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings).toHaveLength(0);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── SKIP_PATTERNS: excluded files ───────────────────────────────────────────

describe('SKIP_PATTERNS: config files that should be ignored', () => {
  it('skips package.json even if it contains sampling-like keys', async () => {
    const dir = tmpDir({
      'package.json': {
        mcpServers: {
          rogue: { capabilities: { sampling: {} } },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('skips tsconfig.json', async () => {
    const dir = tmpDir({
      'tsconfig.json': {
        mcpServers: {
          rogue: { capabilities: { sampling: {} } },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── Multiple servers — partial issues ───────────────────────────────────────

describe('multiple servers where only some have issues', () => {
  it('flags only the server with unrate-limited sampling', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          cleanServer: {
            capabilities: {
              sampling: { maxRequestsPerMinute: 10 },
            },
          },
          riskyServer: {
            capabilities: {
              sampling: {},
            },
          },
          noSamplingServer: {
            capabilities: { tools: {} },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      const rule001 = result.findings.filter(f => f.rule === 'MCP-SAMPLING-001');
      expect(rule001).toHaveLength(1);
      expect(rule001[0].title).toContain('riskyServer');
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('flags multiple servers that each have distinct issues', async () => {
    const dir = tmpDir({
      'mcp.json': {
        mcpServers: {
          noLimitServer: {
            capabilities: {
              sampling: {},
            },
          },
          wildcardServer: {
            capabilities: {
              sampling: {
                maxRequestsPerMinute: 5,
                models: ['*'],
              },
            },
          },
        },
      },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-001')).toBe(true);
      expect(result.findings.some(f => f.rule === 'MCP-SAMPLING-002')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});

// ─── ScanResult metadata ──────────────────────────────────────────────────────

describe('ScanResult metadata', () => {
  it('result includes scanner name and duration', async () => {
    const dir = tmpDir({ 'mcp.json': { mcpServers: {} } });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.scanner).toBe('MCP Sampling Abuse Scanner');
      expect(typeof result.duration).toBe('number');
      expect(result.duration).toBeGreaterThanOrEqual(0);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });

  it('scannedFiles reflects total discovered config files', async () => {
    const dir = tmpDir({
      'mcp.json': { mcpServers: {} },
      'other.json': { foo: 'bar' },
    });
    try {
      const result = await mcpSamplingAbuseScanner.scan(dir);
      expect(result.scannedFiles).toBeGreaterThanOrEqual(2);
    } finally {
      fs.rmSync(dir, { recursive: true });
    }
  });
});
