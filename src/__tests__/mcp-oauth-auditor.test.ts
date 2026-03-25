import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { mcpOAuthAuditor } from '../scanners/mcp-oauth-auditor';

function tmpDir(config: unknown): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-oauth-'));
  fs.writeFileSync(path.join(dir, 'claude_desktop_config.json'), JSON.stringify(config));
  return dir;
}

describe('MCP OAuth Auditor', () => {
  let dir: string;
  afterEach(() => { if (dir) fs.rmSync(dir, { recursive: true }); });

  // ── MCP-OAUTH-001: authorization_server ──────────────────────────────────

  describe('MCP-OAUTH-001 — authorization_server metadata not validated', () => {
    it('flags HIGH when authorization_server is missing', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: {
              client_id: '${CLIENT_ID}',
              redirect_uri: 'http://localhost:8080/cb',
              token_endpoint: 'https://auth.example.com/token',
            },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-001');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('high');
      expect(rule[0].id).toBe('MCP-OAUTH-001-myServer');
    });

    it('flags HIGH when authorization_server uses http://', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: {
              authorization_server: 'http://auth.example.com',
              client_id: '${CLIENT_ID}',
              redirect_uri: 'http://localhost:8080/cb',
              token_endpoint: 'https://auth.example.com/token',
            },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-001');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('high');
    });

    it('does NOT flag when authorization_server uses https://', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: {
              authorization_server: 'https://auth.example.com',
              client_id: '${CLIENT_ID}',
              redirect_uri: 'http://localhost:8080/cb',
              token_endpoint: 'https://auth.example.com/token',
            },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      expect(findings.filter(f => f.rule === 'MCP-OAUTH-001')).toHaveLength(0);
    });
  });

  // ── MCP-OAUTH-002: client_id hardcoded ───────────────────────────────────

  describe('MCP-OAUTH-002 — client_id hardcoded in config', () => {
    it('flags HIGH when client_id is a literal string', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { client_id: 'my-literal-client-id-abc123' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-002');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('high');
      expect(rule[0].id).toBe('MCP-OAUTH-002-myServer');
    });

    it('does NOT flag when client_id is an env var reference', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { client_id: '${OAUTH_CLIENT_ID}' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      expect(findings.filter(f => f.rule === 'MCP-OAUTH-002')).toHaveLength(0);
    });

    it('does NOT flag when client_id looks like an env var name (UPPER_SNAKE_CASE)', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { client_id: 'OAUTH_CLIENT_ID' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      expect(findings.filter(f => f.rule === 'MCP-OAUTH-002')).toHaveLength(0);
    });
  });

  // ── MCP-OAUTH-003: redirect_uri overly permissive ────────────────────────

  describe('MCP-OAUTH-003 — redirect_uri uses wildcard or is overly permissive', () => {
    it('flags HIGH when redirect_uri contains a wildcard', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { redirect_uri: 'https://app.example.com/*' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-003');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('high');
      expect(rule[0].id).toBe('MCP-OAUTH-003-myServer');
    });

    it('flags HIGH when redirect_uri is http://localhost with no path', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { redirect_uri: 'http://localhost' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-003');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('high');
    });

    it('does NOT flag when redirect_uri has a specific path', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { redirect_uri: 'http://localhost:8080/callback' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      expect(findings.filter(f => f.rule === 'MCP-OAUTH-003')).toHaveLength(0);
    });
  });

  // ── MCP-OAUTH-004: token_endpoint uses HTTP ──────────────────────────────

  describe('MCP-OAUTH-004 — token_endpoint uses insecure HTTP', () => {
    it('flags CRITICAL when token_endpoint uses http://', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { token_endpoint: 'http://auth.example.com/token' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-004');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('critical');
      expect(rule[0].id).toBe('MCP-OAUTH-004-myServer');
    });

    it('does NOT flag when token_endpoint uses https://', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { token_endpoint: 'https://auth.example.com/token' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      expect(findings.filter(f => f.rule === 'MCP-OAUTH-004')).toHaveLength(0);
    });
  });

  // ── Direct fields (not nested under oauth sub-object) ────────────────────

  describe('direct OAuth fields on server entry', () => {
    it('detects MCP-OAUTH-004 when token_endpoint is directly on the server entry', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            command: 'npx',
            args: ['some-mcp-server'],
            token_endpoint: 'http://auth.example.com/token',
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-004');
      expect(rule).toHaveLength(1);
      expect(rule[0].severity).toBe('critical');
    });

    it('detects MCP-OAUTH-002 when client_id is directly on the server entry', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            command: 'npx',
            client_id: 'literal-client-id-xyz',
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule = findings.filter(f => f.rule === 'MCP-OAUTH-002');
      expect(rule).toHaveLength(1);
    });
  });

  // ── Cache file downgrade ─────────────────────────────────────────────────

  describe('cache file severity downgrade', () => {
    it('downgrades findings to info for files in a cache directory', async () => {
      dir = ''; // prevent afterEach from double-deleting a stale path
      // Write the config to a /cache/ subdirectory — isCacheOrDataFile matches /[/\\]cache[/\\]/
      const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-oauth-cache-'));
      const cacheDir = path.join(baseDir, 'cache');
      fs.mkdirSync(cacheDir);
      fs.writeFileSync(
        path.join(cacheDir, 'mcp_config.json'),
        JSON.stringify({
          mcpServers: {
            myServer: {
              oauth: {
                token_endpoint: 'http://auth.example.com/token',
                client_id: 'hardcoded-literal-id',
                redirect_uri: 'http://localhost',
              },
            },
          },
        }),
      );

      try {
        const { findings } = await mcpOAuthAuditor.scan(baseDir);
        // All findings from the cache file must be downgraded to info
        const nonInfo = findings.filter(f => f.severity !== 'info');
        expect(nonInfo).toHaveLength(0);
        expect(findings.length).toBeGreaterThan(0);
      } finally {
        fs.rmSync(baseDir, { recursive: true });
      }
    });
  });

  // ── Top-level oauth block ────────────────────────────────────────────────

  describe('top-level oauth block', () => {
    it('detects issues in a top-level oauth config block', async () => {
      dir = tmpDir({
        oauth: {
          token_endpoint: 'http://auth.example.com/token',
          client_id: 'hardcoded-client',
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      const rule004 = findings.filter(f => f.rule === 'MCP-OAUTH-004');
      expect(rule004).toHaveLength(1);
      expect(rule004[0].id).toBe('MCP-OAUTH-004-(root)');
    });
  });

  // ── Scanner metadata ─────────────────────────────────────────────────────

  describe('scanner result metadata', () => {
    it('returns correct scanner name and scannedFiles count', async () => {
      dir = tmpDir({ mcpServers: {} });
      const result = await mcpOAuthAuditor.scan(dir);
      expect(result.scanner).toBe('MCP OAuth Auditor');
      expect(typeof result.scannedFiles).toBe('number');
      expect(result.scannedFiles).toBeGreaterThanOrEqual(1);
      expect(typeof result.duration).toBe('number');
    });

    it('sets confidence to definite on all findings', async () => {
      dir = tmpDir({
        mcpServers: {
          myServer: {
            oauth: { token_endpoint: 'http://auth.example.com/token' },
          },
        },
      });
      const { findings } = await mcpOAuthAuditor.scan(dir);
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.confidence).toBe('definite');
      }
    });
  });
});
