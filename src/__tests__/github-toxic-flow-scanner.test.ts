/**
 * Tests for GitHub MCP Toxic Agent Flow Scanner (sentori-017)
 *
 * Covers:
 *  Axis 1 — Private-repo scope detection (GTF-001, GTF-002, GTF-003)
 *  Axis 2 — Toxic tool combination detection (GTF-101, GTF-102)
 *  Axis 3 — Untrusted input route detection (GTF-201)
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as os from 'os';
import { scanConfigForGitHubToxicFlow, githubToxicFlowScanner } from '../scanners/github-toxic-flow-scanner';

// ============================================================
// Helpers
// ============================================================

function findingsByRule(findings: ReturnType<typeof scanConfigForGitHubToxicFlow>, rule: string) {
  return findings.filter(f => f.rule === rule);
}

// ============================================================
// Axis 1: Private-repo scope (GTF-001..003) — config unit tests
// ============================================================

describe('GTF-001 — literal GitHub token in config', () => {
  it('flags critical when GITHUB_PERSONAL_ACCESS_TOKEN has a literal value', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_abc123literaltoken' },
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/home/.claude/claude_desktop_config.json');
    const gtf001 = findingsByRule(findings, 'GTF-001');
    expect(gtf001).toHaveLength(1);
    expect(gtf001[0].severity).toBe('critical');
    expect(gtf001[0].title).toContain('"github"');
    expect(gtf001[0].description).toContain('literal token');
  });

  it('flags critical when GITHUB_TOKEN has a literal value', () => {
    const config = {
      mcpServers: {
        myGithub: {
          command: 'docker',
          args: ['run', '-i', '--rm', '-e', 'GITHUB_TOKEN', 'ghcr.io/github/github-mcp-server'],
          env: { GITHUB_TOKEN: 'ghs_secretvalue' },
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/mcp.json');
    const gtf001 = findingsByRule(findings, 'GTF-001');
    expect(gtf001).toHaveLength(1);
    expect(gtf001[0].severity).toBe('critical');
  });
});

describe('GTF-002 — env-var reference token without scope restriction', () => {
  it('flags high when GITHUB_PERSONAL_ACCESS_TOKEN is an env-var reference', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${GITHUB_PERSONAL_ACCESS_TOKEN}' },
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf002 = findingsByRule(findings, 'GTF-002');
    expect(gtf002).toHaveLength(1);
    expect(gtf002[0].severity).toBe('high');
    expect(gtf002[0].description).toContain('no explicit');
  });

  it('does NOT flag GTF-002 when --toolsets=repos:public flag is present', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github', '--toolsets=repos:public'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${GITHUB_PERSONAL_ACCESS_TOKEN}' },
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf002 = findingsByRule(findings, 'GTF-002');
    expect(gtf002).toHaveLength(0);
  });
});

describe('GTF-003 — unrestricted toolset (no tools allowlist)', () => {
  it('flags high when GitHub MCP server has no tools array', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf003 = findingsByRule(findings, 'GTF-003');
    expect(gtf003).toHaveLength(1);
    expect(gtf003[0].severity).toBe('high');
    expect(gtf003[0].description).toContain('no `tools` allowlist');
  });

  it('does NOT flag GTF-003 when an explicit tools allowlist is present', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
          tools: [
            { name: 'list_issues', description: 'Lists issues' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf003 = findingsByRule(findings, 'GTF-003');
    expect(gtf003).toHaveLength(0);
  });

  it('does NOT flag non-GitHub MCP servers', () => {
    const config = {
      mcpServers: {
        filesystem: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    expect(findings).toHaveLength(0);
  });
});

// ============================================================
// Axis 2: Toxic tool combination (GTF-101, GTF-102) — config unit tests
// ============================================================

describe('GTF-101 — read-issue + external-write toxic combination', () => {
  it('flags critical when get_issue + create_gist are both present (Invariant Labs PoC pattern)', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
          tools: [
            { name: 'get_issue', description: 'Gets issue details' },
            { name: 'list_issues', description: 'Lists issues' },
            { name: 'create_gist', description: 'Creates a gist' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf101 = findingsByRule(findings, 'GTF-101');
    expect(gtf101).toHaveLength(1);
    expect(gtf101[0].severity).toBe('critical');
    expect(gtf101[0].description).toContain('get_issue');
    expect(gtf101[0].description).toContain('create_gist');
    expect(gtf101[0].description).toContain('Invariant Labs');
  });

  it('flags critical when search_code + push_files co-exist', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'docker',
          args: ['run', '-i', 'ghcr.io/github/github-mcp-server'],
          env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' },
          tools: [
            { name: 'search_code', description: 'Searches code' },
            { name: 'push_files', description: 'Pushes files' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf101 = findingsByRule(findings, 'GTF-101');
    expect(gtf101).toHaveLength(1);
    expect(gtf101[0].severity).toBe('critical');
  });

  it('flags critical when get_file_contents + create_issue_comment co-exist', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['@modelcontextprotocol/server-github'],
          env: { GH_TOKEN: '${GH_TOKEN}' },
          tools: [
            { name: 'get_file_contents', description: 'Gets file contents' },
            { name: 'create_issue_comment', description: 'Creates issue comment' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf101 = findingsByRule(findings, 'GTF-101');
    expect(gtf101).toHaveLength(1);
    expect(gtf101[0].severity).toBe('critical');
  });

  it('does NOT flag GTF-101 when only read tools are present', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
          tools: [
            { name: 'get_issue', description: 'Gets issue details' },
            { name: 'list_issues', description: 'Lists issues' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf101 = findingsByRule(findings, 'GTF-101');
    expect(gtf101).toHaveLength(0);
  });

  it('does NOT flag GTF-101 when only write tools are present', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
          tools: [
            { name: 'create_gist', description: 'Creates gist' },
            { name: 'push_files', description: 'Pushes files' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf101 = findingsByRule(findings, 'GTF-101');
    expect(gtf101).toHaveLength(0);
  });
});

describe('GTF-102 — read-issue tools with broad scope, no write tools', () => {
  it('flags medium when read-issue tools exist but no explicit write tools', () => {
    const config = {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
          tools: [
            { name: 'list_pull_requests', description: 'Lists pull requests' },
            { name: 'get_issue_comments', description: 'Gets issue comments' },
          ],
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    const gtf102 = findingsByRule(findings, 'GTF-102');
    expect(gtf102).toHaveLength(1);
    expect(gtf102[0].severity).toBe('medium');
  });
});

// ============================================================
// Axis 3: Untrusted input route (GTF-201) — file-based scan
// ============================================================

describe('GTF-201 — untrusted issue content flows into agent context', () => {
  const tmpDir = path.join(os.tmpdir(), 'sentori-gtf-tests-' + Date.now());

  beforeAll(async () => {
    await fs.ensureDir(tmpDir);
  });

  afterAll(async () => {
    await fs.remove(tmpDir);
  });

  it('flags high when GitHub Actions workflow injects issue.body into LLM prompt', async () => {
    const workflowDir = path.join(tmpDir, 'toxic-workflow');
    await fs.ensureDir(workflowDir);
    await fs.writeFile(
      path.join(workflowDir, 'agent.ts'),
      `
import Anthropic from '@anthropic-ai/sdk';

async function handleIssue(issueBody: string) {
  const client = new Anthropic();
  const systemPrompt = "You are a helpful assistant. " + issueBody;
  const response = await client.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 1024,
    messages: [{ role: 'user', content: systemPrompt }],
  });
  return response;
}
`,
    );
    // Minimal config so scanner has something to find
    await fs.writeJson(path.join(workflowDir, 'mcp.json'), {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${TOKEN}' },
        },
      },
    });

    const result = await githubToxicFlowScanner.scan(workflowDir);
    // Axis 1/3 findings expected; filter for GTF-201
    const gtf201 = result.findings.filter(f => f.rule === 'GTF-201');
    expect(gtf201.length).toBeGreaterThan(0);
    expect(gtf201[0].severity).toBe('high');
    expect(gtf201[0].description).toContain('issueBody');
  });

  it('flags high when GitHub webhook body is interpolated into a system message', async () => {
    const webhookDir = path.join(tmpDir, 'toxic-webhook');
    await fs.ensureDir(webhookDir);
    await fs.writeFile(
      path.join(webhookDir, 'webhook-handler.ts'),
      `
import express from 'express';
import OpenAI from 'openai';

const app = express();
const openai = new OpenAI();

app.post('/webhook', async (req, res) => {
  const issueBody = req.body.issue.body;
  const messages = [
    { role: 'system', content: \`Process this issue: \${issueBody}\` },
  ];
  const completion = await openai.chat.completions.create({
    model: 'gpt-4',
    messages,
  });
  res.json({ result: completion.choices[0].message.content });
});
`,
    );

    const result = await githubToxicFlowScanner.scan(webhookDir);
    const gtf201 = result.findings.filter(f => f.rule === 'GTF-201');
    expect(gtf201.length).toBeGreaterThan(0);
    expect(gtf201[0].severity).toBe('high');
  });

  it('does NOT flag when sanitization is present in the same window', async () => {
    const safeDir = path.join(tmpDir, 'safe-handler');
    await fs.ensureDir(safeDir);
    await fs.writeFile(
      path.join(safeDir, 'safe-handler.ts'),
      `
import Anthropic from '@anthropic-ai/sdk';

function sanitizeIssueBody(body: string): string {
  return body.replace(/[<>]/g, '').substring(0, 500);
}

async function handleIssue(issueBody: string) {
  const client = new Anthropic();
  const cleanBody = sanitize(issueBody);
  const systemPrompt = "Process this: " + cleanBody;
  const response = await client.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 512,
    messages: [{ role: 'user', content: systemPrompt }],
  });
  return response;
}
`,
    );

    const result = await githubToxicFlowScanner.scan(safeDir);
    const gtf201 = result.findings.filter(f => f.rule === 'GTF-201');
    expect(gtf201).toHaveLength(0);
  });

  it('returns correct scanner name and duration', async () => {
    const emptyDir = path.join(tmpDir, 'empty');
    await fs.ensureDir(emptyDir);
    const result = await githubToxicFlowScanner.scan(emptyDir);
    expect(result.scanner).toBe('GitHub MCP Toxic Flow Scanner');
    expect(result.duration).toBeGreaterThanOrEqual(0);
    expect(result.findings).toBeInstanceOf(Array);
  });
});

// ============================================================
// Docker-based GitHub MCP server detection
// ============================================================

describe('Docker-based GitHub MCP server identification', () => {
  it('detects github-mcp-server Docker image as GitHub MCP server', () => {
    const config = {
      mcpServers: {
        githubDocker: {
          command: 'docker',
          args: ['run', '-i', '--rm', '-e', 'GITHUB_TOKEN', 'ghcr.io/github/github-mcp-server'],
          env: { GITHUB_TOKEN: '${GITHUB_TOKEN}' },
        },
      },
    };
    const findings = scanConfigForGitHubToxicFlow(config, '/fake/config.json');
    // Should have at least GTF-002 or GTF-003
    expect(findings.length).toBeGreaterThan(0);
    const ids = findings.map(f => f.rule);
    expect(ids.some(r => r?.startsWith('GTF-'))).toBe(true);
  });
});
