/**
 * GitHub MCP Toxic Agent Flow Scanner
 *
 * Detects the OWASP MCP06 (Intent Flow Subversion) attack surface demonstrated by
 * Invariant Labs against the official GitHub MCP server (github/github-mcp-server,
 * 14k stars): a malicious GitHub Issue triggers prompt injection that causes an
 * agent to exfiltrate private repository data to an external endpoint.
 *
 * Three detection axes:
 *
 *  Axis 1 — Private-repo scope (GTF-001..099):
 *    MCP config contains a GitHub server entry whose token or scope grants
 *    private-repo READ access or higher (full `repo` scope, no explicit
 *    public_repo restriction, or docker image with unscoped env token).
 *
 *  Axis 2 — Toxic tool combination (GTF-100..199):
 *    A single GitHub MCP server exposes both a read-issue/PR tool AND an
 *    external-write/exfiltration tool (e.g. create_gist, push_files, search +
 *    webhook relay), allowing a prompt-injected issue to drive data out.
 *
 *  Axis 3 — Untrusted input route (GTF-200..299):
 *    Webhook or issue-event configuration (GitHub Actions workflow, Express
 *    handler, or similar) passes raw issue body / PR description into agent
 *    context (system prompt, LLM call, tool invocation) without sanitization.
 */

import * as yaml from 'js-yaml';
import * as fs from 'fs';
import * as path from 'path';
import { ScannerModule, ScanResult, Finding, McpServerEntry, ScannerOptions } from '../types';
import { findConfigFiles, readFileContent, isJsonFile, isYamlFile, tryParseJson } from '../utils/file-utils';
import { walkFiles } from '../utils/file-walker';

// ============================================================
// Constants
// ============================================================

const SCANNER_NAME = 'GitHub MCP Toxic Flow Scanner';
const SCANNER_TAG = 'github-toxic-flow-scanner';

const SKIP_PATTERNS = [
  /package\.json$/,
  /tsconfig\.json$/,
  /pubspec\.yaml$/,
  /\.eslintrc/,
  /jest\.config/,
  /release-please/,
  /renovate/,
  /dependabot/,
];

const LAUNCHERS = ['npx', 'bunx', 'pnpx', 'yarn', 'pnpm', 'docker'];

// ============================================================
// Axis 1: GitHub server identity detection
// ============================================================

/** Known package identifiers for the official GitHub MCP server. */
const GITHUB_MCP_PACKAGES = [
  '@modelcontextprotocol/server-github',
  'github-mcp-server',
  'ghcr.io/github/github-mcp-server',
  'mcp-server-github',
];

/** Returns true if the server entry appears to be a GitHub MCP server. */
function isGitHubMcpServer(server: McpServerEntry): boolean {
  const command = (server.command ?? '').trim().toLowerCase();
  const args = ((server.args ?? []) as unknown[])
    .filter((a): a is string => typeof a === 'string')
    .map(a => a.toLowerCase());
  const argsStr = args.join(' ');
  const envStr = JSON.stringify(server.env ?? {}).toLowerCase();

  // Direct invocation
  if (GITHUB_MCP_PACKAGES.some(p => command.includes(p.toLowerCase()))) return true;

  // Launcher-based
  const baseName = command.split(/[/\\]/).pop() ?? command;
  if (LAUNCHERS.includes(baseName)) {
    if (GITHUB_MCP_PACKAGES.some(p => argsStr.includes(p.toLowerCase()))) return true;
  }

  // Env var hint: GITHUB_PERSONAL_ACCESS_TOKEN without any other strong signal
  if (envStr.includes('github_personal_access_token') || envStr.includes('github_token') || envStr.includes('gh_token')) {
    // Only count as a GitHub server if args/command look like an MCP server
    if (/github/i.test(command + ' ' + argsStr)) return true;
  }

  return false;
}

// ============================================================
// Axis 1 helpers: token scope analysis
// ============================================================

/**
 * Determines whether a token value string (env var value or env var name)
 * indicates full-repo (private) scope.
 *
 * Classic fine-grained PATs carry `repo` in the token header; classic tokens
 * are opaque. We rely on absence of explicit public_repo/read-only indicators.
 */
function hasPrivateRepoScope(server: McpServerEntry): {
  verdict: 'confirmed-private' | 'likely-private' | 'public-only' | 'unknown';
  evidence: string;
} {
  const env = server.env ?? {};
  const args = ((server.args ?? []) as unknown[]).filter((a): a is string => typeof a === 'string');
  const argsStr = args.join(' ');

  // Explicit scope restriction via args (e.g. --toolsets=repos:public)
  const hasPublicOnlyFlag =
    /--toolsets[= ][^\s]*public[^\s]*/i.test(argsStr) ||
    /--read[_-]?only/i.test(argsStr) ||
    /--public[_-]?only/i.test(argsStr);

  if (hasPublicOnlyFlag) {
    return { verdict: 'public-only', evidence: 'explicit public-only flag in args' };
  }

  const tokenKeys = ['GITHUB_PERSONAL_ACCESS_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_PAT'];
  for (const key of tokenKeys) {
    const val = env[key];
    if (typeof val === 'string') {
      if (val.startsWith('${') || val.startsWith('$') || val === '') {
        // Env-var reference — we cannot inspect the token value, assume broad scope
        return {
          verdict: 'likely-private',
          evidence: `${key} is set via env reference (${val}) — scope not restricted in config`,
        };
      }
      // Literal token present
      return {
        verdict: 'confirmed-private',
        evidence: `${key} contains a literal token value — full repo scope assumed`,
      };
    }
  }

  // No token key found but server identified as GitHub MCP
  return {
    verdict: 'unknown',
    evidence: 'no GITHUB_TOKEN/GITHUB_PAT env var found in server config',
  };
}

// ============================================================
// Axis 2: Toxic tool combination
// ============================================================

/**
 * Tool name patterns that indicate the server can READ issue/PR content.
 * (These are the untrusted-input source half of the toxic pair.)
 */
const READ_ISSUE_TOOLS = [
  /^get_issue$/i,
  /^list_issues$/i,
  /^list_issues_and_prs$/i,
  /^get_pull_request$/i,
  /^list_pull_requests$/i,
  /^get_issue_comments$/i,
  /^get_pull_request_comments$/i,
  /^search_issues$/i,
  /^search_code$/i,          // Can fetch private code via prompt-injected query
  /^get_file_contents$/i,    // Can read private files
  /^list_commits$/i,
];

/**
 * Tool name patterns that indicate the server can WRITE to external targets,
 * exfiltrate data, or relay content to a networked destination.
 */
const EXTERNAL_WRITE_TOOLS = [
  /^create_gist$/i,
  /^update_gist$/i,
  /^push_files$/i,
  /^create_or_update_file$/i,
  /^create_issue_comment$/i,   // Can relay secrets as a comment to attacker-owned repo
  /^create_issue$/i,
  /^create_pull_request$/i,
  /^fork_repository$/i,
  /^create_repository$/i,
  /^send_webhook$/i,
  /^http_request$/i,
  /^web_fetch$/i,
  /^fetch$/i,
  /^post_to_slack$/i,
  /^send_email$/i,
];

interface ToolNameList {
  readIssueTools: string[];
  externalWriteTools: string[];
}

function extractToolNames(server: McpServerEntry): ToolNameList {
  const readIssueTools: string[] = [];
  const externalWriteTools: string[] = [];

  const tools = Array.isArray(server.tools) ? server.tools : [];
  for (const t of tools) {
    if (typeof t !== 'object' || t === null) continue;
    const name = (t as Record<string, unknown>).name;
    if (typeof name !== 'string') continue;

    if (READ_ISSUE_TOOLS.some(p => p.test(name))) readIssueTools.push(name);
    if (EXTERNAL_WRITE_TOOLS.some(p => p.test(name))) externalWriteTools.push(name);
  }

  return { readIssueTools, externalWriteTools };
}

/**
 * Returns true if the tool list for the server includes ALL GitHub MCP tools
 * (i.e., the wildcard / unrestricted case — when no explicit tool allowlist is
 * configured, the GitHub MCP server exposes every capability by default).
 */
function isUnrestrictedToolset(server: McpServerEntry): boolean {
  // No tools array defined → server exposes all tools by default
  if (!Array.isArray(server.tools) || server.tools.length === 0) return true;
  // Explicit allowlist containing wildcard
  return false;
}

// ============================================================
// Axis 3: Untrusted input route detection (source-code scan)
// ============================================================

/**
 * Patterns that indicate issue/PR body is being used as raw input for an LLM
 * or agent without sanitization.
 *
 * We look for co-occurrence (within ~10 lines) of:
 *   A) an issue/PR body/title read expression
 *   B) an LLM/agent context insertion expression
 */

const UNTRUSTED_CONTENT_PATTERNS = [
  // GitHub Actions: ${{ github.event.issue.body }}
  /\$\{\{\s*github\.event\.issue\.body\s*\}\}/,
  /\$\{\{\s*github\.event\.issue\.title\s*\}\}/,
  /\$\{\{\s*github\.event\.pull_request\.body\s*\}\}/,
  /\$\{\{\s*github\.event\.pull_request\.title\s*\}\}/,
  /\$\{\{\s*github\.event\.comment\.body\s*\}\}/,
  // JS/TS webhook payloads
  /(?:issue|payload|event|body)\s*[\.\[]['"]?(?:body|title|description|content)['"]?\s*[\.\]]/,
  /\.issue\s*[\.\[].*?\.body/,
  /issue(?:Body|Content|Text|Title)/i,
  /payload\.issue\b/,
  /webhook(?:Body|Payload|Event)/i,
  // Common express/fastify webhook handler variables
  /req\.body\.(?:issue|pull_request|comment)/,
];

const AGENT_CONTEXT_PATTERNS = [
  // System prompt / message construction
  /system(?:Prompt|Message|Content|_prompt|_message|_content)\s*[+=]/i,
  /messages\s*\.push\s*\(/i,
  /\{\s*role\s*:\s*['"](?:system|user)['"]/,
  /client\.messages\.create/i,
  /openai\.chat\.completions\.create/i,
  /anthropic\.messages\.create/i,
  /llm\.(?:invoke|call|complete|chat|predict)\s*\(/i,
  /agent\.(?:invoke|run|execute|chat)\s*\(/i,
  /chain\.(?:invoke|run|call)\s*\(/i,
  /HumanMessage\s*\(/i,
  /SystemMessage\s*\(/i,
  /ChatPromptTemplate/i,
  /PromptTemplate\s*\.from/i,
  // Interpolated template strings containing untrusted variable names
  /`[^`]*\$\{[^`]*(?:issue|body|title|description|payload|webhook)[^`]*\}[^`]*`/i,
];

/**
 * Returns true if the given source line (or surrounding window) looks like
 * it sanitizes issue content before use.
 */
const SANITIZATION_MARKERS = [
  /sanitize\s*\(/i,
  /escape\s*\(/i,
  /clean\s*\(/i,
  /strip(?:Html|Tags|Markdown|Injection|Unsafe)\s*\(/i,
  /DOMPurify/i,
  /xss\s*\(/i,
  /validateIssue/i,
  /assertSafe/i,
  /isTrusted/i,
  /trusted_content/i,
  /allowedPattern/i,
];

interface UntrustedInputHit {
  file: string;
  line: number;
  snippet: string;
  untrustedPattern: string;
  agentContextPattern: string;
}

/**
 * Scan a single source file for co-occurrence of untrusted input + agent context
 * insertion within a WINDOW of lines.
 */
const COOCCURRENCE_WINDOW = 15;

function scanFileForUntrustedInputRoute(filePath: string): UntrustedInputHit[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const lines = content.split('\n');
  const hits: UntrustedInputHit[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const matchedUntrusted = UNTRUSTED_CONTENT_PATTERNS.find(p => p.test(line));
    if (!matchedUntrusted) continue;

    // Check window around this line for agent context usage
    const windowStart = Math.max(0, i - COOCCURRENCE_WINDOW);
    const windowEnd = Math.min(lines.length - 1, i + COOCCURRENCE_WINDOW);
    const window = lines.slice(windowStart, windowEnd + 1).join('\n');

    // Skip if sanitization is present in the same window
    if (SANITIZATION_MARKERS.some(p => p.test(window))) continue;

    const matchedAgent = AGENT_CONTEXT_PATTERNS.find(p => p.test(window));
    if (!matchedAgent) continue;

    hits.push({
      file: filePath,
      line: i + 1,
      snippet: line.trim().substring(0, 150),
      untrustedPattern: matchedUntrusted.toString(),
      agentContextPattern: matchedAgent.toString(),
    });
  }

  return hits;
}

// ============================================================
// Source file extensions to scan for Axis 3
// ============================================================

const SOURCE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.kt', '.cs',
  '.yml', '.yaml',  // GitHub Actions workflows
]);

const SOURCE_SKIP_PATTERNS = [
  /node_modules/,
  /\.git\//,
  /dist\//,
  /build\//,
  /coverage\//,
  /\.min\.(js|css)$/,
];

// ============================================================
// Main scanner
// ============================================================

export const githubToxicFlowScanner: ScannerModule = {
  name: SCANNER_NAME,
  description:
    'Detects the GitHub MCP Toxic Agent Flow (OWASP MCP06): MCP config with private-repo scope, ' +
    'toxic tool combinations (read-issue + external-write), and untrusted issue content flowing into agent context.',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // ── Axis 1 & 2: config file scan ──────────────────────────────────────
    const configFiles = await findConfigFiles(
      targetPath,
      options?.exclude,
      options?.includeVendored,
      options?.sentoriIgnorePatterns,
    );

    for (const file of configFiles) {
      if (SKIP_PATTERNS.some(p => p.test(file))) continue;

      let parsed: unknown = null;
      try {
        const content = readFileContent(file);
        if (isJsonFile(file)) parsed = tryParseJson(content);
        else if (isYamlFile(file)) parsed = yaml.load(content);
      } catch {
        continue;
      }

      if (!parsed || typeof parsed !== 'object') continue;

      findings.push(...scanConfigForGitHubToxicFlow(parsed as Record<string, unknown>, file));
    }

    // ── Axis 3: source-code scan ─────────────────────────────────────────
    const sourceFiles = collectSourceFiles(targetPath, options);
    for (const file of sourceFiles) {
      const hits = scanFileForUntrustedInputRoute(file);
      for (const hit of hits) {
        findings.push({
          id: `GTF-201-${path.basename(hit.file)}-L${hit.line}`,
          scanner: SCANNER_TAG,
          severity: 'high',
          rule: 'GTF-201',
          title: 'GitHub issue/PR content flows into agent context without sanitization',
          description:
            `Line ${hit.line} reads untrusted GitHub issue/PR content (matched: ${hit.untrustedPattern}) ` +
            `and passes it into an LLM/agent call (matched: ${hit.agentContextPattern}) ` +
            `with no sanitization detected in the surrounding ${COOCCURRENCE_WINDOW}-line window. ` +
            `A malicious issue body can inject arbitrary instructions into the agent (OWASP MCP06). ` +
            `Snippet: "${hit.snippet}"`,
          file: hit.file,
          line: hit.line,
          recommendation:
            'Sanitize issue body/title before using it as LLM input. ' +
            'Strip Markdown, HTML, and any text matching prompt-injection patterns. ' +
            'Consider wrapping untrusted content in a clearly delimited block ' +
            '("The following is untrusted user content: ...") and instruct the model not to follow instructions within it.',
          confidence: 'likely',
        });
      }
    }

    // Set confidence on config findings
    for (const f of findings) {
      if (!f.confidence) f.confidence = 'definite';
    }

    return {
      scanner: SCANNER_NAME,
      findings,
      scannedFiles: configFiles.length + sourceFiles.length,
      duration: Date.now() - start,
    };
  },
};

// ============================================================
// Config-level analysis (Axes 1 & 2)
// ============================================================

export function scanConfigForGitHubToxicFlow(
  config: Record<string, unknown>,
  filePath?: string,
): Finding[] {
  const findings: Finding[] = [];

  const mcpServers =
    (config.mcpServers ?? config.mcp_servers ?? config.servers) as
    | Record<string, McpServerEntry>
    | undefined;

  if (!mcpServers || typeof mcpServers !== 'object') return findings;

  for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
    if (!isGitHubMcpServer(serverConfig)) continue;

    // ── Axis 1: private-repo scope ───────────────────────────────────────
    const scopeResult = hasPrivateRepoScope(serverConfig);

    if (scopeResult.verdict === 'confirmed-private') {
      findings.push({
        id: `GTF-001-${serverName}`,
        scanner: SCANNER_TAG,
        severity: 'critical',
        rule: 'GTF-001',
        title: `GitHub MCP server "${serverName}" has a literal token with full private-repo scope`,
        description:
          `The server "${serverName}" stores a literal GitHub token (GITHUB_TOKEN/GITHUB_PAT) in the MCP config. ` +
          `Classic PATs with \`repo\` scope grant full read/write access to all private repositories. ` +
          `Combined with prompt injection via a malicious issue, an agent can exfiltrate any private file. ` +
          `Evidence: ${scopeResult.evidence}`,
        file: filePath,
        recommendation:
          'Replace the literal token with an env-var reference (${GITHUB_TOKEN}). ' +
          'Create a fine-grained PAT scoped to specific repositories with minimum required permissions. ' +
          'If only public repos are needed, use a token with `public_repo` scope only.',
      });
    } else if (scopeResult.verdict === 'likely-private') {
      findings.push({
        id: `GTF-002-${serverName}`,
        scanner: SCANNER_TAG,
        severity: 'high',
        rule: 'GTF-002',
        title: `GitHub MCP server "${serverName}" token scope is unrestricted — private repo leakage risk`,
        description:
          `The server "${serverName}" uses a GitHub token (${scopeResult.evidence}) with no explicit ` +
          `public-only restriction. If the token carries \`repo\` scope, a prompt-injected issue can ` +
          `instruct the agent to read private repository files and exfiltrate them (OWASP MCP06 / Invariant Labs PoC). ` +
          `No \`--public-only\` flag or \`--toolsets=repos:public\` restriction detected in args.`,
        file: filePath,
        recommendation:
          'Restrict the GitHub token to `public_repo` scope if private repos are not required. ' +
          'Use a fine-grained PAT limited to specific repositories. ' +
          'Add `--toolsets=repos:public` or equivalent arg if supported by the server version. ' +
          'Review the Invariant Labs GitHub MCP PoC for full attack surface details.',
      });
    }

    // GTF-003: No scope restriction and unrestricted toolset
    if (scopeResult.verdict !== 'public-only' && isUnrestrictedToolset(serverConfig)) {
      findings.push({
        id: `GTF-003-${serverName}`,
        scanner: SCANNER_TAG,
        severity: 'high',
        rule: 'GTF-003',
        title: `GitHub MCP server "${serverName}" exposes all tools with no explicit allowlist`,
        description:
          `The server "${serverName}" has no \`tools\` allowlist, meaning all GitHub MCP tools are ` +
          `available to the agent by default. This includes high-risk tools such as \`search_code\`, ` +
          `\`get_file_contents\`, \`create_gist\`, \`push_files\`, and \`create_issue_comment\`. ` +
          `Without an allowlist, a single prompt-injected issue can chain read + write tools to exfiltrate data.`,
        file: filePath,
        recommendation:
          'Configure an explicit tool allowlist in the MCP server config (tools: [...]). ' +
          'Only permit the tools your agent actually needs. ' +
          'Separate read-only tools (get_file_contents, list_issues) from write/exfil tools (create_gist, push_files) ' +
          'and remove write tools if not required for your use case.',
      });
    }

    // ── Axis 2: toxic tool combination ──────────────────────────────────
    if (Array.isArray(serverConfig.tools) && serverConfig.tools.length > 0) {
      const { readIssueTools, externalWriteTools } = extractToolNames(serverConfig);

      if (readIssueTools.length > 0 && externalWriteTools.length > 0) {
        findings.push({
          id: `GTF-101-${serverName}`,
          scanner: SCANNER_TAG,
          severity: 'critical',
          rule: 'GTF-101',
          title: `GitHub MCP server "${serverName}" has toxic tool combination: read-issue + external-write`,
          description:
            `Server "${serverName}" exposes tools that can READ untrusted issue/PR content ` +
            `(${readIssueTools.join(', ')}) AND tools that can WRITE to external targets ` +
            `(${externalWriteTools.join(', ')}). ` +
            `This is the exact tool combination exploited in the Invariant Labs GitHub MCP PoC: ` +
            `a malicious issue body injects instructions, the read tool surfaces the content to the agent, ` +
            `and the write tool exfiltrates private data (OWASP MCP06 Intent Flow Subversion).`,
          file: filePath,
          recommendation:
            'Remove external-write tools from the GitHub MCP server allowlist if not required. ' +
            'Separate reading and writing concerns into distinct MCP servers with different trust levels. ' +
            'Apply human-in-the-loop confirmation gates before any write/publish operation triggered from issue content.',
        });
      } else if (readIssueTools.length > 0 && scopeResult.verdict !== 'public-only') {
        // Has read-issue tools but write tools are absent — still worth flagging if scope is broad
        findings.push({
          id: `GTF-102-${serverName}`,
          scanner: SCANNER_TAG,
          severity: 'medium',
          rule: 'GTF-102',
          title: `GitHub MCP server "${serverName}" can read issue content with broad token scope`,
          description:
            `Server "${serverName}" exposes issue/PR read tools (${readIssueTools.join(', ')}) ` +
            `with a token that may have private-repo scope. Even without an explicit exfil tool, ` +
            `a prompt-injected issue could instruct the agent to relay data via other configured MCP servers ` +
            `(cross-server chain attack). Confirm no network/HTTP-capable server is co-configured.`,
          file: filePath,
          recommendation:
            'Audit all co-configured MCP servers for network-write capability. ' +
            'Restrict the GitHub token to public_repo scope if private data must not be accessible. ' +
            'Add human confirmation before the agent acts on issue body content.',
        });
      }
    }
  }

  return findings;
}

// ============================================================
// Collect source files for Axis 3
// ============================================================

function collectSourceFiles(
  targetPath: string,
  options?: ScannerOptions,
): string[] {
  try {
    const entries = walkFiles(targetPath, {
      extensions: SOURCE_EXTENSIONS,
      includeVendored: options?.includeVendored ?? false,
    });
    return entries
      .map(e => e.path)
      .filter(f => !SOURCE_SKIP_PATTERNS.some(p => p.test(f)));
  } catch {
    return [];
  }
}
