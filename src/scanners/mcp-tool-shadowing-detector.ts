/**
 * MCP Tool Shadowing Detector (sentori-scanner-002)
 *
 * Detects tool names that mimic legitimate MCP server tool names to intercept
 * calls via lookalike naming (e.g. `filesystem_tool` vs `filesystem-tool`,
 * `read__file` vs `read_file`, `Bash` vs `bash`).
 *
 * Detection rules:
 *  SHADOW-001 — Lookalike tool name: high similarity to a known canonical tool
 *               (Levenshtein distance <= threshold, or normalized match)
 *  SHADOW-002 — Separator substitution: identical name with - / _ / __ swap
 *  SHADOW-003 — Case-only difference: tool names that differ only in casing
 */

import * as yaml from 'js-yaml';
import { ScannerModule, ScanResult, Finding, McpServerEntry, ScannerOptions } from '../types';
import {
  findConfigFiles,
  readFileContent,
  isJsonFile,
  isYamlFile,
  tryParseJson,
  isCacheOrDataFile,
} from '../utils/file-utils';

// ============================================================
// Known canonical MCP server names
// Source: official MCP servers (github.com/modelcontextprotocol/servers)
// Used to detect server-key shadowing in mcpServers configs
// ============================================================

export const CANONICAL_SERVER_NAMES: string[] = [
  'filesystem',
  'memory',
  'git',
  'github',
  'gitlab',
  'google-drive',
  'google-maps',
  'puppeteer',
  'playwright',
  'brave-search',
  'sqlite',
  'postgres',
  'mysql',
  'redis',
  'slack',
  'sentry',
  'aws-kb-retrieval',
  'time',
  'fetch',
  'sequential-thinking',
  'everything',
];

// ============================================================
// Known canonical MCP tool names
// Source: official MCP servers + widely-deployed community servers
// ============================================================

export const CANONICAL_TOOL_NAMES: string[] = [
  // filesystem server
  'read_file',
  'read_multiple_files',
  'write_file',
  'edit_file',
  'create_directory',
  'list_directory',
  'directory_tree',
  'move_file',
  'search_files',
  'get_file_info',
  'list_allowed_directories',
  // fetch server
  'fetch',
  // memory server
  'create_entities',
  'create_relations',
  'add_observations',
  'delete_entities',
  'delete_observations',
  'delete_relations',
  'read_graph',
  'search_nodes',
  'open_nodes',
  // git server
  'git_status',
  'git_diff',
  'git_diff_staged',
  'git_diff_unstaged',
  'git_commit',
  'git_add',
  'git_reset',
  'git_log',
  'git_create_branch',
  'git_checkout',
  'git_show',
  'git_init',
  // github server
  'create_or_update_file',
  'search_repositories',
  'create_repository',
  'get_file_contents',
  'push_files',
  'create_issue',
  'create_pull_request',
  'fork_repository',
  'create_branch',
  'list_commits',
  'list_issues',
  'update_issue',
  'add_issue_comment',
  'search_code',
  'search_issues',
  'search_users',
  'get_issue',
  // puppeteer / browser server
  'puppeteer_navigate',
  'puppeteer_screenshot',
  'puppeteer_click',
  'puppeteer_fill',
  'puppeteer_select',
  'puppeteer_hover',
  'puppeteer_evaluate',
  // brave-search
  'brave_web_search',
  'brave_local_search',
  // sqlite server
  'read_query',
  'write_query',
  'create_table',
  'list_tables',
  'describe_table',
  'append_insight',
  // postgres server
  'query',
  // slack server
  'slack_list_channels',
  'slack_post_message',
  'slack_reply_to_thread',
  'slack_add_reaction',
  'slack_get_channel_history',
  'slack_get_thread_replies',
  'slack_get_users',
  'slack_get_user_profile',
  // time server
  'get_current_time',
  'convert_time',
  // sequential thinking
  'sequentialthinking',
  // everything server (test/demo)
  'echo',
  'add',
  'longRunningOperation',
  'sampleLLM',
  'getTinyImage',
  // common agent patterns
  'bash',
  'computer',
  'text_editor',
  'web_search',
  'execute_command',
  'run_command',
  'shell',
];

// ============================================================
// Levenshtein distance (pure TypeScript, no external deps)
// ============================================================

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  // Use single-row DP to keep memory at O(n)
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,       // deletion
        curr[j - 1] + 1,   // insertion
        prev[j - 1] + cost, // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

/**
 * Normalize a tool name for comparison:
 * lowercase, collapse separator variants (-, _, __, space) to single underscore.
 */
export function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[-\s]+/g, '_').replace(/__+/g, '_');
}

/**
 * Returns true if `name` is a separator-only variant of `canonical`
 * (identical after normalization but different before).
 */
export function isSeparatorVariant(name: string, canonical: string): boolean {
  if (name === canonical) return false;
  return normalizeName(name) === normalizeName(canonical);
}

/**
 * Returns true if `name` is a case-only variant of `canonical`
 * (identical after lowercasing but different before, and same separators).
 */
export function isCaseVariant(name: string, canonical: string): boolean {
  if (name === canonical) return false;
  return name.toLowerCase() === canonical.toLowerCase();
}

// Levenshtein similarity threshold: flag if distance <= this value
// For short names (<=5 chars) use 1, for longer names use 2
function distanceThreshold(canonical: string): number {
  return canonical.length <= 5 ? 1 : 2;
}

export interface ShadowMatch {
  canonical: string;
  rule: 'SHADOW-001' | 'SHADOW-002' | 'SHADOW-003';
  distance: number;
  reason: string;
}

/**
 * Check if `toolName` shadows any canonical tool.
 * Returns the first (most specific) match, or null.
 */
export function detectShadowing(toolName: string): ShadowMatch | null {
  // SHADOW-003: case-only difference (exact after lowercasing)
  for (const canonical of CANONICAL_TOOL_NAMES) {
    if (isCaseVariant(toolName, canonical)) {
      return {
        canonical,
        rule: 'SHADOW-003',
        distance: 0,
        reason: `Case-only difference: "${toolName}" vs canonical "${canonical}"`,
      };
    }
  }

  // SHADOW-002: separator substitution (exact after normalizing separators)
  for (const canonical of CANONICAL_TOOL_NAMES) {
    if (isSeparatorVariant(toolName, canonical)) {
      return {
        canonical,
        rule: 'SHADOW-002',
        distance: 0,
        reason: `Separator substitution: "${toolName}" normalizes to same as canonical "${canonical}"`,
      };
    }
  }

  // SHADOW-001: lookalike by Levenshtein distance
  // Compare lowercased to avoid duplicate case findings
  const lowerTool = toolName.toLowerCase();
  for (const canonical of CANONICAL_TOOL_NAMES) {
    // Skip exact match (legitimate tool registered directly)
    if (lowerTool === canonical.toLowerCase()) return null;

    const threshold = distanceThreshold(canonical);
    const dist = levenshtein(lowerTool, canonical.toLowerCase());
    if (dist > 0 && dist <= threshold) {
      return {
        canonical,
        rule: 'SHADOW-001',
        distance: dist,
        reason: `Lookalike name: "${toolName}" is within edit distance ${dist} of canonical "${canonical}"`,
      };
    }
  }

  return null;
}

/**
 * Check if `serverName` shadows any canonical MCP server name.
 * Uses the same SHADOW-001/002/003 rules as tool shadowing.
 * Returns the first (most specific) match, or null.
 */
export function detectServerShadowing(serverName: string): ShadowMatch | null {
  // SHADOW-003: case-only difference
  for (const canonical of CANONICAL_SERVER_NAMES) {
    if (isCaseVariant(serverName, canonical)) {
      return {
        canonical,
        rule: 'SHADOW-003',
        distance: 0,
        reason: `Case-only difference: server "${serverName}" vs canonical server "${canonical}"`,
      };
    }
  }

  // SHADOW-002: separator substitution
  for (const canonical of CANONICAL_SERVER_NAMES) {
    if (isSeparatorVariant(serverName, canonical)) {
      return {
        canonical,
        rule: 'SHADOW-002',
        distance: 0,
        reason: `Separator substitution: server "${serverName}" normalizes to same as canonical server "${canonical}"`,
      };
    }
  }

  // SHADOW-001: lookalike by Levenshtein distance
  const lowerServer = serverName.toLowerCase();
  for (const canonical of CANONICAL_SERVER_NAMES) {
    if (lowerServer === canonical.toLowerCase()) return null;

    const threshold = distanceThreshold(canonical);
    const dist = levenshtein(lowerServer, canonical.toLowerCase());
    if (dist > 0 && dist <= threshold) {
      return {
        canonical,
        rule: 'SHADOW-001',
        distance: dist,
        reason: `Lookalike server name: "${serverName}" is within edit distance ${dist} of canonical server "${canonical}"`,
      };
    }
  }

  return null;
}

// ============================================================
// Scanner
// ============================================================

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

export const mcpToolShadowingDetector: ScannerModule = {
  name: 'MCP Tool Shadowing Detector',
  description:
    'Detects tool names that mimic legitimate MCP server tool names to intercept calls (lookalike naming, separator swaps, case differences)',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    const files = await findConfigFiles(
      targetPath,
      options?.exclude,
      options?.includeVendored,
      options?.sentoriIgnorePatterns,
    );

    for (const file of files) {
      if (SKIP_PATTERNS.some(p => p.test(file))) continue;

      let parsed: unknown = null;
      try {
        const content = readFileContent(file);

        if (isJsonFile(file)) {
          parsed = tryParseJson(content);
        } else if (isYamlFile(file)) {
          parsed = yaml.load(content);
        }
      } catch {
        continue;
      }

      if (!parsed || typeof parsed !== 'object') continue;

      const config = parsed as Record<string, unknown>;
      const mcpServers = (config.mcpServers || config.mcp_servers || config.servers) as
        | Record<string, McpServerEntry>
        | undefined;

      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [serverName, serverConfig] of Object.entries(mcpServers)) {
        if (!serverConfig || typeof serverConfig !== 'object') continue;

        const severity = isCacheOrDataFile(file) ? 'info' as const : 'high' as const;

        // --- Server-name shadowing check ---
        const serverMatch = detectServerShadowing(serverName);
        if (serverMatch) {
          const serverRuleDescriptions: Record<string, string> = {
            'SHADOW-001':
              `Lookalike server name detected. "${serverName}" is suspiciously similar to ` +
              `the canonical MCP server "${serverMatch.canonical}" (edit distance: ${serverMatch.distance}). ` +
              `A malicious actor can register a server under a near-identical key to intercept ` +
              `all tool calls routed to the legitimate server.`,
            'SHADOW-002':
              `Separator substitution detected in server name. "${serverName}" normalizes to the same key as ` +
              `canonical server "${serverMatch.canonical}" after collapsing separators (-, _, whitespace). ` +
              `Some MCP hosts resolve server keys case- or separator-insensitively, allowing silent hijacking.`,
            'SHADOW-003':
              `Case-shadowing detected in server name. "${serverName}" differs from canonical server ` +
              `"${serverMatch.canonical}" only in casing. Case-insensitive hosts may route calls ` +
              `to the wrong server.`,
          };

          findings.push({
            id: `${serverMatch.rule}-server-${serverName}`,
            scanner: 'mcp-tool-shadowing-detector',
            severity,
            rule: serverMatch.rule.toLowerCase(),
            title: `Server name shadowing risk: "${serverName}" mimics canonical server "${serverMatch.canonical}"`,
            description: serverRuleDescriptions[serverMatch.rule],
            evidence: serverMatch.reason,
            file,
            recommendation:
              'Verify that this server name is intentional and not a typosquat of an official MCP server. ' +
              'Use the exact canonical server key when adding official MCP servers to your config. ' +
              'Audit third-party servers whose names closely resemble well-known MCP server names.',
            confidence: 'likely',
          });
        }

        // --- Tool-name shadowing check (explicit tools[] array) ---
        const toolsList = serverConfig.tools;
        if (!Array.isArray(toolsList)) continue;

        for (const tool of toolsList) {
          if (!tool || typeof tool !== 'object') continue;
          const t = tool as Record<string, unknown>;
          const toolName = (t.name as string) || '';
          if (!toolName) continue;

          const match = detectShadowing(toolName);
          if (!match) continue;

          const ruleDescriptions: Record<string, string> = {
            'SHADOW-001':
              `Lookalike tool name detected. "${toolName}" in server "${serverName}" ` +
              `is suspiciously similar to canonical tool "${match.canonical}" ` +
              `(edit distance: ${match.distance}). ` +
              `A malicious MCP server can register a near-identical tool name to intercept ` +
              `calls intended for a trusted server, potentially exfiltrating data or ` +
              `executing unauthorized actions.`,
            'SHADOW-002':
              `Separator substitution detected. "${toolName}" in server "${serverName}" ` +
              `is identical to canonical tool "${match.canonical}" after normalizing separators ` +
              `(-, _, whitespace). This technique exploits ambiguous tool routing to shadow ` +
              `a legitimate tool and hijack its call traffic.`,
            'SHADOW-003':
              `Case-shadowing detected. "${toolName}" in server "${serverName}" ` +
              `differs from canonical tool "${match.canonical}" only in letter casing. ` +
              `Case-insensitive dispatchers may route calls to the wrong server, ` +
              `enabling silent interception.`,
          };

          findings.push({
            id: `${match.rule}-${serverName}-${toolName}`,
            scanner: 'mcp-tool-shadowing-detector',
            severity,
            rule: match.rule.toLowerCase(),
            title: `Tool shadowing risk: "${toolName}" mimics canonical "${match.canonical}"`,
            description: ruleDescriptions[match.rule],
            evidence: match.reason,
            file,
            recommendation:
              'Verify that this tool name is intentional and not a typosquat of a legitimate MCP tool. ' +
              'Use exact canonical names when integrating official MCP servers. ' +
              'Audit third-party MCP servers for lookalike tool registrations before adding them to your config.',
            confidence: 'likely',
          });
        }
      }
    }

    return {
      scanner: 'MCP Tool Shadowing Detector',
      findings,
      scannedFiles: files.length,
      duration: Date.now() - start,
    };
  },
};
