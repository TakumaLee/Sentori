/**
 * --discover mode: auto-scan common agent config paths
 */
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import chalk from 'chalk';
import { auditConfig } from './scanners/mcp-config-auditor';
import { Finding } from './types';

const HOME = os.homedir();

interface DiscoverTarget {
  label: string;
  path: string;
  type: 'mcp' | 'claude' | 'cursor' | 'gemini' | 'continue' | 'generic';
}

function getDiscoverTargets(): DiscoverTarget[] {
  const targets: DiscoverTarget[] = [
    // Claude Desktop
    { label: 'Claude Desktop (macOS)', path: path.join(HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), type: 'mcp' },
    { label: 'Claude Desktop (Linux)', path: path.join(HOME, '.config', 'claude', 'claude_desktop_config.json'), type: 'mcp' },
    // Claude Code (Claude CLI)
    { label: 'Claude Code settings', path: path.join(HOME, '.claude', 'settings.json'), type: 'claude' },
    { label: 'Claude Code CLAUDE.md', path: path.join(HOME, '.claude', 'CLAUDE.md'), type: 'claude' },
    // Cursor
    { label: 'Cursor MCP config', path: path.join(HOME, '.cursor', 'mcp.json'), type: 'mcp' },
    { label: 'Cursor settings', path: path.join(HOME, '.cursor', 'settings.json'), type: 'cursor' },
    // Gemini CLI
    { label: 'Gemini CLI config', path: path.join(HOME, '.config', 'gemini', 'config.json'), type: 'gemini' },
    { label: 'Gemini CLI settings', path: path.join(HOME, '.gemini', 'settings.json'), type: 'gemini' },
    // Continue
    { label: 'Continue AI config', path: path.join(HOME, '.continue', 'config.yaml'), type: 'continue' },
    { label: 'Continue AI config (JSON)', path: path.join(HOME, '.continue', 'config.json'), type: 'continue' },
    // Windsurf
    { label: 'Windsurf MCP config', path: path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json'), type: 'mcp' },
    // Local .mcp.json
    { label: '.mcp.json (cwd)', path: path.join(process.cwd(), '.mcp.json'), type: 'mcp' },
    { label: '.cursor/mcp.json (cwd)', path: path.join(process.cwd(), '.cursor', 'mcp.json'), type: 'mcp' },
  ];
  return targets;
}

export async function runDiscover(): Promise<void> {
  console.log('');
  console.log(chalk.bold.cyan('  🔍 Sentori — Agent Config Discovery'));
  console.log(chalk.gray('  Scanning common agent configuration paths...'));
  console.log('');

  const targets = getDiscoverTargets();
  const found: DiscoverTarget[] = [];
  const allFindings: Array<{ target: DiscoverTarget; findings: Finding[] }> = [];

  // Scan each target
  for (const target of targets) {
    if (!fs.existsSync(target.path)) continue;
    found.push(target);

    let findings: Finding[] = [];
    try {
      const ext = path.extname(target.path).toLowerCase();
      if (ext === '.json') {
        const content = fs.readFileSync(target.path, 'utf-8');
        const parsed = JSON.parse(content);
        if (parsed && typeof parsed === 'object') {
          findings = auditConfig(parsed as Record<string, unknown>, target.path);
        }
      }
      // YAML parsing for .yaml/.yml files would go here
    } catch {
      // skip unreadable
    }

    allFindings.push({ target, findings });
  }

  if (found.length === 0) {
    console.log(chalk.gray('  No agent config files found in common locations.'));
    console.log(chalk.gray('  Run `sentori scan [dir]` to scan a specific directory.'));
    console.log('');
    return;
  }

  // Report discovered files
  console.log(chalk.bold(`  Found ${found.length} config file(s):`));
  console.log('');

  let totalFindings = 0;
  for (const { target, findings } of allFindings) {
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const otherCount = findings.filter(f => f.severity !== 'critical' && f.severity !== 'high').length;

    const statusIcon = criticalCount > 0 ? '🔴' : highCount > 0 ? '🟠' : findings.length > 0 ? '🟡' : '✅';
    console.log(`  ${statusIcon} ${chalk.bold(target.label)}`);
    console.log(chalk.gray(`     ${target.path}`));

    if (findings.length > 0) {
      const parts = [
        criticalCount > 0 ? chalk.red(`${criticalCount} critical`) : null,
        highCount > 0 ? chalk.hex('#FF8C00')(`${highCount} high`) : null,
        otherCount > 0 ? chalk.yellow(`${otherCount} other`) : null,
      ].filter(Boolean);
      console.log(chalk.gray(`     Issues: ${parts.join(', ')}`));

      for (const f of findings) {
        const sev = f.severity === 'critical' ? chalk.red(f.severity) : f.severity === 'high' ? chalk.hex('#FF8C00')(f.severity) : chalk.yellow(f.severity);
        console.log(`       → [${sev}] ${f.title}`);
        if (f.recommendation) console.log(chalk.green(`          💡 ${f.recommendation}`));
      }
      totalFindings += findings.length;
    }
    console.log('');
  }

  if (totalFindings > 0) {
    console.log(chalk.yellow(`  ⚠️  ${totalFindings} issue(s) found across discovered configs.`));
    console.log(chalk.gray('  Run `sentori scan <dir>` for a full security report on a specific directory.'));
  } else {
    console.log(chalk.green('  ✅ No issues found in discovered configs.'));
  }
  console.log('');
}
