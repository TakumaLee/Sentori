import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

// Use dynamic import for chokidar (ESM-compatible)
let chokidar: typeof import('chokidar');

export type ChangeType = 'config' | 'package' | 'mcp';

export interface WatchEvent {
  type: ChangeType;
  filePath: string;
}

const PACKAGE_SCANNERS = [
  'SupplyChainScanner',
  'NPM Attestation Scanner',
  'PostinstallScanner',
  'ConventionSquattingScanner',
];

const MCP_SCANNERS = [
  'MCP Config Auditor',
  'MCP Tool Manifest Scanner',
  'MCP Tool Shadowing Detector',
  'MCP OAuth Auditor',
  'MCP Git CVE Scanner',
  'MCP Sampling Abuse Scanner',
  'MCP Tool Result Injection Scanner',
];

/**
 * Return which scanners to re-run for a given change type.
 * null = run all scanners (config changed).
 */
export function getAffectedScanners(type: ChangeType): string[] | null {
  switch (type) {
    case 'config':
      return null;
    case 'package':
      return PACKAGE_SCANNERS;
    case 'mcp':
      return MCP_SCANNERS;
  }
}

function classifyChange(filePath: string): ChangeType {
  const base = path.basename(filePath);
  if (base === '.sentori.yml' || base === '.sentori.yaml') return 'config';
  if (base === 'package.json') return 'package';
  return 'mcp';
}

function getMcpConfigPaths(targetDir: string): string[] {
  const paths: string[] = [];
  const platform = os.platform();

  // Project-local MCP config
  paths.push(path.join(targetDir, '.mcp.json'));

  if (platform === 'darwin') {
    const appSupport = path.join(os.homedir(), 'Library', 'Application Support', 'Claude');
    paths.push(path.join(appSupport, 'claude_desktop_config.json'));
  } else {
    const configDir = path.join(os.homedir(), '.config', 'claude');
    paths.push(path.join(configDir, 'claude_desktop_config.json'));
  }

  // Cursor MCP configs
  const cursorDir = path.join(os.homedir(), '.cursor');
  paths.push(path.join(cursorDir, 'mcp.json'));

  return paths;
}

const DEBOUNCE_MS = 500;

export async function startWatcher(
  targetDir: string,
  onChange: (scanners: string[] | null, changedPaths: string[]) => void
): Promise<() => void> {
  // Lazy-load chokidar
  if (!chokidar) {
    chokidar = await import('chokidar');
  }

  const watchPaths: string[] = [
    path.join(targetDir, '.sentori.yml'),
    path.join(targetDir, '.sentori.yaml'),
    path.join(targetDir, 'package.json'),
    ...getMcpConfigPaths(targetDir),
  ];

  // Only watch paths that exist or whose parent directory exists
  const validPaths = watchPaths.filter((p) => {
    return fs.existsSync(p) || fs.existsSync(path.dirname(p));
  });

  const watcher = chokidar.watch(validPaths, {
    ignoreInitial: true,
    awaitWriteFinish: { stabilityThreshold: 200 },
  });

  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingEvents: WatchEvent[] = [];

  const flush = () => {
    if (pendingEvents.length === 0) return;

    const changedPaths = pendingEvents.map((e) => e.filePath);
    const hasConfig = pendingEvents.some((e) => e.type === 'config');

    let scanners: string[] | null;
    if (hasConfig) {
      // config change → re-run everything
      scanners = null;
    } else {
      // union all affected scanner sets across all change types
      const types = new Set(pendingEvents.map((e) => e.type));
      const merged: string[] = [];
      if (types.has('package')) merged.push(...PACKAGE_SCANNERS);
      if (types.has('mcp')) merged.push(...MCP_SCANNERS);
      scanners = merged;
    }

    pendingEvents = [];
    onChange(scanners, changedPaths);
  };

  const onFileChange = (filePath: string) => {
    const type = classifyChange(filePath);
    pendingEvents.push({ type, filePath });

    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(flush, DEBOUNCE_MS);
  };

  watcher.on('change', onFileChange);
  watcher.on('add', onFileChange);
  watcher.on('unlink', onFileChange);

  // Return cleanup function
  return () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    watcher.close();
  };
}
