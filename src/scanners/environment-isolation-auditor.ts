import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { ScannerModule, ScanResult, Finding, Severity, ScannerOptions } from '../types';
import { findFiles, readFileContent } from '../utils/file-utils';

// ============================================================
// 1. Container / VM Detection
// ============================================================

export interface EnvironmentDetection {
  isDocker: boolean;
  isContainer: boolean; // docker or lxc
  isVM: boolean;
  unknown: boolean;
  details: string[];
}

export function detectEnvironment(): EnvironmentDetection {
  const result: EnvironmentDetection = {
    isDocker: false,
    isContainer: false,
    isVM: false,
    unknown: false,
    details: [],
  };

  const platform = os.platform();

  // Check /.dockerenv
  try {
    if (fs.existsSync('/.dockerenv')) {
      result.isDocker = true;
      result.isContainer = true;
      result.details.push('/.dockerenv exists → Docker detected');
    }
  } catch {
    // No permission — not an error
  }

  // Check /proc/1/cgroup for docker/lxc
  if (platform === 'linux') {
    try {
      const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf-8');
      if (/docker|lxc|containerd|kubepods/i.test(cgroup)) {
        result.isContainer = true;
        if (/docker|containerd/i.test(cgroup)) result.isDocker = true;
        result.details.push('/proc/1/cgroup contains container indicators');
      }
    } catch {
      // Not available or no permission
    }
  }

  // macOS VM detection via sysctl (we check the flag but don't exec commands)
  if (platform === 'darwin') {
    try {
      // On macOS, kern.hv_vmm_present is 1 inside a VM
      // We read via execSync since sysctl is a system command
      const { execSync } = require('child_process');
      const out = execSync('sysctl -n kern.hv_vmm_present 2>/dev/null', {
        encoding: 'utf-8',
        timeout: 3000,
      }).trim();
      if (out === '1') {
        result.isVM = true;
        result.details.push('kern.hv_vmm_present=1 → VM detected (macOS)');
      }
    } catch {
      // sysctl not available or errored — mark unknown only if no other detection
    }
  }

  // Linux VM detection: check /sys/class/dmi/id or /proc/cpuinfo
  if (platform === 'linux' && !result.isContainer) {
    try {
      const productName = fs.readFileSync('/sys/class/dmi/id/product_name', 'utf-8').toLowerCase();
      if (/virtualbox|vmware|qemu|kvm|xen|parallels|hyper-v|utm/i.test(productName)) {
        result.isVM = true;
        result.details.push(`/sys/class/dmi/id/product_name: ${productName.trim()} → VM detected`);
      }
    } catch {
      // Not available
    }
  }

  // If nothing detected
  if (!result.isDocker && !result.isContainer && !result.isVM) {
    result.unknown = true;
    result.details.push('No container or VM isolation detected');
  }

  return result;
}

// ============================================================
// 2. File Permission Checks
// ============================================================

const SENSITIVE_CONFIG_EXTENSIONS = ['.json', '.yaml', '.yml', '.env', '.toml'];
const SENSITIVE_CONTENT_PATTERNS = [
  /(?:api[_-]?key|apikey)\s*["']?\s*[:=]/i,
  /(?:secret|password|passwd|pwd|token)\s*["']?\s*[:=]/i,
  /(?:private[_-]?key|signing[_-]?key)\s*["']?\s*[:=]/i,
  /(?:database[_-]?url|connection[_-]?string)\s*["']?\s*[:=]/i,
  /(?:access[_-]?token|refresh[_-]?token)\s*["']?\s*[:=]/i,
  /sk-[A-Za-z0-9]{10,}/i,
  /ghp_[A-Za-z0-9]{20,}/i,
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/i,
];

export interface FilePermissionIssue {
  file: string;
  mode: number;
  issue: string;
}

/** Directory segments that indicate workspace/managed content, not deployable config. */
const WORKSPACE_CONTENT_DIRS = /[/\\](?:workspace|shared|coord|claims|reviews|state|team|projects|research|knowledge|intel|products|content-queue|drafts|skills|memory|workflows|cron-runs)[/\\]/i;

function isSensitiveConfigFile(filePath: string): boolean {
  const basename = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();

  // Handle dotfiles like .env, .env.local, .env.production
  if (basename === '.env' || basename.startsWith('.env.')) return true;

  // Skip workspace/managed content directories — these contain agent data
  // that naturally includes words like "token", "key" in non-secret contexts.
  if (WORKSPACE_CONTENT_DIRS.test(filePath)) return false;

  return SENSITIVE_CONFIG_EXTENSIONS.includes(ext);
}

export function checkFilePermissions(targetPath: string, files: string[]): FilePermissionIssue[] {
  const issues: FilePermissionIssue[] = [];

  // On Windows, file permission checks are not meaningful
  if (os.platform() === 'win32') return issues;

  for (const file of files) {
    if (!isSensitiveConfigFile(file)) continue;

    try {
      const content = readFileContent(file);
      const hasSensitiveContent = SENSITIVE_CONTENT_PATTERNS.some(p => p.test(content));
      if (!hasSensitiveContent) continue;

      const stat = fs.statSync(file);
      const mode = stat.mode;
      // Check world-readable (others read bit = 0o004)
      const worldReadable = (mode & 0o004) !== 0;
      if (worldReadable) {
        const modeStr = '0' + (mode & 0o777).toString(8);
        issues.push({
          file,
          mode: mode & 0o777,
          issue: `Sensitive config file is world-readable (${modeStr}). Recommended: 600 or 640.`,
        });
      }
    } catch {
      // Skip unreadable files
    }
  }

  return issues;
}

// ============================================================
// 3. Network Isolation (Static)
// ============================================================

export interface NetworkIsolationResult {
  hasDockerCompose: boolean;
  hasNetworkConfig: boolean;
  exposedPorts: string[];
  details: string[];
}

export function checkNetworkIsolation(targetPath: string, files: string[]): NetworkIsolationResult {
  const result: NetworkIsolationResult = {
    hasDockerCompose: false,
    hasNetworkConfig: false,
    exposedPorts: [],
    details: [],
  };

  for (const file of files) {
    const basename = path.basename(file).toLowerCase();
    try {
      const content = readFileContent(file);

      // docker-compose.yml network settings
      if (basename === 'docker-compose.yml' || basename === 'docker-compose.yaml') {
        result.hasDockerCompose = true;
        if (/\bnetworks?\s*:/i.test(content)) {
          result.hasNetworkConfig = true;
          result.details.push(`${file}: network configuration found`);
        }
        if (/network_mode\s*:\s*["']?none/i.test(content)) {
          result.hasNetworkConfig = true;
          result.details.push(`${file}: network_mode: none (isolated)`);
        }
      }

      // Dockerfile EXPOSE
      if (basename === 'dockerfile' || basename.startsWith('dockerfile.')) {
        const exposeMatches = content.match(/^EXPOSE\s+(.+)$/gmi);
        if (exposeMatches) {
          for (const m of exposeMatches) {
            const ports = m.replace(/^EXPOSE\s+/i, '').trim();
            result.exposedPorts.push(ports);
            result.details.push(`${file}: EXPOSE ${ports}`);
          }
        }
      }
    } catch {
      // Skip
    }
  }

  return result;
}

// ============================================================
// 4. Resource Limits (Static)
// ============================================================

export interface ResourceLimitResult {
  hasLimits: boolean;
  details: string[];
}

export function checkResourceLimits(targetPath: string, files: string[]): ResourceLimitResult {
  const result: ResourceLimitResult = {
    hasLimits: false,
    details: [],
  };

  for (const file of files) {
    const basename = path.basename(file).toLowerCase();
    if (basename !== 'docker-compose.yml' && basename !== 'docker-compose.yaml') continue;

    try {
      const content = readFileContent(file);

      if (/\bmem_limit\b|\bmemory\s*:/i.test(content)) {
        result.hasLimits = true;
        result.details.push(`${file}: memory limit configured`);
      }
      if (/\bcpus?\s*:/i.test(content) || /\bcpu_quota\b/i.test(content)) {
        result.hasLimits = true;
        result.details.push(`${file}: CPU limit configured`);
      }
      if (/\bdeploy\s*:[\s\S]*?\bresources\s*:/i.test(content)) {
        result.hasLimits = true;
        result.details.push(`${file}: deploy resources configured`);
      }
    } catch {
      // Skip
    }
  }

  return result;
}

// ============================================================
// 5. Snapshot / Rollback Capability
// ============================================================

export interface SnapshotResult {
  hasGit: boolean;
  hasDockerfile: boolean;
  hasDockerCompose: boolean;
  details: string[];
}

export function checkSnapshotCapability(targetPath: string, files: string[]): SnapshotResult {
  const result: SnapshotResult = {
    hasGit: false,
    hasDockerfile: false,
    hasDockerCompose: false,
    details: [],
  };

  // Check for .git directory
  try {
    const gitDir = path.join(targetPath, '.git');
    if (fs.existsSync(gitDir) && fs.statSync(gitDir).isDirectory()) {
      result.hasGit = true;
      result.details.push('.git directory found — rollback via git is possible');
    }
  } catch {
    // Skip
  }

  for (const file of files) {
    const basename = path.basename(file).toLowerCase();
    if (basename === 'dockerfile' || basename.startsWith('dockerfile.')) {
      result.hasDockerfile = true;
      result.details.push(`${file}: Dockerfile found — environment is rebuildable`);
    }
    if (basename === 'docker-compose.yml' || basename === 'docker-compose.yaml') {
      result.hasDockerCompose = true;
      result.details.push(`${file}: docker-compose found — environment is rebuildable`);
    }
  }

  return result;
}

// ============================================================
// 6. Cross-Environment Sharing (Docker volumes)
// ============================================================

export interface CrossEnvResult {
  dangerousVolumes: { file: string; volume: string; severity: Severity }[];
  privileged: { file: string }[];
  details: string[];
}

export function checkCrossEnvSharing(targetPath: string, files: string[]): CrossEnvResult {
  const result: CrossEnvResult = {
    dangerousVolumes: [],
    privileged: [],
    details: [],
  };

  for (const file of files) {
    const basename = path.basename(file).toLowerCase();
    if (basename !== 'docker-compose.yml' && basename !== 'docker-compose.yaml') continue;

    try {
      const content = readFileContent(file);

      // Check for docker.sock / podman.sock / containerd.sock mount
      if (/docker\.sock/i.test(content)) {
        result.dangerousVolumes.push({ file, volume: 'docker.sock', severity: 'critical' });
        result.details.push(`${file}: mounts docker.sock — container escape risk`);
      }
      if (/podman\.sock/i.test(content)) {
        result.dangerousVolumes.push({ file, volume: 'podman.sock', severity: 'critical' });
        result.details.push(`${file}: mounts podman.sock — container escape risk`);
      }
      if (/containerd\.sock/i.test(content)) {
        result.dangerousVolumes.push({ file, volume: 'containerd.sock', severity: 'critical' });
        result.details.push(`${file}: mounts containerd.sock — container escape risk`);
      }

      // Check for root or home mount
      // Match patterns like: - /:/something or - $HOME:/something or - ~/:/something
      const volumeLines = content.match(/^\s*-\s*["']?(?:\/|~\/|\$HOME)[^:]*:/gmi) || [];
      for (const line of volumeLines) {
        const trimmed = line.trim().replace(/^-\s*["']?/, '');
        const hostPath = trimmed.split(':')[0].trim();

        // Skip if it's a specific subdirectory (not root or home itself)
        if (hostPath === '/' || hostPath === '/:/') {
          result.dangerousVolumes.push({ file, volume: hostPath, severity: 'high' });
          result.details.push(`${file}: mounts host root filesystem`);
        }
        if (/^\$HOME\/?$|^~\/?$/i.test(hostPath)) {
          result.dangerousVolumes.push({ file, volume: hostPath, severity: 'high' });
          result.details.push(`${file}: mounts host $HOME directory`);
        }
      }

      // Check for privileged: true
      if (/privileged\s*:\s*true/i.test(content)) {
        result.privileged.push({ file });
        result.details.push(`${file}: privileged: true — full host access`);
      }
    } catch {
      // Skip
    }
  }

  return result;
}

// ============================================================
// Main Scanner
// ============================================================

export const environmentIsolationAuditor: ScannerModule = {
  name: 'Environment Isolation Auditor',
  description: 'Checks runtime environment isolation: container/VM detection, file permissions, network isolation, resource limits, snapshot capability, and dangerous Docker mounts',

  async scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Gather only config/env/container files — the auditor does not need to walk
    // every file in the tree. It checks file permissions on config files, and
    // reads docker-compose / Dockerfile for network/resource/volume settings.
    let allFiles: string[] = [];
    try {
      allFiles = await findFiles(
        targetPath,
        [
          '**/*.json',
          '**/*.yaml',
          '**/*.yml',
          '**/*.toml',
          '**/*.conf',
          '**/*.cfg',
          '**/*.ini',
          '**/*.env',
          '**/.env*',
          '**/*.pem',
          '**/*.key',
          '**/Dockerfile',
          '**/Dockerfile.*',
          '**/docker-compose.yml',
          '**/docker-compose.yaml',
        ],
        options?.exclude,
        options?.includeVendored,
        options?.sentoriIgnorePatterns,
      );
    } catch {
      // If we can't find files, still do environment detection
    }

    // --- 1. Container/VM Detection ---
    const env = detectEnvironment();

    if (env.isDocker || env.isContainer) {
      findings.push({
        id: 'EI-001-CONTAINER',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'Container environment detected',
        description: `Running in a container environment. ${env.details.join('. ')}.`,
        file: targetPath,
        recommendation: 'Good — container isolation provides a security boundary. Ensure the container is properly configured (no privileged mode, limited mounts).',
        confidence: 'definite',
      });
    } else if (env.isVM) {
      findings.push({
        id: 'EI-001-VM',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'Virtual machine environment detected',
        description: `Running inside a VM. ${env.details.join('. ')}.`,
        file: targetPath,
        recommendation: 'Good — VM isolation provides strong security boundaries.',
        confidence: 'definite',
      });
    } else if (env.unknown) {
      findings.push({
        id: 'EI-001-BARE',
        scanner: 'Environment Isolation Auditor',
        severity: 'medium',
        title: 'No environment isolation detected',
        description: 'No container or VM isolation detected. The agent appears to run directly on the host system.',
        file: targetPath,
        recommendation: 'Consider running the agent inside a Docker container or VM for isolation. This limits the blast radius if the agent is compromised.',
        confidence: 'possible',
      });
    }

    // --- 2. File Permissions ---
    const permIssues = checkFilePermissions(targetPath, allFiles);
    for (const issue of permIssues) {
      findings.push({
        id: 'EI-002-PERM',
        scanner: 'Environment Isolation Auditor',
        severity: 'high',
        title: 'Sensitive config file is world-readable',
        description: issue.issue,
        file: issue.file,
        recommendation: 'Change file permissions to 600 (owner read/write only) or 640 (owner read/write, group read). Run: chmod 600 <file>',
        confidence: 'definite',
      });
    }

    // --- 3. Network Isolation ---
    const netResult = checkNetworkIsolation(targetPath, allFiles);
    if (netResult.hasDockerCompose && !netResult.hasNetworkConfig) {
      findings.push({
        id: 'EI-003-NONET',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'No network isolation configured in docker-compose',
        description: 'docker-compose.yml found but no custom network configuration detected. Services use the default bridge network.',
        file: targetPath,
        recommendation: 'Define custom networks in docker-compose.yml to isolate services. Use network_mode: none for services that do not need network access.',
        confidence: 'possible',
      });
    }
    if (netResult.exposedPorts.length > 0) {
      findings.push({
        id: 'EI-003-EXPOSE',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'Dockerfile exposes ports',
        description: `Dockerfile EXPOSE directives found: ${netResult.exposedPorts.join(', ')}. Ensure only necessary ports are exposed.`,
        file: targetPath,
        recommendation: 'Review exposed ports and remove any that are not strictly necessary. Use Docker network policies to restrict access.',
        confidence: 'possible',
      });
    }

    // --- 4. Resource Limits ---
    const resResult = checkResourceLimits(targetPath, allFiles);
    if (netResult.hasDockerCompose && !resResult.hasLimits) {
      findings.push({
        id: 'EI-004-NOLIMIT',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'No resource limits configured',
        description: 'docker-compose.yml found but no memory or CPU limits detected. A compromised agent could consume all host resources.',
        file: targetPath,
        recommendation: 'Add mem_limit and cpus constraints in docker-compose.yml to limit resource consumption.',
        confidence: 'possible',
      });
    }

    // --- 5. Snapshot/Rollback ---
    const snapResult = checkSnapshotCapability(targetPath, allFiles);
    if (snapResult.hasGit) {
      findings.push({
        id: 'EI-005-GIT',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'Git version control detected',
        description: 'The target directory is under git version control, enabling rollback capability.',
        file: targetPath,
        recommendation: 'Good — git provides rollback capability. Ensure commits are regular and .gitignore excludes sensitive files.',
        confidence: 'definite',
      });
    }
    if (snapResult.hasDockerfile || snapResult.hasDockerCompose) {
      findings.push({
        id: 'EI-005-REBUILD',
        scanner: 'Environment Isolation Auditor',
        severity: 'info',
        title: 'Reproducible environment detected',
        description: `${snapResult.hasDockerfile ? 'Dockerfile' : ''}${snapResult.hasDockerfile && snapResult.hasDockerCompose ? ' and ' : ''}${snapResult.hasDockerCompose ? 'docker-compose.yml' : ''} found — environment can be rebuilt from scratch.`,
        file: targetPath,
        recommendation: 'Good — infrastructure-as-code enables clean rebuilds after compromise.',
        confidence: 'definite',
      });
    }

    // --- 6. Cross-Environment Sharing ---
    const crossResult = checkCrossEnvSharing(targetPath, allFiles);
    for (const vol of crossResult.dangerousVolumes) {
      const isSocket = /(?:docker|podman|containerd)\.sock/.test(vol.volume);
      findings.push({
        id: isSocket ? 'EI-006-SOCKET' : 'EI-006-MOUNT',
        scanner: 'Environment Isolation Auditor',
        severity: isSocket ? 'critical' : 'high',
        title: isSocket
          ? `Container socket mounted (${vol.volume}) — container escape possible`
          : 'Dangerous host filesystem mount',
        description: isSocket
          ? `${vol.file}: mounts ${vol.volume} into the container. This allows the container to control the container runtime and escape isolation.`
          : `${vol.file}: mounts ${vol.volume} into the container. This exposes the host filesystem and effectively negates container isolation.`,
        file: vol.file,
        recommendation: isSocket
          ? `Remove ${vol.volume} mount. If container API access is needed, use a socket proxy with restricted access.`
          : 'Mount only the specific directories needed. Avoid mounting / or $HOME.',
        confidence: 'definite',
      });
    }
    for (const priv of crossResult.privileged) {
      findings.push({
        id: 'EI-006-PRIV',
        scanner: 'Environment Isolation Auditor',
        severity: 'critical',
        title: 'Container runs in privileged mode',
        description: `${priv.file}: privileged: true gives the container full access to the host, effectively disabling container isolation.`,
        file: priv.file,
        recommendation: 'Remove privileged: true. Use specific capabilities (cap_add) instead of granting all privileges.',
        confidence: 'definite',
      });
    }

    return {
      scanner: 'Environment Isolation Auditor',
      findings,
      scannedFiles: allFiles.length,
      duration: Date.now() - start,
    };
  },
};
