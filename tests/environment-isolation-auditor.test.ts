import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  detectEnvironment,
  checkFilePermissions,
  checkNetworkIsolation,
  checkResourceLimits,
  checkSnapshotCapability,
  checkCrossEnvSharing,
  environmentIsolationAuditor,
} from '../src/scanners/environment-isolation-auditor';

// ============================================================
// 1. Container/VM Detection
// ============================================================

describe('Environment Isolation Auditor', () => {
  describe('Container/VM Detection', () => {
    test('detectEnvironment returns a result object', () => {
      const result = detectEnvironment();
      expect(result).toHaveProperty('isDocker');
      expect(result).toHaveProperty('isContainer');
      expect(result).toHaveProperty('isVM');
      expect(result).toHaveProperty('unknown');
      expect(result).toHaveProperty('details');
      expect(Array.isArray(result.details)).toBe(true);
    });

    test('detectEnvironment sets unknown=true when no isolation detected on bare metal', () => {
      // On a typical dev machine without Docker/VM, unknown should be true
      // (unless running in CI Docker — we just verify the shape)
      const result = detectEnvironment();
      // At least one of the flags should be true
      const anyDetected = result.isDocker || result.isContainer || result.isVM || result.unknown;
      expect(anyDetected).toBe(true);
    });

    test('detectEnvironment details array is non-empty', () => {
      const result = detectEnvironment();
      expect(result.details.length).toBeGreaterThan(0);
    });

    test('detectEnvironment isDocker implies isContainer', () => {
      const result = detectEnvironment();
      if (result.isDocker) {
        expect(result.isContainer).toBe(true);
      }
    });

    test('when no isolation detected, unknown is true and details mention it', () => {
      const result = detectEnvironment();
      if (result.unknown) {
        expect(result.details.some(d => /no container|no.*isolation/i.test(d))).toBe(true);
      }
    });
  });

  // ============================================================
  // 2. File Permission Checks
  // ============================================================

  describe('File Permission Checks', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('detects world-readable config file with sensitive content', () => {
      if (os.platform() === 'win32') return; // Skip on Windows

      const configFile = path.join(tmpDir, 'config.json');
      fs.writeFileSync(configFile, '{ "api_key": "sk-abc123def456ghi789" }');
      fs.chmodSync(configFile, 0o644); // world-readable

      const issues = checkFilePermissions(tmpDir, [configFile]);
      expect(issues.length).toBe(1);
      expect(issues[0].issue).toContain('world-readable');
    });

    test('no issue for config file with restrictive permissions', () => {
      if (os.platform() === 'win32') return;

      const configFile = path.join(tmpDir, 'config.json');
      fs.writeFileSync(configFile, '{ "api_key": "sk-abc123def456ghi789" }');
      fs.chmodSync(configFile, 0o600); // owner only

      const issues = checkFilePermissions(tmpDir, [configFile]);
      expect(issues.length).toBe(0);
    });

    test('no issue for world-readable file without sensitive content', () => {
      if (os.platform() === 'win32') return;

      const configFile = path.join(tmpDir, 'config.json');
      fs.writeFileSync(configFile, '{ "name": "test-app", "version": "1.0" }');
      fs.chmodSync(configFile, 0o644);

      const issues = checkFilePermissions(tmpDir, [configFile]);
      expect(issues.length).toBe(0);
    });

    test('skips non-config file extensions', () => {
      if (os.platform() === 'win32') return;

      const jsFile = path.join(tmpDir, 'app.js');
      fs.writeFileSync(jsFile, 'const api_key = "sk-abc123def456ghi789";');
      fs.chmodSync(jsFile, 0o644);

      const issues = checkFilePermissions(tmpDir, [jsFile]);
      expect(issues.length).toBe(0);
    });

    test('detects world-readable .env file with password', () => {
      if (os.platform() === 'win32') return;

      const envFile = path.join(tmpDir, '.env');
      fs.writeFileSync(envFile, 'DATABASE_PASSWORD=supersecret123');
      fs.chmodSync(envFile, 0o644);

      const issues = checkFilePermissions(tmpDir, [envFile]);
      expect(issues.length).toBe(1);
    });

    test('detects world-readable .yaml file with token', () => {
      if (os.platform() === 'win32') return;

      const yamlFile = path.join(tmpDir, 'config.yaml');
      fs.writeFileSync(yamlFile, 'access_token: ghp_abc123def456ghi789jklmnop012345678901');
      fs.chmodSync(yamlFile, 0o644);

      const issues = checkFilePermissions(tmpDir, [yamlFile]);
      expect(issues.length).toBe(1);
    });

    test('returns empty array on Windows', () => {
      // We test the guard by checking the function works without error
      if (os.platform() !== 'win32') return;

      const issues = checkFilePermissions(tmpDir, []);
      expect(issues).toEqual([]);
    });

    test('detects world-readable .toml file with secret', () => {
      if (os.platform() === 'win32') return;

      const tomlFile = path.join(tmpDir, 'config.toml');
      fs.writeFileSync(tomlFile, 'secret = "my-super-secret-value"');
      fs.chmodSync(tomlFile, 0o644);

      const issues = checkFilePermissions(tmpDir, [tomlFile]);
      expect(issues.length).toBe(1);
    });

    test('mode string in issue message', () => {
      if (os.platform() === 'win32') return;

      const configFile = path.join(tmpDir, 'config.json');
      fs.writeFileSync(configFile, '{ "password": "hunter2" }');
      fs.chmodSync(configFile, 0o644);

      const issues = checkFilePermissions(tmpDir, [configFile]);
      expect(issues[0].issue).toContain('0644');
    });
  });

  // ============================================================
  // 3. Network Isolation
  // ============================================================

  describe('Network Isolation', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('detects docker-compose with no network config', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    ports:
      - "3000:3000"
`);
      const result = checkNetworkIsolation(tmpDir, [compose]);
      expect(result.hasDockerCompose).toBe(true);
      expect(result.hasNetworkConfig).toBe(false);
    });

    test('detects docker-compose with network config', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    networks:
      - backend
networks:
  backend:
    driver: bridge
`);
      const result = checkNetworkIsolation(tmpDir, [compose]);
      expect(result.hasDockerCompose).toBe(true);
      expect(result.hasNetworkConfig).toBe(true);
    });

    test('detects network_mode: none', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  worker:
    image: node:18
    network_mode: none
`);
      const result = checkNetworkIsolation(tmpDir, [compose]);
      expect(result.hasNetworkConfig).toBe(true);
    });

    test('detects EXPOSE in Dockerfile', () => {
      const dockerfile = path.join(tmpDir, 'Dockerfile');
      fs.writeFileSync(dockerfile, `
FROM node:18
WORKDIR /app
COPY . .
EXPOSE 3000
EXPOSE 8080
CMD ["node", "index.js"]
`);
      const result = checkNetworkIsolation(tmpDir, [dockerfile]);
      expect(result.exposedPorts).toContain('3000');
      expect(result.exposedPorts).toContain('8080');
    });

    test('no exposed ports when Dockerfile has no EXPOSE', () => {
      const dockerfile = path.join(tmpDir, 'Dockerfile');
      fs.writeFileSync(dockerfile, `
FROM node:18
WORKDIR /app
CMD ["node", "index.js"]
`);
      const result = checkNetworkIsolation(tmpDir, [dockerfile]);
      expect(result.exposedPorts.length).toBe(0);
    });

    test('returns defaults when no docker files present', () => {
      const jsFile = path.join(tmpDir, 'app.js');
      fs.writeFileSync(jsFile, 'console.log("hello")');
      const result = checkNetworkIsolation(tmpDir, [jsFile]);
      expect(result.hasDockerCompose).toBe(false);
      expect(result.hasNetworkConfig).toBe(false);
      expect(result.exposedPorts).toEqual([]);
    });
  });

  // ============================================================
  // 4. Resource Limits
  // ============================================================

  describe('Resource Limits', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('detects mem_limit in docker-compose', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    mem_limit: 512m
`);
      const result = checkResourceLimits(tmpDir, [compose]);
      expect(result.hasLimits).toBe(true);
    });

    test('detects cpus in docker-compose', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    cpus: "0.5"
`);
      const result = checkResourceLimits(tmpDir, [compose]);
      expect(result.hasLimits).toBe(true);
    });

    test('detects deploy resources', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    deploy:
      resources:
        limits:
          memory: 512M
`);
      const result = checkResourceLimits(tmpDir, [compose]);
      expect(result.hasLimits).toBe(true);
    });

    test('no limits detected when none configured', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    ports:
      - "3000:3000"
`);
      const result = checkResourceLimits(tmpDir, [compose]);
      expect(result.hasLimits).toBe(false);
    });

    test('ignores non-docker-compose files', () => {
      const yamlFile = path.join(tmpDir, 'config.yaml');
      fs.writeFileSync(yamlFile, 'mem_limit: 512m');
      const result = checkResourceLimits(tmpDir, [yamlFile]);
      expect(result.hasLimits).toBe(false);
    });
  });

  // ============================================================
  // 5. Snapshot/Rollback
  // ============================================================

  describe('Snapshot/Rollback Capability', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('detects .git directory', () => {
      const gitDir = path.join(tmpDir, '.git');
      fs.mkdirSync(gitDir);
      const result = checkSnapshotCapability(tmpDir, []);
      expect(result.hasGit).toBe(true);
    });

    test('detects Dockerfile', () => {
      const dockerfile = path.join(tmpDir, 'Dockerfile');
      fs.writeFileSync(dockerfile, 'FROM node:18');
      const result = checkSnapshotCapability(tmpDir, [dockerfile]);
      expect(result.hasDockerfile).toBe(true);
    });

    test('detects docker-compose.yml', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, 'version: "3"');
      const result = checkSnapshotCapability(tmpDir, [compose]);
      expect(result.hasDockerCompose).toBe(true);
    });

    test('no snapshot when nothing found', () => {
      const result = checkSnapshotCapability(tmpDir, []);
      expect(result.hasGit).toBe(false);
      expect(result.hasDockerfile).toBe(false);
      expect(result.hasDockerCompose).toBe(false);
    });

    test('detects all three together', () => {
      fs.mkdirSync(path.join(tmpDir, '.git'));
      const dockerfile = path.join(tmpDir, 'Dockerfile');
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(dockerfile, 'FROM node:18');
      fs.writeFileSync(compose, 'version: "3"');
      const result = checkSnapshotCapability(tmpDir, [dockerfile, compose]);
      expect(result.hasGit).toBe(true);
      expect(result.hasDockerfile).toBe(true);
      expect(result.hasDockerCompose).toBe(true);
    });
  });

  // ============================================================
  // 6. Cross-Environment Sharing
  // ============================================================

  describe('Cross-Environment Sharing', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('detects docker.sock mount', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`);
      const result = checkCrossEnvSharing(tmpDir, [compose]);
      expect(result.dangerousVolumes.length).toBe(1);
      expect(result.dangerousVolumes[0].volume).toBe('docker.sock');
      expect(result.dangerousVolumes[0].severity).toBe('critical');
    });

    test('detects privileged: true', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    privileged: true
`);
      const result = checkCrossEnvSharing(tmpDir, [compose]);
      expect(result.privileged.length).toBe(1);
    });

    test('detects root mount', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    volumes:
      - /:/host
`);
      const result = checkCrossEnvSharing(tmpDir, [compose]);
      expect(result.dangerousVolumes.some(v => v.volume === '/')).toBe(true);
    });

    test('detects $HOME mount', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    volumes:
      - $HOME:/home/user
`);
      const result = checkCrossEnvSharing(tmpDir, [compose]);
      expect(result.dangerousVolumes.some(v => /\$HOME/i.test(v.volume))).toBe(true);
    });

    test('no issues for safe volume mounts', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    volumes:
      - ./data:/app/data
`);
      const result = checkCrossEnvSharing(tmpDir, [compose]);
      expect(result.dangerousVolumes.length).toBe(0);
      expect(result.privileged.length).toBe(0);
    });

    test('detects both docker.sock and privileged together', () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`);
      const result = checkCrossEnvSharing(tmpDir, [compose]);
      expect(result.dangerousVolumes.length).toBe(1);
      expect(result.privileged.length).toBe(1);
    });

    test('ignores non docker-compose files', () => {
      const yamlFile = path.join(tmpDir, 'config.yaml');
      fs.writeFileSync(yamlFile, `
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
privileged: true
`);
      const result = checkCrossEnvSharing(tmpDir, [yamlFile]);
      expect(result.dangerousVolumes.length).toBe(0);
      expect(result.privileged.length).toBe(0);
    });
  });

  // ============================================================
  // Integration: Full Scanner
  // ============================================================

  describe('Full Scanner Integration', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    test('scanner returns valid ScanResult structure', async () => {
      const result = await environmentIsolationAuditor.scan(tmpDir);
      expect(result.scanner).toBe('Environment Isolation Auditor');
      expect(Array.isArray(result.findings)).toBe(true);
      expect(typeof result.scannedFiles).toBe('number');
      expect(typeof result.duration).toBe('number');
    });

    test('scanner name and description are set', () => {
      expect(environmentIsolationAuditor.name).toBe('Environment Isolation Auditor');
      expect(environmentIsolationAuditor.description).toBeTruthy();
    });

    test('scanner produces EI-001 finding for environment detection', async () => {
      const result = await environmentIsolationAuditor.scan(tmpDir);
      const envFinding = result.findings.find(f => f.id.startsWith('EI-001'));
      expect(envFinding).toBeDefined();
    });

    test('scanner detects dangerous docker-compose', async () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`);
      const result = await environmentIsolationAuditor.scan(tmpDir);
      const criticals = result.findings.filter(f => f.severity === 'critical');
      expect(criticals.length).toBeGreaterThanOrEqual(2); // docker.sock + privileged
    });

    test('scanner detects world-readable config', async () => {
      if (os.platform() === 'win32') return;

      const configFile = path.join(tmpDir, 'config.json');
      fs.writeFileSync(configFile, '{ "api_key": "sk-abc123def456ghi789" }');
      fs.chmodSync(configFile, 0o644);

      const result = await environmentIsolationAuditor.scan(tmpDir);
      const permFinding = result.findings.find(f => f.id === 'EI-002-PERM');
      expect(permFinding).toBeDefined();
      expect(permFinding!.severity).toBe('high');
    });

    test('scanner reports snapshot capability', async () => {
      fs.mkdirSync(path.join(tmpDir, '.git'));
      const result = await environmentIsolationAuditor.scan(tmpDir);
      const gitFinding = result.findings.find(f => f.id === 'EI-005-GIT');
      expect(gitFinding).toBeDefined();
      expect(gitFinding!.severity).toBe('info');
    });

    test('scanner respects exclude option', async () => {
      const result = await environmentIsolationAuditor.scan(tmpDir, { exclude: ['**/*'] });
      // Should still have EI-001 (environment detection doesn't depend on files)
      const envFinding = result.findings.find(f => f.id.startsWith('EI-001'));
      expect(envFinding).toBeDefined();
    });

    test('scanner reports no resource limits for bare docker-compose', async () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
`);
      const result = await environmentIsolationAuditor.scan(tmpDir);
      const limitFinding = result.findings.find(f => f.id === 'EI-004-NOLIMIT');
      expect(limitFinding).toBeDefined();
      expect(limitFinding!.severity).toBe('info');
    });

    test('scanner reports no network config for bare docker-compose', async () => {
      const compose = path.join(tmpDir, 'docker-compose.yml');
      fs.writeFileSync(compose, `
version: "3"
services:
  app:
    image: node:18
`);
      const result = await environmentIsolationAuditor.scan(tmpDir);
      const netFinding = result.findings.find(f => f.id === 'EI-003-NONET');
      expect(netFinding).toBeDefined();
    });

    test('all findings have confidence set', async () => {
      const result = await environmentIsolationAuditor.scan(tmpDir);
      for (const f of result.findings) {
        expect(f.confidence).toBeDefined();
      }
    });
  });
});
