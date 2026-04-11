import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  ConventionSquattingScanner,
  isTLDCollision,
  domainResolves,
  KNOWN_CONVENTION_FILES,
  fetchPackageMetadata,
  calculateContextScore,
  PackageMetadata,
} from '../scanners/convention-squatting-scanner';

function createTempDir(files: Record<string, string>): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-squat-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(tmpDir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return tmpDir;
}

function cleanup(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('isTLDCollision', () => {
  test('detects .md as TLD collision', () => {
    expect(isTLDCollision('README.md')).toBe(true);
  });

  test('detects .ai as TLD collision', () => {
    expect(isTLDCollision('config.ai')).toBe(true);
  });

  test('does not flag .txt', () => {
    expect(isTLDCollision('notes.txt')).toBe(false);
  });

  test('does not flag .yaml', () => {
    expect(isTLDCollision('config.yaml')).toBe(false);
  });
});

describe('domainResolves', () => {
  test('returns true when resolver returns addresses', async () => {
    const mockResolver = async () => ['1.2.3.4'];
    expect(await domainResolves('readme.md', mockResolver)).toBe(true);
  });

  test('returns false when resolver throws', async () => {
    const mockResolver = async () => { throw new Error('NXDOMAIN'); };
    expect(await domainResolves('nonexistent.md', mockResolver)).toBe(false);
  });

  test('returns false when resolver returns empty', async () => {
    const mockResolver = async () => [] as string[];
    expect(await domainResolves('test.md', mockResolver)).toBe(false);
  });
});

describe('ConventionSquattingScanner', () => {
  let scanner: ConventionSquattingScanner;

  beforeAll(() => {
    scanner = new ConventionSquattingScanner();
  });

  // --- SQUAT-001: TLD Collision ---

  describe('SQUAT-001: Convention Filename TLD Collision', () => {
    test('flags .md files as TLD collisions', async () => {
      const dir = createTempDir({ 'AGENTS.md': '# Agents', 'README.md': '# Readme' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches.length).toBe(2);
        expect(matches.every((m) => m.message?.includes('TLD collision'))).toBe(true);
      } finally {
        cleanup(dir);
      }
    });

    test('flags known convention files with MEDIUM severity', async () => {
      const dir = createTempDir({ 'SOUL.md': '# Soul' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches.length).toBe(1);
        expect(matches[0].severity).toBe('medium');
      } finally {
        cleanup(dir);
      }
    });

    test('does NOT flag unknown .md files (not in KNOWN_CONVENTION_FILES)', async () => {
      // Arbitrary .md files that are not known convention files are skipped to reduce
      // false positives when scanning large codebases or workstation directories.
      const dir = createTempDir({ 'CUSTOM.md': '# Custom' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches.length).toBe(0);
      } finally {
        cleanup(dir);
      }
    });

    test('does NOT flag arbitrary .sh files (not known convention files)', async () => {
      // Arbitrary shell scripts that happen to have a TLD-colliding extension (.sh)
      // are skipped — only known convention filenames are flagged.
      const dir = createTempDir({ 'setup.sh': '#!/bin/bash\necho hi' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches.length).toBe(0);
      } finally {
        cleanup(dir);
      }
    });

    test('does NOT flag arbitrary .py files (not known convention files)', async () => {
      // Python source files have a TLD-colliding extension (.py) but are not convention
      // squatting targets — only known convention filenames (heartbeat.md, readme.md, etc.)
      // should be flagged to avoid false positives in workstation/codebase scans.
      const dir = createTempDir({ 'utils.py': 'def hello(): pass', 'mymodule.py': 'x = 1' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches.length).toBe(0);
      } finally {
        cleanup(dir);
      }
    });

    test('does NOT flag arbitrary .ts files (not known convention files)', async () => {
      // TypeScript source files have a TLD-colliding extension (.ts) but are not convention
      // squatting targets.
      const dir = createTempDir({ 'index.ts': 'export const x = 1;', 'service.ts': 'class S {}' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches.length).toBe(0);
      } finally {
        cleanup(dir);
      }
    });

    test('does not flag .txt or .yaml files', async () => {
      const dir = createTempDir({ 'notes.txt': 'hello', 'config.yaml': 'key: val' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-001');
        expect(matches).toHaveLength(0);
      } finally {
        cleanup(dir);
      }
    });
  });

  // --- SQUAT-002: URL Resolution Risk ---

  describe('SQUAT-002: URL Resolution Risk', () => {
    test('detects fetch() with filename-like argument', async () => {
      const dir = createTempDir({
        'agent.js': 'const data = fetch("AGENTS.md").then(r => r.text());',
      });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-002');
        expect(matches.length).toBeGreaterThanOrEqual(1);
        expect(matches[0].severity).toBe('high');
      } finally {
        cleanup(dir);
      }
    });

    test('detects axios.get with filename-like argument', async () => {
      const dir = createTempDir({
        'loader.ts': 'const res = axios.get("README.md");',
      });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-002');
        expect(matches.length).toBeGreaterThanOrEqual(1);
      } finally {
        cleanup(dir);
      }
    });

    test('detects requests.get in Python files', async () => {
      const dir = createTempDir({
        'loader.py': 'resp = requests.get("SOUL.md")',
      });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-002');
        expect(matches.length).toBeGreaterThanOrEqual(1);
      } finally {
        cleanup(dir);
      }
    });

    test('no false positive on fs.readFileSync', async () => {
      const dir = createTempDir({
        'safe.js': 'const data = fs.readFileSync("AGENTS.md", "utf-8");',
      });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-002');
        expect(matches).toHaveLength(0);
      } finally {
        cleanup(dir);
      }
    });
  });

  // --- SQUAT-003: Known Squatted Domains (DNS) ---

  describe('SQUAT-003: Known Squatted Domains', () => {
    test('reports domains that resolve via DNS', async () => {
      const mockResolver = async (host: string) => {
        if (host === 'readme.md' || host === 'heartbeat.md') return ['93.184.216.34'];
        throw new Error('NXDOMAIN');
      };
      const dnsScanner = new ConventionSquattingScanner({ resolver: mockResolver, dnsCheck: true });
      const dir = createTempDir({ 'dummy.txt': 'x' });
      try {
        const result = await dnsScanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-003');
        expect(matches.length).toBe(2);
        expect(matches.every((m) => m.severity === 'critical')).toBe(true);
        const domains = matches.map((m) => m.message);
        expect(domains.some((d) => d?.includes('readme.md'))).toBe(true);
        expect(domains.some((d) => d?.includes('heartbeat.md'))).toBe(true);
      } finally {
        cleanup(dir);
      }
    });

    test('does not report domains that do not resolve', async () => {
      const mockResolver = async () => { throw new Error('NXDOMAIN'); };
      const dnsScanner = new ConventionSquattingScanner({ resolver: mockResolver, dnsCheck: true });
      const dir = createTempDir({ 'dummy.txt': 'x' });
      try {
        const result = await dnsScanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-003');
        expect(matches).toHaveLength(0);
      } finally {
        cleanup(dir);
      }
    });

    test('skips DNS check when dnsCheck is false (default)', async () => {
      const dir = createTempDir({ 'README.md': '# hi' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-003');
        expect(matches).toHaveLength(0);
      } finally {
        cleanup(dir);
      }
    });
  });

  // --- SQUAT-004: Heartbeat/Periodic Read Risk ---

  describe('SQUAT-004: Heartbeat/Periodic Read Risk', () => {
    test('flags HEARTBEAT.md with extra heartbeat finding', async () => {
      const dir = createTempDir({ 'HEARTBEAT.md': '- check email' });
      try {
        const result = await scanner.scan(dir);
        const squat001 = result.findings.filter((f) => f.rule === 'SQUAT-001' && f.file?.includes('HEARTBEAT'));
        const squat004 = result.findings.filter((f) => f.rule === 'SQUAT-004');
        expect(squat001.length).toBe(1);
        expect(squat001[0].severity).toBe('high');
        expect(squat004.length).toBe(1);
        expect(squat004[0].severity).toBe('high');
        expect(squat004[0].message).toContain('persistent injection');
      } finally {
        cleanup(dir);
      }
    });

    test('does not flag non-heartbeat files with SQUAT-004', async () => {
      const dir = createTempDir({ 'README.md': '# hi' });
      try {
        const result = await scanner.scan(dir);
        const matches = result.findings.filter((f) => f.rule === 'SQUAT-004');
        expect(matches).toHaveLength(0);
      } finally {
        cleanup(dir);
      }
    });
  });

  // --- Integration ---

  describe('Integration', () => {
    test('scans a realistic agent workspace', async () => {
      const dir = createTempDir({
        'AGENTS.md': '# Agent instructions',
        'SOUL.md': '# Identity',
        'MEMORY.md': '# Memory',
        'HEARTBEAT.md': '- check inbox',
        'TOOLS.md': '# Tools',
        'src/loader.js': 'const soul = fetch("SOUL.md").then(r => r.text());',
      });
      try {
        const result = await scanner.scan(dir);
        // Should have TLD collision findings for all .md files
        const squat001 = result.findings.filter((f) => f.rule === 'SQUAT-001');
        // Only known convention files: AGENTS.md, SOUL.md, MEMORY.md, HEARTBEAT.md, TOOLS.md
        // src/loader.js is NOT a known convention file, so it's skipped (no false positives)
        expect(squat001.length).toBe(5);
        // Should have URL resolution finding
        const squat002 = result.findings.filter((f) => f.rule === 'SQUAT-002');
        expect(squat002.length).toBe(1);
        // Should have heartbeat finding
        const squat004 = result.findings.filter((f) => f.rule === 'SQUAT-004');
        expect(squat004.length).toBe(1);
      } finally {
        cleanup(dir);
      }
    });

    test('reports filesScanned count', async () => {
      const dir = createTempDir({ 'A.md': 'a', 'B.md': 'b', 'C.txt': 'c' });
      try {
        const result = await scanner.scan(dir);
        expect(result.scannedFiles).toBe(3);
        expect(result.scanner).toBe('ConventionSquattingScanner');
      } finally {
        cleanup(dir);
      }
    });
  });

  // --- Context Scoring ---

  describe('Context Scoring', () => {
    describe('fetchPackageMetadata', () => {
      test('fetches package metadata successfully', async () => {
        const mockFetcher = async (url: string) => {
          if (url.includes('registry.npmjs.org')) {
            return {
              time: { created: '2020-01-01T00:00:00.000Z' },
              maintainers: [{ name: 'dev1' }, { name: 'dev2' }],
            };
          }
          if (url.includes('api.npmjs.org/downloads')) {
            return { downloads: 50000 };
          }
          throw new Error('Unknown URL');
        };

        const metadata = await fetchPackageMetadata('test-package', mockFetcher);
        expect(metadata).not.toBeNull();
        expect(metadata?.name).toBe('test-package');
        expect(metadata?.ageInDays).toBeGreaterThan(1000);
        expect(metadata?.weeklyDownloads).toBe(50000);
        expect(metadata?.maintainerCount).toBe(2);
      });

      test('returns null for non-existent package', async () => {
        const mockFetcher = async () => {
          throw new Error('404');
        };

        const metadata = await fetchPackageMetadata('non-existent-pkg', mockFetcher);
        expect(metadata).toBeNull();
      });
    });

    describe('calculateContextScore', () => {
      test('keeps severity for new packages (< 30 days)', () => {
        const metadata: PackageMetadata = {
          name: 'new-pkg',
          ageInDays: 15,
          weeklyDownloads: 1000,
          maintainerCount: 1,
        };

        const score = calculateContextScore('high', metadata);
        expect(score.adjustedSeverity).toBe('high');
        expect(score.reason).toContain('< 30 days');
      });

      test('keeps severity for low-traffic packages', () => {
        const metadata: PackageMetadata = {
          name: 'low-traffic',
          ageInDays: 100,
          weeklyDownloads: 500,
          maintainerCount: 1,
        };

        const score = calculateContextScore('high', metadata);
        expect(score.adjustedSeverity).toBe('high');
        expect(score.reason).toContain('Low traffic');
      });

      test('downgrades by 2 levels for established high-traffic packages', () => {
        const metadata: PackageMetadata = {
          name: 'popular-pkg',
          ageInDays: 730,
          weeklyDownloads: 50000,
          maintainerCount: 5,
        };

        const score = calculateContextScore('high', metadata);
        expect(score.adjustedSeverity).toBe('info');
        expect(score.reason).toContain('Established package');
      });

      test('downgrades by 1 level for moderate packages', () => {
        const metadata: PackageMetadata = {
          name: 'moderate-pkg',
          ageInDays: 400,
          weeklyDownloads: 5000,
          maintainerCount: 1,
        };

        const score = calculateContextScore('high', metadata);
        expect(score.adjustedSeverity).toBe('medium');
        expect(score.reason).toContain('Moderate package');
      });

      test('handles null metadata', () => {
        const score = calculateContextScore('high', null);
        expect(score.adjustedSeverity).toBe('high');
        expect(score.reason).toContain('No package metadata');
      });
    });

    describe('Scanner with context scoring', () => {
      test('applies context scoring to reduce severity', async () => {
        const mockFetcher = async (url: string) => {
          if (url.includes('registry.npmjs.org/readme')) {
            return {
              time: { created: '2020-01-01T00:00:00.000Z' },
              maintainers: [{ name: 'dev1' }, { name: 'dev2' }, { name: 'dev3' }],
            };
          }
          if (url.includes('api.npmjs.org/downloads')) {
            return { downloads: 100000 };
          }
          throw new Error('Unknown URL');
        };

        const contextScanner = new ConventionSquattingScanner({ 
          enableContextScoring: true,
          fetcher: mockFetcher,
        });

        const dir = createTempDir({ 'README.md': '# Test' });
        try {
          const result = await contextScanner.scan(dir);
          const squat001 = result.findings.filter((f) => f.rule === 'SQUAT-001');
          expect(squat001.length).toBe(1);
          // Should be downgraded from medium to info
          expect(squat001[0].severity).toBe('info');
          expect(squat001[0].description).toContain('Context:');
        } finally {
          cleanup(dir);
        }
      });

      test('can disable context scoring', async () => {
        const noContextScanner = new ConventionSquattingScanner({ 
          enableContextScoring: false,
        });

        const dir = createTempDir({ 'README.md': '# Test' });
        try {
          const result = await noContextScanner.scan(dir);
          const squat001 = result.findings.filter((f) => f.rule === 'SQUAT-001');
          expect(squat001.length).toBe(1);
          // Should keep original severity (medium for known files)
          expect(squat001[0].severity).toBe('medium');
          expect(squat001[0].description).not.toContain('Context:');
        } finally {
          cleanup(dir);
        }
      });

      test('keeps high severity for suspicious new packages', async () => {
        const mockFetcher = async (url: string) => {
          if (url.includes('registry.npmjs.org/heartbeat')) {
            return {
              time: { created: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString() },
              maintainers: [{ name: 'suspicious' }],
            };
          }
          if (url.includes('api.npmjs.org/downloads')) {
            return { downloads: 100 };
          }
          throw new Error('Unknown URL');
        };

        const contextScanner = new ConventionSquattingScanner({ 
          enableContextScoring: true,
          fetcher: mockFetcher,
        });

        const dir = createTempDir({ 'HEARTBEAT.md': '# Check' });
        try {
          const result = await contextScanner.scan(dir);
          const squat001 = result.findings.filter((f) => f.rule === 'SQUAT-001');
          expect(squat001.length).toBe(1);
          // Should keep high severity for new suspicious package
          expect(squat001[0].severity).toBe('high');
          // Check that context note is included in the description
          expect(squat001[0].description).toMatch(/Package age < 30 days|TLD collision/);
        } finally {
          cleanup(dir);
        }
      });
    });
  });
});
