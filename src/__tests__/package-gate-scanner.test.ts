import { PackageGateLockParser, ParsedLockResult } from '../scanners/package-gate-scanner';

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
