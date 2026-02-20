import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  parseLockfile,
  findLockfiles,
  mergePackages,
  summarizePackages,
  LockFileParseResult,
} from '../src/utils/lockfile-parser';

describe('lockfile-parser', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('parseLockfile - NPM', () => {
    it('should parse NPM lockfile v2 format', () => {
      const lockfileContent = {
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 2,
        requires: true,
        packages: {
          '': {
            name: 'test-project',
            version: '1.0.0',
          },
          'node_modules/express': {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            integrity: 'sha512-example',
            dependencies: {
              'accepts': '^1.3.8',
            },
          },
          'node_modules/lodash': {
            version: '4.17.21',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
            integrity: 'sha512-example2',
            dev: true,
          },
        },
      };

      const lockfilePath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockfilePath, JSON.stringify(lockfileContent, null, 2));

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('npm');
      expect(result.lockfileVersion).toBe(2);
      expect(result.packages.length).toBe(2);
      expect(result.errors.length).toBe(0);

      const express = result.packages.find((p) => p.name === 'express');
      expect(express).toBeDefined();
      expect(express?.version).toBe('4.18.2');
      expect(express?.resolved).toContain('express-4.18.2.tgz');
      expect(express?.dev).toBe(false);

      const lodash = result.packages.find((p) => p.name === 'lodash');
      expect(lodash).toBeDefined();
      expect(lodash?.version).toBe('4.17.21');
      expect(lodash?.dev).toBe(true);
    });

    it('should parse NPM lockfile v1 format', () => {
      const lockfileContent = {
        name: 'test-project',
        version: '1.0.0',
        lockfileVersion: 1,
        dependencies: {
          'express': {
            version: '4.18.2',
            resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz',
            integrity: 'sha512-example',
            requires: {
              'accepts': '^1.3.8',
            },
          },
          'lodash': {
            version: '4.17.21',
            resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
            integrity: 'sha512-example2',
            dev: true,
          },
        },
      };

      const lockfilePath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockfilePath, JSON.stringify(lockfileContent, null, 2));

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('npm');
      expect(result.lockfileVersion).toBe(1);
      expect(result.packages.length).toBe(2);
      expect(result.errors.length).toBe(0);
    });

    it('should handle nested dependencies in v1 format', () => {
      const lockfileContent = {
        lockfileVersion: 1,
        dependencies: {
          'express': {
            version: '4.18.2',
            dependencies: {
              'accepts': {
                version: '1.3.8',
              },
            },
          },
        },
      };

      const lockfilePath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockfilePath, JSON.stringify(lockfileContent, null, 2));

      const result = parseLockfile(lockfilePath);

      expect(result.packages.length).toBe(2); // express + accepts
      expect(result.packages.some((p) => p.name === 'express')).toBe(true);
      expect(result.packages.some((p) => p.name === 'accepts')).toBe(true);
    });
  });

  describe('parseLockfile - PNPM', () => {
    it('should parse PNPM lockfile v6+ format', () => {
      const lockfileContent = `lockfileVersion: '6.0'

packages:
  /express/4.18.2:
    resolution:
      tarball: https://registry.npmjs.org/express/-/express-4.18.2.tgz
      integrity: sha512-example
    dependencies:
      accepts: ^1.3.8
    dev: false

  /@types/node/20.11.0:
    resolution:
      tarball: https://registry.npmjs.org/@types/node/-/node-20.11.0.tgz
      integrity: sha512-example2
    dev: true
`;

      const lockfilePath = path.join(tempDir, 'pnpm-lock.yaml');
      fs.writeFileSync(lockfilePath, lockfileContent);

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('pnpm');
      expect(result.lockfileVersion).toBe('6.0');
      expect(result.packages.length).toBe(2);
      expect(result.errors.length).toBe(0);

      const express = result.packages.find((p) => p.name === 'express');
      expect(express).toBeDefined();
      expect(express?.version).toBe('4.18.2');
      expect(express?.dev).toBe(false);

      const typesNode = result.packages.find((p) => p.name === '@types/node');
      expect(typesNode).toBeDefined();
      expect(typesNode?.version).toBe('20.11.0');
      expect(typesNode?.dev).toBe(true);
    });

    it('should parse PNPM lockfile v5 format', () => {
      const lockfileContent = `lockfileVersion: 5.3

specifiers:
  express: ^4.18.2
  lodash: ^4.17.21
`;

      const lockfilePath = path.join(tempDir, 'pnpm-lock.yaml');
      fs.writeFileSync(lockfilePath, lockfileContent);

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('pnpm');
      expect(result.packages.length).toBe(2);
      expect(result.errors.length).toBe(0);
    });
  });

  describe('parseLockfile - Bun', () => {
    it('should return error for bun.lockb binary format', () => {
      const lockfilePath = path.join(tempDir, 'bun.lockb');
      fs.writeFileSync(lockfilePath, Buffer.from([0x42, 0x55, 0x4e, 0x00])); // "BUN\0"

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('bun');
      expect(result.packages.length).toBe(0);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors[0]).toContain('binary format');
    });
  });

  describe('parseLockfile - Error handling', () => {
    it('should handle missing lock file', () => {
      const result = parseLockfile(path.join(tempDir, 'nonexistent.json'));

      expect(result.type).toBe('unknown');
      expect(result.packages.length).toBe(0);
      expect(result.errors.length).toBe(1);
      expect(result.errors[0]).toContain('not found');
    });

    it('should handle invalid JSON', () => {
      const lockfilePath = path.join(tempDir, 'package-lock.json');
      fs.writeFileSync(lockfilePath, 'invalid json {');

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('npm');
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('should handle unknown lock file type', () => {
      const lockfilePath = path.join(tempDir, 'unknown.lock');
      fs.writeFileSync(lockfilePath, 'content');

      const result = parseLockfile(lockfilePath);

      expect(result.type).toBe('unknown');
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('findLockfiles', () => {
    it('should find all lock files in directory', () => {
      fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');
      fs.writeFileSync(path.join(tempDir, 'pnpm-lock.yaml'), '');
      fs.writeFileSync(path.join(tempDir, 'bun.lockb'), '');

      const lockfiles = findLockfiles(tempDir);

      expect(lockfiles.length).toBe(3);
      expect(lockfiles.some((f) => f.endsWith('package-lock.json'))).toBe(true);
      expect(lockfiles.some((f) => f.endsWith('pnpm-lock.yaml'))).toBe(true);
      expect(lockfiles.some((f) => f.endsWith('bun.lockb'))).toBe(true);
    });

    it('should return empty array if no lock files found', () => {
      const lockfiles = findLockfiles(tempDir);
      expect(lockfiles.length).toBe(0);
    });
  });

  describe('mergePackages', () => {
    it('should merge packages from multiple lock files', () => {
      const result1: LockFileParseResult = {
        type: 'npm',
        packages: [
          { name: 'express', version: '4.18.2' },
          { name: 'lodash', version: '4.17.21' },
        ],
        errors: [],
      };

      const result2: LockFileParseResult = {
        type: 'pnpm',
        packages: [
          { name: 'express', version: '4.18.2' }, // duplicate
          { name: 'react', version: '18.2.0' },
        ],
        errors: [],
      };

      const merged = mergePackages([result1, result2]);

      expect(merged.length).toBe(3); // express, lodash, react
      expect(merged.some((p) => p.name === 'express')).toBe(true);
      expect(merged.some((p) => p.name === 'lodash')).toBe(true);
      expect(merged.some((p) => p.name === 'react')).toBe(true);
    });

    it('should handle different versions of same package', () => {
      const result1: LockFileParseResult = {
        type: 'npm',
        packages: [{ name: 'lodash', version: '4.17.20' }],
        errors: [],
      };

      const result2: LockFileParseResult = {
        type: 'npm',
        packages: [{ name: 'lodash', version: '4.17.21' }],
        errors: [],
      };

      const merged = mergePackages([result1, result2]);

      expect(merged.length).toBe(2); // Both versions kept
    });
  });

  describe('summarizePackages', () => {
    it('should calculate package statistics', () => {
      const result: LockFileParseResult = {
        type: 'npm',
        packages: [
          { name: 'express', version: '4.18.2', dev: false },
          { name: 'lodash', version: '4.17.21', dev: true },
          { name: 'lodash', version: '4.17.20', dev: false }, // different version
        ],
        errors: [],
      };

      const summary = summarizePackages(result);

      expect(summary.totalPackages).toBe(3);
      expect(summary.prodPackages).toBe(2);
      expect(summary.devPackages).toBe(1);
      expect(summary.uniqueNames).toBe(2); // express, lodash
      expect(summary.lockfileType).toBe('npm');
    });
  });
});
