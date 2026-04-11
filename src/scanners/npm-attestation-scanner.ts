import * as path from 'path';
import * as https from 'https';
import { ScannerModule, ScanResult, Finding } from '../types';
import { parseLockfile, findLockfiles } from '../utils/lockfile-parser';

const SCANNER_NAME = 'NPM Attestation Scanner';
const CONCURRENCY = 8;
const REQUEST_TIMEOUT_MS = 5000;

interface RegistryResponse {
  dist?: {
    attestations?: unknown;
  };
}

/**
 * Fetch package metadata from the npm registry.
 * Returns whether the package has attestations.
 * On any error (network, timeout, non-200), returns null (skip).
 */
function checkAttestation(name: string, version: string): Promise<boolean | null> {
  return new Promise((resolve) => {
    // Scoped packages: @org/pkg -> @org%2fpkg
    const encodedName = name.startsWith('@')
      ? `@${encodeURIComponent(name.slice(1))}`
      : encodeURIComponent(name);
    const url = `https://registry.npmjs.org/${encodedName}/${version}`;

    const req = https.get(url, { timeout: REQUEST_TIMEOUT_MS }, (res) => {
      if (res.statusCode !== 200) {
        res.resume(); // drain
        resolve(null);
        return;
      }

      let body = '';
      res.setEncoding('utf-8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        try {
          const data: RegistryResponse = JSON.parse(body);
          const attestations = data.dist?.attestations;
          const hasAttestation = Array.isArray(attestations)
            ? attestations.length > 0
            : attestations != null && attestations !== false;
          resolve(hasAttestation);
        } catch {
          resolve(null);
        }
      });
    });

    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Run promises with bounded concurrency.
 */
async function pooled<T>(tasks: (() => Promise<T>)[], limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let idx = 0;

  async function worker(): Promise<void> {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export const npmAttestationScanner: ScannerModule = {
  name: SCANNER_NAME,
  description: 'Checks npm packages for Sigstore attestation / OIDC provenance',

  async scan(targetPath: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    // Find lock files
    const lockfiles = findLockfiles(targetPath);
    if (lockfiles.length === 0) {
      return {
        scanner: SCANNER_NAME,
        findings: [{
          scanner: SCANNER_NAME,
          severity: 'info',
          rule: 'ATTESTATION-000',
          title: 'No lock file found — npm attestation check skipped',
          description: 'No lock file found — npm attestation check skipped',
          message: 'No lock file found — npm attestation check skipped',
          recommendation: 'Run `npm install` to generate package-lock.json',
        }],
        scannedFiles: 0,
        duration: Date.now() - start,
      };
    }

    // Parse lock file (prefer package-lock.json)
    const npmLock = lockfiles.find((f) => path.basename(f) === 'package-lock.json');
    const lockPath = npmLock || lockfiles[0];
    const parsed = parseLockfile(lockPath);

    if (parsed.errors.length > 0 || parsed.packages.length === 0) {
      return {
        scanner: SCANNER_NAME,
        findings: [],
        scannedFiles: 0,
        duration: Date.now() - start,
      };
    }

    // Deduplicate by name@version
    const seen = new Set<string>();
    const uniquePackages = parsed.packages.filter((pkg) => {
      const key = `${pkg.name}@${pkg.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Check attestations with bounded concurrency
    const tasks = uniquePackages.map((pkg) => () => checkAttestation(pkg.name, pkg.version));
    const results = await pooled(tasks, CONCURRENCY);

    let skipped = 0;
    for (let i = 0; i < uniquePackages.length; i++) {
      const result = results[i];
      if (result === null) {
        skipped++;
        continue; // network error — skip, don't false-positive
      }
      if (result === false) {
        const pkg = uniquePackages[i];
        findings.push({
          scanner: SCANNER_NAME,
          severity: 'info',
          rule: 'ATTESTATION-001',
          title: `"${pkg.name}@${pkg.version}" has no npm attestation (Sigstore provenance unverified)`,
          description: `"${pkg.name}@${pkg.version}" has no npm attestation (Sigstore provenance unverified)`,
          message: `"${pkg.name}@${pkg.version}" has no npm attestation (Sigstore provenance unverified)`,
          recommendation: 'Use packages published with GitHub Actions OIDC provenance',
        });
      }
    }

    if (skipped > 0) {
      findings.push({
        scanner: SCANNER_NAME,
        severity: 'info',
        rule: 'ATTESTATION-002',
        title: `${skipped} package(s) skipped due to network errors or timeouts`,
        description: `${skipped} package(s) skipped due to network errors or timeouts`,
        message: `${skipped} package(s) skipped due to network errors or timeouts`,
        recommendation: 'Re-run with network access for complete attestation coverage',
      });
    }

    return {
      scanner: SCANNER_NAME,
      findings,
      scannedFiles: uniquePackages.length,
      duration: Date.now() - start,
    };
  },
};
