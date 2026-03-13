import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as https from 'https';
import { EventEmitter } from 'events';
import { npmAttestationScanner } from '../src/scanners/npm-attestation-scanner';

// Mock https.get to avoid real network calls
jest.mock('https');
const mockHttpsGet = https.get as jest.MockedFunction<typeof https.get>;

// Helper: create a fake IncomingMessage response
function makeFakeResponse(statusCode: number, body: string): EventEmitter {
  const res = new EventEmitter() as any;
  res.statusCode = statusCode;
  res.setEncoding = jest.fn();
  res.resume = jest.fn();

  // Emit data + end asynchronously so the handler can attach listeners
  setImmediate(() => {
    res.emit('data', body);
    res.emit('end');
  });

  return res;
}

// Helper: create a fake request object (for error / timeout cases)
function makeFakeRequest(opts: { emitError?: boolean; emitTimeout?: boolean } = {}): EventEmitter {
  const req = new EventEmitter() as any;
  req.destroy = jest.fn(() => {
    if (opts.emitError) req.emit('error', new Error('destroyed'));
  });

  if (opts.emitError) {
    setImmediate(() => req.emit('error', new Error('ECONNREFUSED')));
  }
  if (opts.emitTimeout) {
    setImmediate(() => req.emit('timeout'));
  }

  return req;
}

// Build a minimal package-lock.json (v2) for a given list of packages
function makeLockfile(packages: Array<{ name: string; version: string }>): string {
  const pkgs: Record<string, unknown> = { '': { name: 'root', version: '1.0.0' } };
  for (const { name, version } of packages) {
    pkgs[`node_modules/${name}`] = { version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz` };
  }
  return JSON.stringify({ name: 'root', version: '1.0.0', lockfileVersion: 2, packages: pkgs });
}

describe('npmAttestationScanner', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-attestation-'));
    jest.clearAllMocks();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // ── metadata ─────────────────────────────────────────────────────────────

  test('has correct name and description', () => {
    expect(npmAttestationScanner.name).toBe('NPM Attestation Scanner');
    expect(npmAttestationScanner.description).toMatch(/attestation|provenance/i);
  });

  // ── no lock file ──────────────────────────────────────────────────────────

  test('returns ATTESTATION-000 info when no lock file exists', async () => {
    const result = await npmAttestationScanner.scan(tempDir);

    expect(result.scanner).toBe('NPM Attestation Scanner');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].rule).toBe('ATTESTATION-000');
    expect(result.findings[0].severity).toBe('info');
  });

  // ── all packages have attestations ────────────────────────────────────────

  test('emits no attestation findings when all packages are attested', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'package-lock.json'),
      makeLockfile([{ name: 'express', version: '4.18.2' }]),
    );

    // Respond with attestation present
    mockHttpsGet.mockImplementation((_url: any, _opts: any, cb: any) => {
      cb(makeFakeResponse(200, JSON.stringify({ dist: { attestations: [{ type: 'sigstore' }] } })));
      return makeFakeRequest() as any;
    });

    const result = await npmAttestationScanner.scan(tempDir);
    const attestationFindings = result.findings.filter((f) => f.rule === 'ATTESTATION-001');
    expect(attestationFindings).toHaveLength(0);
  });

  // ── package missing attestation ───────────────────────────────────────────

  test('emits ATTESTATION-001 for each package without attestation', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'package-lock.json'),
      makeLockfile([
        { name: 'lodash', version: '4.17.21' },
        { name: 'moment', version: '2.29.4' },
      ]),
    );

    // Respond with no attestation
    mockHttpsGet.mockImplementation((_url: any, _opts: any, cb: any) => {
      cb(makeFakeResponse(200, JSON.stringify({ dist: {} })));
      return makeFakeRequest() as any;
    });

    const result = await npmAttestationScanner.scan(tempDir);
    const missingFindings = result.findings.filter((f) => f.rule === 'ATTESTATION-001');
    expect(missingFindings).toHaveLength(2);
    expect(missingFindings[0].severity).toBe('info');
    expect(missingFindings[0].message).toMatch(/no npm attestation/i);
  });

  // ── network errors are skipped (no false positives) ───────────────────────

  test('skips packages on network error and emits ATTESTATION-002', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'package-lock.json'),
      makeLockfile([{ name: 'axios', version: '1.6.0' }]),
    );

    mockHttpsGet.mockImplementation((_url: any, _opts: any, _cb: any) => {
      return makeFakeRequest({ emitError: true }) as any;
    });

    const result = await npmAttestationScanner.scan(tempDir);
    const skipped = result.findings.filter((f) => f.rule === 'ATTESTATION-002');
    expect(skipped).toHaveLength(1);
    // Should NOT emit a false-positive ATTESTATION-001 for errored packages
    const falsePositives = result.findings.filter((f) => f.rule === 'ATTESTATION-001');
    expect(falsePositives).toHaveLength(0);
  });

  // ── non-200 response treated as skip ─────────────────────────────────────

  test('skips packages on non-200 HTTP response', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'package-lock.json'),
      makeLockfile([{ name: 'unknown-pkg', version: '0.1.0' }]),
    );

    mockHttpsGet.mockImplementation((_url: any, _opts: any, cb: any) => {
      cb(makeFakeResponse(404, ''));
      return makeFakeRequest() as any;
    });

    const result = await npmAttestationScanner.scan(tempDir);
    const falsePositives = result.findings.filter((f) => f.rule === 'ATTESTATION-001');
    expect(falsePositives).toHaveLength(0);
  });

  // ── scoped packages ───────────────────────────────────────────────────────

  test('handles scoped packages (@scope/name)', async () => {
    const lockfile: Record<string, unknown> = {
      name: 'root',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/@babel/core': {
          version: '7.24.0',
          resolved: 'https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz',
        },
      },
    };
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), JSON.stringify(lockfile));

    let capturedUrl = '';
    mockHttpsGet.mockImplementation((url: any, _opts: any, cb: any) => {
      capturedUrl = typeof url === 'string' ? url : url.toString();
      cb(makeFakeResponse(200, JSON.stringify({ dist: { attestations: [{ type: 'sigstore' }] } })));
      return makeFakeRequest() as any;
    });

    await npmAttestationScanner.scan(tempDir);

    // URL should encode the scoped package name correctly
    expect(capturedUrl).toContain('@babel');
  });

  // ── deduplication ─────────────────────────────────────────────────────────

  test('deduplicates packages with same name@version', async () => {
    // Build a lock file with duplicate entries via nested node_modules
    const lockfile: Record<string, unknown> = {
      name: 'root',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz' },
        'node_modules/express/node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz' },
      },
    };
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), JSON.stringify(lockfile));

    let callCount = 0;
    mockHttpsGet.mockImplementation((_url: any, _opts: any, cb: any) => {
      callCount++;
      cb(makeFakeResponse(200, JSON.stringify({ dist: {} })));
      return makeFakeRequest() as any;
    });

    await npmAttestationScanner.scan(tempDir);

    // lodash@4.17.21 should only be checked once despite appearing twice
    expect(callCount).toBe(1);
  });

  // ── empty lock file ───────────────────────────────────────────────────────

  test('returns empty findings for lock file with no packages', async () => {
    const emptyLock = JSON.stringify({
      name: 'root',
      version: '1.0.0',
      lockfileVersion: 2,
      packages: { '': { name: 'root', version: '1.0.0' } },
    });
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), emptyLock);

    const result = await npmAttestationScanner.scan(tempDir);
    expect(result.findings).toHaveLength(0);
  });

  // ── duration is recorded ──────────────────────────────────────────────────

  test('records duration in result', async () => {
    const result = await npmAttestationScanner.scan(tempDir);
    expect(typeof result.duration).toBe('number');
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });
});
