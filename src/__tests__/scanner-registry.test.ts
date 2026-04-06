/**
 * Tests for ScannerRegistry timeout, abort, and partial-failure handling.
 */

import { ScannerRegistry } from '../scanner-registry';
import type { Scanner, ScanResult } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeScanner(name: string, impl: (dir: string) => Promise<ScanResult>): Scanner {
  return { name, description: `test scanner: ${name}`, scan: impl };
}

function okResult(name: string, duration = 10): ScanResult {
  return { scanner: name, findings: [], duration };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ScannerRegistry.runAll', () => {
  it('returns results from all scanners on success', async () => {
    const registry = new ScannerRegistry();
    registry.register(makeScanner('fast-a', async () => okResult('fast-a')));
    registry.register(makeScanner('fast-b', async () => okResult('fast-b')));

    const report = await registry.runAll('/tmp/test', undefined, {});
    expect(report.results).toHaveLength(2);
    expect(report.results[0].scanner).toBe('fast-a');
    expect(report.results[1].scanner).toBe('fast-b');
    expect(report.results.every((r) => r.error === undefined)).toBe(true);
  });

  it('marks a scanner as timed out without blocking others', async () => {
    const registry = new ScannerRegistry();
    registry.register(
      makeScanner('slow', async () => {
        await delay(500);
        return okResult('slow');
      }),
    );
    registry.register(makeScanner('fast', async () => okResult('fast')));

    const report = await registry.runAll('/tmp/test', undefined, { timeout: 100 });

    // slow scanner should have timed out
    const slowResult = report.results.find((r) => r.scanner === 'slow')!;
    expect(slowResult.error?.type).toBe('TimeoutError');
    expect(slowResult.error?.message).toMatch(/timeout/);
    expect(slowResult.findings).toEqual([]);

    // fast scanner should have succeeded
    const fastResult = report.results.find((r) => r.scanner === 'fast')!;
    expect(fastResult.error).toBeUndefined();
  });

  it('skips pending scanners when abort signal is triggered', async () => {
    const controller = new AbortController();
    const registry = new ScannerRegistry();

    // First scanner aborts after completing
    registry.register(
      makeScanner('trigger', async () => {
        controller.abort();
        return okResult('trigger');
      }),
    );
    // Second scanner should be skipped — with 2 scanners, trigger's abort() runs
    // synchronously before the next worker loop iteration checks signal.aborted
    registry.register(makeScanner('skipped', async () => okResult('skipped')));

    const report = await registry.runAll('/tmp/test', undefined, {
      signal: controller.signal,
      timeout: 5000,
    });

    expect(report.results[0].scanner).toBe('trigger');
    expect(report.results[0].error).toBeUndefined();

    expect(report.results[1].scanner).toBe('skipped');
    expect(report.results[1].error?.type).toBe('LogicError');
    expect(report.results[1].error?.message).toBe('aborted');
  });

  it('catches scanner exceptions and records them as errors', async () => {
    const registry = new ScannerRegistry();
    registry.register(
      makeScanner('boom', async () => {
        throw new Error('scanner crashed');
      }),
    );
    registry.register(makeScanner('ok', async () => okResult('ok')));

    const report = await registry.runAll('/tmp/test', undefined, {});

    const boomResult = report.results.find((r) => r.scanner === 'boom')!;
    expect(boomResult.error?.type).toBe('LogicError');
    expect(boomResult.error?.message).toMatch(/scanner crashed/);
    expect(boomResult.findings).toEqual([]);

    const okResultEntry = report.results.find((r) => r.scanner === 'ok')!;
    expect(okResultEntry.error).toBeUndefined();
  });

  it('still produces a valid summary when some scanners fail', async () => {
    const registry = new ScannerRegistry();
    registry.register(
      makeScanner('fail', async () => {
        throw new Error('nope');
      }),
    );
    registry.register(
      makeScanner('good', async () => ({
        scanner: 'good',
        findings: [{ scanner: 'good', severity: 'medium' as const, message: 'test' }],
        duration: 5,
      })),
    );

    const report = await registry.runAll('/tmp/test', undefined, {});

    expect(report.summary).toBeDefined();
    expect(report.summary!.totalFindings).toBe(1);
    expect(report.results).toHaveLength(2);
  });
});
