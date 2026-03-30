import { Scanner, ScannerOptions, ScanReport, ScanResult } from './types';
import { calculateSummary } from './utils/scorer';

const DEFAULT_SCANNER_TIMEOUT_MS = 30_000;

export class ScannerRegistry {
  private scanners: Scanner[] = [];

  register(scanner: Scanner): void {
    this.scanners.push(scanner);
  }

  getScanners(): Scanner[] {
    return [...this.scanners];
  }

  setScanners(scanners: Scanner[]): void {
    this.scanners = [...scanners];
  }

  async runAll(targetDir: string, onProgress?: (step: number, total: number, scannerName: string, result?: ScanResult) => void, options?: ScannerOptions): Promise<ScanReport> {
    const timestamp = new Date().toISOString();
    const total = this.scanners.length;
    const results: ScanResult[] = new Array(total);
    const timeout = options?.timeout ?? DEFAULT_SCANNER_TIMEOUT_MS;
    const signal = options?.signal;

    // Run scanners in parallel with concurrency limit of 5
    const CONCURRENCY = 5;
    let nextIndex = 0;
    let completedCount = 0;

    const runNext = async (): Promise<void> => {
      while (nextIndex < total) {
        const i = nextIndex++;
        const scanner = this.scanners[i];

        // Skip if already aborted
        if (signal?.aborted) {
          results[i] = {
            scanner: scanner.name,
            findings: [],
            duration: 0,
            error: 'aborted',
          };
          completedCount++;
          onProgress?.(completedCount, total, scanner.name, results[i]);
          continue;
        }

        onProgress?.(completedCount + 1, total, scanner.name);

        const start = Date.now();
        try {
          const scanPromise = scanner.scan(targetDir, options);
          const timeoutPromise = new Promise<null>((resolve) =>
            setTimeout(() => resolve(null), timeout)
          );

          const result = await Promise.race([scanPromise, timeoutPromise]);

          if (result === null) {
            results[i] = {
              scanner: scanner.name,
              findings: [],
              duration: Date.now() - start,
              error: `timeout after ${timeout}ms`,
            };
          } else {
            results[i] = result;
          }
        } catch (err) {
          results[i] = {
            scanner: scanner.name,
            findings: [],
            duration: Date.now() - start,
            error: String(err),
          };
        }

        completedCount++;
        onProgress?.(completedCount, total, scanner.name, results[i]);
      }
    };

    const workers = Array.from({ length: Math.min(CONCURRENCY, total) }, () => runNext());
    await Promise.all(workers);

    const summary = calculateSummary(results);

    return {
      target: targetDir,
      timestamp,
      results,
      summary,
      totalFindings: summary.totalFindings,
      criticalCount: summary.critical,
      highCount: summary.high,
      mediumCount: summary.medium,
      lowCount: summary.info,
    };
  }
}
