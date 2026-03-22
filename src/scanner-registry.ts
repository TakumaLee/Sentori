import { Scanner, ScannerOptions, ScanReport, ScanResult } from './types';
import { calculateSummary } from './utils/scorer';

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

    // Run scanners in parallel with concurrency limit of 5
    const CONCURRENCY = 5;
    let nextIndex = 0;
    let completedCount = 0;

    const runNext = async (): Promise<void> => {
      while (nextIndex < total) {
        const i = nextIndex++;
        const scanner = this.scanners[i];
        onProgress?.(completedCount + 1, total, scanner.name);
        // Module-based scanners (ScannerModule) accept an optional second options
        // argument. Class-based legacy scanners ignore extra arguments in JS, so
        // it is safe to always pass options — they will silently be discarded.
        const result = await (scanner.scan as (dir: string, opts?: ScannerOptions) => Promise<ScanResult>).call(scanner, targetDir, options);
        results[i] = result;
        completedCount++;
        onProgress?.(completedCount, total, scanner.name, result);
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
