import { Scanner, ScanReport, ScanResult } from './types';
import { calculateSummary } from './utils/scorer';

export class ScannerRegistry {
  private scanners: Scanner[] = [];

  register(scanner: Scanner): void {
    this.scanners.push(scanner);
  }

  getScanners(): Scanner[] {
    return [...this.scanners];
  }

  async runAll(targetDir: string, onProgress?: (step: number, total: number, scannerName: string, result?: ScanResult) => void): Promise<ScanReport> {
    const timestamp = new Date().toISOString();
    const results: ScanResult[] = [];
    const total = this.scanners.length;

    for (let i = 0; i < total; i++) {
      const scanner = this.scanners[i];
      onProgress?.(i + 1, total, scanner.name);
      const result = await scanner.scan(targetDir);
      results.push(result);
      onProgress?.(i + 1, total, scanner.name, result);
    }

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
