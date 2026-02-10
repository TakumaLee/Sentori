import { Scanner, ScanReport, ScanResult } from './types';

export class ScannerRegistry {
  private scanners: Scanner[] = [];

  register(scanner: Scanner): void {
    this.scanners.push(scanner);
  }

  getScanners(): Scanner[] {
    return [...this.scanners];
  }

  async runAll(targetDir: string): Promise<ScanReport> {
    const timestamp = new Date().toISOString();
    const results: ScanResult[] = [];

    for (const scanner of this.scanners) {
      const result = await scanner.scan(targetDir);
      results.push(result);
    }

    const allFindings = results.flatMap((r) => r.findings);

    return {
      target: targetDir,
      timestamp,
      results,
      totalFindings: allFindings.length,
      criticalCount: allFindings.filter((f) => f.severity === 'CRITICAL').length,
      highCount: allFindings.filter((f) => f.severity === 'HIGH').length,
      mediumCount: allFindings.filter((f) => f.severity === 'MEDIUM').length,
      lowCount: allFindings.filter((f) => f.severity === 'LOW').length,
    };
  }
}
