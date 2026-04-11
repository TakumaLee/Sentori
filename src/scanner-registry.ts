import * as os from 'os';
import { ErrorType, ScanError, Scanner, ScannerOptions, ScanReport, ScanResult } from './types';
import { calculateSummary } from './utils/scorer';

const DEFAULT_SCANNER_TIMEOUT_MS = 30_000;

const FILE_ERROR_CODES = new Set(['ENOENT', 'EACCES', 'EISDIR', 'ENOTDIR', 'EPERM', 'EBADF']);
const NETWORK_ERROR_CODES = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'ECONNRESET']);

function classifyError(err: unknown): ScanError {
  const debug = process.env.SENTORI_DEBUG === 'true';
  if (err instanceof Error) {
    const code = (err as NodeJS.ErrnoException).code ?? '';
    let type: ErrorType;
    if (FILE_ERROR_CODES.has(code)) {
      type = 'FileError';
    } else if (NETWORK_ERROR_CODES.has(code)) {
      type = 'NetworkError';
    } else {
      type = 'LogicError';
    }
    const scanError: ScanError = { type, message: err.message };
    if (debug && err.stack) scanError.stack = err.stack;
    return scanError;
  }
  return { type: 'LogicError', message: String(err) };
}

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

    // Run scanners in parallel with configurable concurrency.
    // Priority: options.concurrency > SENTORI_CONCURRENCY env var > Math.min(5, os.cpus().length)
    // Hard cap at 50 to prevent fd exhaustion from runaway values (e.g. SENTORI_CONCURRENCY=100000).
    const MAX_CONCURRENCY = 50;
    const rawEnvConcurrency = process.env.SENTORI_CONCURRENCY;
    let envConcurrency = NaN;
    if (rawEnvConcurrency !== undefined) {
      envConcurrency = parseInt(rawEnvConcurrency, 10);
      if (!Number.isFinite(envConcurrency) || envConcurrency <= 0) {
        process.stderr.write(JSON.stringify({ level: 'warn', context: 'scanner-registry', message: `SENTORI_CONCURRENCY="${rawEnvConcurrency}" is not a valid positive integer — using default concurrency` }) + '\n');
        envConcurrency = NaN;
      }
    }
    const CONCURRENCY = Math.min(
      options?.concurrency ?? (Number.isFinite(envConcurrency) ? envConcurrency : Math.min(5, os.cpus().length)),
      MAX_CONCURRENCY,
    );
    let nextIndex = 0;
    let completedCount = 0;

    const runNext = async (): Promise<void> => {
      while (nextIndex < total) {
        const i = nextIndex++;
        const scanner = this.scanners[i];

        // Skip if already aborted
        if (signal?.aborted) {
          const scanError: ScanError = { type: 'LogicError', message: 'aborted' };
          results[i] = {
            scanner: scanner.name,
            findings: [],
            duration: 0,
            scannedFiles: 0,
            error: scanError,
          };
          completedCount++;
          onProgress?.(completedCount, total, scanner.name, results[i]);
          continue;
        }

        onProgress?.(completedCount + 1, total, scanner.name);

        const start = Date.now();
        try {
          const scanPromise = scanner.scan(targetDir, options);
          let timer: ReturnType<typeof setTimeout>;
          const timeoutPromise = new Promise<null>((resolve) => {
            timer = setTimeout(() => resolve(null), timeout);
          });

          const result = await Promise.race([scanPromise, timeoutPromise]);
          clearTimeout(timer!);

          if (result === null) {
            const scanError: ScanError = { type: 'TimeoutError', message: `timeout after ${timeout}ms` };
            process.stderr.write(JSON.stringify({ level: 'warn', scanner: scanner.name, ...scanError }) + '\n');
            results[i] = {
              scanner: scanner.name,
              findings: [],
              duration: Date.now() - start,
              scannedFiles: 0,
              error: scanError,
            };
          } else {
            results[i] = result;
          }
        } catch (err) {
          const scanError = classifyError(err);
          process.stderr.write(JSON.stringify({ level: 'error', scanner: scanner.name, ...scanError }) + '\n');
          results[i] = {
            scanner: scanner.name,
            findings: [],
            duration: Date.now() - start,
            scannedFiles: 0,
            error: scanError,
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
