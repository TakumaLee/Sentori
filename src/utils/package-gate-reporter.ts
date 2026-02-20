/**
 * PackageGate Reporter — Phase 3C
 *
 * Generates a structured `PackageGateReport` from a `ScanResult` produced by
 * `PackageGateScanner`.  The report aggregates:
 *  - Lock file paths involved
 *  - Total version conflicts (PKGATE-001 / 002 / 003)
 *  - Total suspicious hook findings (PKGATE-010 / 011 / 012 / 013)
 *  - Critical-severity findings
 *  - Human-readable one-line summary
 */

import { Finding, ScanResult } from '../types';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface PackageGateReport {
  /** Scanned target directory path */
  target: string;
  /** ISO 8601 timestamp when the report was generated */
  scannedAt: string;
  /** Unique lock file paths that produced conflict findings */
  lockFiles: string[];
  /** Number of version-conflict findings (PKGATE-001/002/003) */
  totalConflicts: number;
  /** Number of suspicious-hook findings (PKGATE-010/011/012/013) */
  suspiciousHooks: number;
  /** All findings with severity === 'critical' */
  criticalFindings: Finding[];
  /** All findings from the scan (unfiltered) */
  allFindings: Finding[];
  /** Human-readable one-line summary */
  summary: string;
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** Finding IDs that originate from lock-file version-conflict detection */
const LOCK_CONFLICT_IDS = new Set(['PKGATE-001', 'PKGATE-002', 'PKGATE-003']);

/** Finding IDs that originate from install-hook detection */
const HOOK_FINDING_IDS = new Set(['PKGATE-010', 'PKGATE-011', 'PKGATE-012', 'PKGATE-013']);

// ---------------------------------------------------------------------------
// generatePackageGateReport
// ---------------------------------------------------------------------------

/**
 * Build a `PackageGateReport` from a completed `ScanResult`.
 *
 * @param result   The `ScanResult` returned by `PackageGateScanner.scan()`
 * @param target   The directory path that was scanned (passed through to the report)
 * @returns        Populated `PackageGateReport`
 */
export function generatePackageGateReport(
  result: ScanResult,
  target: string,
): PackageGateReport {
  const allFindings = result.findings;

  // --- version conflicts
  const conflictFindings = allFindings.filter(
    (f) => f.id !== undefined && LOCK_CONFLICT_IDS.has(f.id),
  );
  const totalConflicts = conflictFindings.length;

  // --- suspicious hooks
  const hookFindings = allFindings.filter(
    (f) => f.id !== undefined && HOOK_FINDING_IDS.has(f.id),
  );
  const suspiciousHooks = hookFindings.length;

  // --- critical findings (any severity === 'critical')
  const criticalFindings = allFindings.filter((f) => f.severity === 'critical');

  // --- unique lock files (from conflict findings only; hook findings point to package.json)
  const lockFiles = [
    ...new Set(
      conflictFindings
        .filter((f) => typeof f.file === 'string' && f.file.length > 0)
        .map((f) => f.file as string),
    ),
  ];

  // --- human-readable summary
  const summary = buildSummary(target, totalConflicts, suspiciousHooks, criticalFindings.length);

  return {
    target,
    scannedAt: new Date().toISOString(),
    lockFiles,
    totalConflicts,
    suspiciousHooks,
    criticalFindings,
    allFindings,
    summary,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildSummary(
  target: string,
  conflicts: number,
  hooks: number,
  criticals: number,
): string {
  if (conflicts === 0 && hooks === 0) {
    return `PackageGate scan of "${target}" completed: no issues found.`;
  }

  const parts: string[] = [];
  if (conflicts > 0) {
    parts.push(`${conflicts} version conflict${conflicts !== 1 ? 's' : ''}`);
  }
  if (hooks > 0) {
    parts.push(`${hooks} suspicious hook${hooks !== 1 ? 's' : ''}`);
  }
  if (criticals > 0) {
    parts.push(`${criticals} critical finding${criticals !== 1 ? 's' : ''}`);
  }

  return `PackageGate scan of "${target}": ${parts.join(', ')}.`;
}
