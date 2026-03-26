import { minimatch } from 'minimatch';
import { ScanReport } from '../types';
import { SentoriConfig } from '../config/sentori-config';

/**
 * Apply ignore entries and severity overrides from .sentori.yml to a completed
 * scan report. Does not mutate the input; returns a new report object.
 */
export function applyConfig(report: ScanReport, config: SentoriConfig): ScanReport {
  const { ignore, overrides } = config;

  const results = report.results.map((result) => {
    let findings = result.findings;

    // 1. Severity overrides — must run before ignore so overrides apply to kept findings
    if (overrides.length > 0) {
      findings = findings.map((f) => {
        for (const ov of overrides) {
          if (ov.scanner !== result.scanner) continue;
          if (ov.rule !== undefined && ov.rule !== f.rule) continue;
          return { ...f, severity: ov.severity };
        }
        return f;
      });
    }

    // 2. Ignore filters — suppress findings where ALL specified fields match
    if (ignore.length > 0) {
      findings = findings.filter((f) => {
        for (const ig of ignore) {
          const scannerMatch = ig.scanner === undefined || ig.scanner === result.scanner;
          const ruleMatch = ig.rule === undefined || ig.rule === f.rule;
          const fileMatch =
            ig.file === undefined ||
            (f.file !== undefined && minimatch(f.file, ig.file, { matchBase: false }));

          if (scannerMatch && ruleMatch && fileMatch) return false; // suppress
        }
        return true; // keep
      });
    }

    return { ...result, findings };
  });

  return { ...report, results };
}
