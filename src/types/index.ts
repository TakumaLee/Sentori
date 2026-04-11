export type Severity = 'critical' | 'high' | 'medium' | 'info';

export type ErrorType = 'FileError' | 'TimeoutError' | 'NetworkError' | 'LogicError';

export interface ScanError {
  type: ErrorType;
  message: string;
  /** Stack trace — present only when SENTORI_DEBUG=true */
  stack?: string;
}

/**
 * Scan context controls how findings are severity-adjusted:
 *  - app: default — standard scanning
 *  - framework: framework-aware downgrades for expected patterns
 *  - skill: strict — no downgrades (third-party skill/plugin scanning)
 */
export type ScanContext = 'app' | 'framework' | 'skill';

export type Confidence = 'definite' | 'likely' | 'possible';

export interface Finding {
  id?: string;
  scanner: string;
  severity: Severity;
  title: string;
  description: string;
  rule?: string;
  message?: string;
  evidence?: string;
  file?: string;
  line?: number;
  recommendation?: string;
  confidence?: Confidence;
  /** Tagged as [TEST] — from test files, excluded from scoring */
  isTestFile?: boolean;
  /** Tagged as third-party code (node_modules, venv, vendor) vs own source code */
  isThirdParty?: boolean;
}

export interface ScanResult {
  scanner: string;
  findings: Finding[];
  scannedFiles: number;
  duration: number; // ms
  /** Present when the scanner timed out, was aborted, or threw an error */
  error?: ScanError;
}

export interface ScanReport {
  version?: string;
  timestamp: string;
  target: string;
  results: ScanResult[];
  summary?: ReportSummary;
  totalFindings?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
}

export interface DimensionScore {
  score: number;
  grade: string;
  findings: number;
}

export interface ReportSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  info: number;
  grade: string; // A+ ~ F
  score: number; // 0 ~ 100
  scannedFiles: number;
  ignoredFiles?: number;
  duration: number;
  dimensions?: {
    codeSafety: DimensionScore;
    configSafety: DimensionScore;
    defenseScore: DimensionScore;
    environmentSafety: DimensionScore;
  };
  scannerBreakdown?: Record<string, Record<Severity, number>>;
}

export interface ScannerOptions {
  exclude?: string[];
  context?: ScanContext;
  includeVendored?: boolean;
  /** Additional glob patterns from .sentoriignore */
  sentoriIgnorePatterns?: string[];
  /** When true, scan sub-projects inside workspace/ directories. Default: false. */
  includeWorkspaceProjects?: boolean;
  /** Per-scanner timeout in milliseconds. Default: 30000 */
  timeout?: number;
  /** AbortSignal to cancel remaining scanners */
  signal?: AbortSignal;
  /** Maximum number of scanners to run in parallel. Default: Math.min(5, os.cpus().length) */
  concurrency?: number;
}

/** Unified scanner interface — covers both class-based and module-based scanners. */
export interface Scanner {
  name: string;
  description: string;
  scan(targetDir: string, options?: ScannerOptions): Promise<ScanResult>;
}

/**
 * @deprecated Use Scanner directly. Kept as a type alias for backward compatibility.
 */
export type ScannerModule = Scanner;

export interface McpServerConfig {
  mcpServers?: Record<string, McpServerEntry>;
  [key: string]: unknown;
}

export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  tools?: McpToolConfig[];
  permissions?: Record<string, unknown>;
  allowlist?: string[];
  denylist?: string[];
  [key: string]: unknown;
}

export interface McpToolConfig {
  name: string;
  description?: string;
  permissions?: string[];
  allowedPaths?: string[];
  blockedPaths?: string[];
  [key: string]: unknown;
}
