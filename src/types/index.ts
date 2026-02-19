export type Severity = 'critical' | 'high' | 'medium' | 'info';

/**
 * Scan context controls how findings are severity-adjusted:
 *  - app: default — standard scanning
 *  - framework: framework-aware downgrades for expected patterns
 *  - skill: strict — no downgrades (third-party skill/plugin scanning)
 */
export type ScanContext = 'app' | 'framework' | 'skill';

export type Confidence = 'definite' | 'likely' | 'possible';

export interface Finding {
  id: string;
  scanner: string;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  recommendation: string;
  confidence?: Confidence;
  /** Tagged as [TEST] — from test files, excluded from scoring */
  isTestFile?: boolean;
}

export interface ScanResult {
  scanner: string;
  findings: Finding[];
  scannedFiles: number;
  duration: number; // ms
}

export interface ScanReport {
  version: string;
  timestamp: string;
  target: string;
  results: ScanResult[];
  summary: ReportSummary;
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
}

export interface ScannerModule {
  name: string;
  description: string;
  scan(targetPath: string, options?: ScannerOptions): Promise<ScanResult>;
}

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
