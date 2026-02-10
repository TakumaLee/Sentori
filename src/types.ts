export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Finding {
  scanner: string;
  rule: string;
  severity: Severity;
  file: string;
  line: number;
  message: string;
  evidence: string;
}

export interface ScanResult {
  scanner: string;
  findings: Finding[];
  filesScanned: number;
  duration: number;
}

export interface Scanner {
  name: string;
  description: string;
  scan(targetDir: string): Promise<ScanResult>;
}

export interface ScanReport {
  target: string;
  timestamp: string;
  results: ScanResult[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}
