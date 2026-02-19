import "./Dashboard.css";

interface ScanResult {
  id: string;
  timestamp: string;
  target: string;
  findings: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

interface DashboardProps {
  scanResults: ScanResult[];
  onStartScan: () => void;
}

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#38bdf8",
};

export default function Dashboard({ scanResults, onStartScan }: DashboardProps) {
  const totalScans = scanResults.length;
  const criticalFindings = scanResults.filter(
    (r) => r.severity === "critical"
  ).length;
  const totalFindings = scanResults.reduce((sum, r) => sum + r.findings, 0);

  return (
    <div className="dashboard">
      <div className="dashboard-hero">
        <h1 className="dashboard-title">
          🛡️ AI Agent Security Scanner
        </h1>
        <p className="dashboard-subtitle">
          守るべきものを、守る。Protect what matters in the agentic era.
        </p>
        <button className="start-scan-btn" onClick={onStartScan}>
          ⚡ Start New Scan
        </button>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{totalScans}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Total Findings</span>
          <span className="stat-value">{totalFindings}</span>
        </div>
        <div className="stat-card critical">
          <span className="stat-label">Critical Issues</span>
          <span className="stat-value" style={{ color: SEVERITY_COLORS.critical }}>
            {criticalFindings}
          </span>
        </div>
      </div>

      {scanResults.length > 0 && (
        <div className="recent-scans">
          <h2>Recent Scans</h2>
          <div className="scan-list">
            {scanResults.slice(0, 5).map((result) => (
              <div key={result.id} className="scan-item">
                <span className="scan-target">{result.target}</span>
                <span className="scan-findings">{result.findings} findings</span>
                <span
                  className="scan-severity"
                  style={{ color: SEVERITY_COLORS[result.severity] }}
                >
                  {result.severity.toUpperCase()}
                </span>
                <span className="scan-time">{result.timestamp}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanResults.length === 0 && (
        <div className="empty-state">
          <p>No scans yet. Start your first security scan to get insights.</p>
        </div>
      )}
    </div>
  );
}
