import "./ResultsPanel.css";

interface ScanResult {
  id: string;
  timestamp: string;
  target: string;
  findings: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

interface ResultsPanelProps {
  results: ScanResult[];
}

const SEVERITY_CONFIG = {
  critical: { color: "#ef4444", icon: "🔴", bg: "rgba(239, 68, 68, 0.1)", border: "rgba(239, 68, 68, 0.3)" },
  high: { color: "#f97316", icon: "🟠", bg: "rgba(249, 115, 22, 0.1)", border: "rgba(249, 115, 22, 0.3)" },
  medium: { color: "#eab308", icon: "🟡", bg: "rgba(234, 179, 8, 0.1)", border: "rgba(234, 179, 8, 0.3)" },
  low: { color: "#22c55e", icon: "🟢", bg: "rgba(34, 197, 94, 0.1)", border: "rgba(34, 197, 94, 0.3)" },
  info: { color: "#38bdf8", icon: "🔵", bg: "rgba(56, 189, 248, 0.1)", border: "rgba(56, 189, 248, 0.3)" },
};

export default function ResultsPanel({ results }: ResultsPanelProps) {
  if (results.length === 0) {
    return (
      <div className="results-panel">
        <h2 className="results-title">Scan Results</h2>
        <div className="results-empty">
          No results yet. Run a scan to see findings.
        </div>
      </div>
    );
  }

  return (
    <div className="results-panel">
      <h2 className="results-title">Scan Results</h2>
      <div className="results-list">
        {results.map((result) => {
          const config = SEVERITY_CONFIG[result.severity];
          return (
            <div
              key={result.id}
              className="result-card"
              style={{
                background: config.bg,
                borderColor: config.border,
              }}
            >
              <div className="result-header">
                <span className="result-icon">{config.icon}</span>
                <span className="result-target">{result.target}</span>
                <span
                  className="result-severity"
                  style={{ color: config.color }}
                >
                  {result.severity.toUpperCase()}
                </span>
              </div>
              <div className="result-meta">
                <span className="result-findings">
                  {result.findings} findings detected
                </span>
                <span className="result-time">{result.timestamp}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
