import { useState } from "react";
import "./ScanPanel.css";

interface ScanResult {
  id: string;
  timestamp: string;
  target: string;
  findings: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

interface ScanPanelProps {
  onScanComplete: (result: ScanResult) => void;
}

const SCANNERS = [
  { id: "supply-chain", label: "Supply Chain Scanner", icon: "🔗" },
  { id: "secret-leak", label: "Secret Leak Scanner", icon: "🔑" },
  { id: "prompt-injection", label: "Prompt Injection Tester", icon: "💉" },
  { id: "mcp-config", label: "MCP Config Auditor", icon: "⚙️" },
  { id: "permissions", label: "Permission Analyzer", icon: "🔒" },
  { id: "dxt-security", label: "DXT Security Scanner", icon: "🧩" },
];

export default function ScanPanel({ onScanComplete }: ScanPanelProps) {
  const [targetPath, setTargetPath] = useState("");
  const [selectedScanners, setSelectedScanners] = useState<string[]>(
    SCANNERS.map((s) => s.id)
  );
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScanner, setCurrentScanner] = useState("");

  const toggleScanner = (id: string) => {
    setSelectedScanners((prev) =>
      prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]
    );
  };

  const handleScan = async () => {
    if (!targetPath.trim()) return;
    setIsScanning(true);
    setScanProgress(0);

    // Simulate scanning progress
    const steps = selectedScanners.length;
    for (let i = 0; i < steps; i++) {
      const scanner = SCANNERS.find((s) => s.id === selectedScanners[i]);
      if (scanner) {
        setCurrentScanner(scanner.label);
        setScanProgress(Math.round(((i + 1) / steps) * 100));
        await new Promise((resolve) => setTimeout(resolve, 600));
      }
    }

    // Mock result
    const severities: ScanResult["severity"][] = [
      "critical", "high", "medium", "low", "info",
    ];
    const result: ScanResult = {
      id: crypto.randomUUID(),
      timestamp: new Date().toLocaleString(),
      target: targetPath,
      findings: Math.floor(Math.random() * 20),
      severity: severities[Math.floor(Math.random() * severities.length)],
    };

    setIsScanning(false);
    setScanProgress(0);
    setCurrentScanner("");
    onScanComplete(result);
  };

  return (
    <div className="scan-panel">
      <h2 className="scan-title">New Security Scan</h2>

      <div className="scan-form">
        <div className="form-group">
          <label className="form-label">Target Path</label>
          <input
            type="text"
            className="form-input"
            placeholder="/path/to/agent or ./my-agent"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            disabled={isScanning}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Scanners</label>
          <div className="scanner-grid">
            {SCANNERS.map((scanner) => (
              <button
                key={scanner.id}
                className={`scanner-toggle ${
                  selectedScanners.includes(scanner.id) ? "selected" : ""
                }`}
                onClick={() => toggleScanner(scanner.id)}
                disabled={isScanning}
              >
                <span>{scanner.icon}</span>
                <span>{scanner.label}</span>
              </button>
            ))}
          </div>
        </div>

        {isScanning && (
          <div className="scan-progress">
            <div className="progress-label">
              Running: {currentScanner}... {scanProgress}%
            </div>
            <div className="progress-bar">
              <div
                className="progress-fill"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        )}

        <button
          className="run-scan-btn"
          onClick={handleScan}
          disabled={isScanning || !targetPath.trim() || selectedScanners.length === 0}
        >
          {isScanning ? "🔍 Scanning..." : "🚀 Run Scan"}
        </button>
      </div>
    </div>
  );
}
