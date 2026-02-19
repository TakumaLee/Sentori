import { useState } from "react";
import Header from "./components/Header";
import Dashboard from "./components/Dashboard";
import ScanPanel from "./components/ScanPanel";
import ResultsPanel from "./components/ResultsPanel";
import "./App.css";

type View = "dashboard" | "scan" | "results";

interface ScanResult {
  id: string;
  timestamp: string;
  target: string;
  findings: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

function App() {
  const [currentView, setCurrentView] = useState<View>("dashboard");
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);

  const handleScanComplete = (result: ScanResult) => {
    setScanResults((prev) => [result, ...prev]);
    setCurrentView("results");
  };

  return (
    <div className="app">
      <Header currentView={currentView} onNavigate={setCurrentView} />
      <main className="app-content">
        {currentView === "dashboard" && (
          <Dashboard
            scanResults={scanResults}
            onStartScan={() => setCurrentView("scan")}
          />
        )}
        {currentView === "scan" && (
          <ScanPanel onScanComplete={handleScanComplete} />
        )}
        {currentView === "results" && (
          <ResultsPanel results={scanResults} />
        )}
      </main>
    </div>
  );
}

export default App;
