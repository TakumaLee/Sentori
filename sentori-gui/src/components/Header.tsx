import "./Header.css";

type View = "dashboard" | "scan" | "results";

interface HeaderProps {
  currentView: View;
  onNavigate: (view: View) => void;
}

export default function Header({ currentView, onNavigate }: HeaderProps) {
  return (
    <header className="header">
      <div className="header-brand">
        <span className="header-logo">🛡️</span>
        <span className="header-title">Sentori</span>
        <span className="header-subtitle">AI Agent Security Scanner</span>
      </div>
      <nav className="header-nav">
        <button
          className={`nav-btn ${currentView === "dashboard" ? "active" : ""}`}
          onClick={() => onNavigate("dashboard")}
        >
          Dashboard
        </button>
        <button
          className={`nav-btn ${currentView === "scan" ? "active" : ""}`}
          onClick={() => onNavigate("scan")}
        >
          New Scan
        </button>
        <button
          className={`nav-btn ${currentView === "results" ? "active" : ""}`}
          onClick={() => onNavigate("results")}
        >
          Results
        </button>
      </nav>
    </header>
  );
}
