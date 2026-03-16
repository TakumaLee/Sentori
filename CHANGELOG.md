# Changelog

> **Note:** This project was formerly known as **AgentShield** (npm: `aiagentshield`). Renamed to **Sentori** (`@nexylore/sentori`) starting v0.8.1.

## [0.9.0] - 2026-03-14

### Added
- **NPM Attestation Scanner** — verifies npm package attestations and OIDC provenance signatures for supply chain integrity
- 3-dimension scoring documentation with confidence levels, CLI flags, and JSON output schema

### Fixed
- `--include-vendored` flag now correctly threads through legacy scanner chain (was silently ignored)
- `isDefensePatternFile()` scan bypass vulnerability — path-only match no longer skips content analysis
- QA security hardening: C1 threading fix + H1–H5 audit findings resolved

## [0.8.2] - 2026-03-03

### Added
- **7 new scanners**: MCP Tool Shadowing Detector, MCP Git CVE Scanner, MCP Tool Manifest Scanner, MCP Tool Result Injection Scanner, IDE Rule Injection Scanner, A2A Security Scanner, DXT Security Scanner
- `.sentori.yml` configuration file support with Custom Rules Scanner
- Runtime anomaly detection, alerting, and interceptor
- PackageGate lock file parser + Phase 3 hooks detection
- MCP Server Auditor prototype

### Changed
- Renamed internal config namespace from `openclaw` to `tetora`
- Score calculation now distinguishes own-code vs third-party dependency weights

### Fixed
- ConventionSquattingScanner scan time reduced from 210s to <10s (first-level deps only)
- PromptInjectionScanner no longer flags workspace configuration files
- SupplyChainScanner correctly separates own code from third-party dependencies

## [0.8.1] - 2026-02-22

### Added
- **Agentic Framework Scanner** — security issues across multi-agent frameworks
- **OpenClaw Config Security Scanner** (now Tetora Config Auditor)
- **Python Supply Chain Scanner** — requirements.txt, pyproject.toml, setup.py analysis
- Tauri + React GUI foundation (sentori-gui)

### Changed
- Renamed from AgentShield (`aiagentshield`) to Sentori (`@nexylore/sentori`)

### Fixed
- Corrected bin path to `dist/cli.js`

## [0.8.0] - 2026-02-18

### Added
- ✨ Redesigned CLI output with Security Grade, dimension scores, and ASCII progress bars
- 🔧 Restored and enhanced report formatting (chalk colors, emoji severity icons, dividers)
- 📊 Per-scanner breakdown and dimension analysis (Code Safety / Config Safety / Defense Score / Env Safety)
- 🔍 All 20 scanners now active by default (was 6): AgentConfigAuditor, ChannelSurfaceAuditor, ClipboardExfiltrationScanner, ConventionSquattingScanner, DefenseAnalyzer, DnsIcmpToolScanner, EnvironmentIsolationAuditor, McpConfigAuditor, PermissionAnalyzer, PromptInjectionTester, RagPoisoningScanner, RedTeamSimulator, SecretLeakScanner, SkillAuditor (+ original 6)
- 🎯 Added `--json` and `--output` / `-o` flags for structured report output
- 🏷️  Added `--ioc` flag for external IOC blocklist path
- 🔀 Added `filterScannersByProfile` utility (agent / general / mobile profiles)
- 🐛 Fixed finding field normalization: title/description/recommendation now always populated even if scanner uses legacy rule/message/evidence fields
- 📈 scanner-registry.ts now calls calculateSummary() to populate Security Grade, dimension scores, and per-scanner breakdown

## [0.2.0] - 2026-02-10

### Added
- **Supply Chain Scanner** integrated into default scan registry
  - SUPPLY-001: Base64 hidden command detection
  - SUPPLY-002: Remote code execution pattern detection
  - SUPPLY-003: IOC blocklist matching
  - SUPPLY-004: Credential theft detection
  - SUPPLY-005: Data exfiltration pattern detection
  - SUPPLY-006: Persistence mechanism detection
- External IOC blocklist support (custom JSON file)
- CLI interface (`npx sentori`, formerly `npx aiagentshield`)

## [0.1.0] - Initial Release

### Added
- Core scanner registry and orchestration
- File walker utility
- Type definitions for Scanner, Finding, ScanResult
