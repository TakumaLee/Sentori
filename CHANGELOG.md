# Changelog

> **Note:** This project was formerly known as **AgentShield** (npm: `aiagentshield`). Renamed to **Sentori** (`@nexylore/sentori`) starting v0.8.1.

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
