# Changelog

> **Note:** This project was formerly known as **AgentShield** (npm: `aiagentshield`). Renamed to **Sentori** (`@nexylore/sentori`) starting v0.8.1.

## [Unreleased]

### Changed

- **`ConventionSquattingScanner` — `nodeModulesDepth` default changed from `1` to `0`** ⚠️ **Breaking behavior change**
  node_modules directories are now skipped by default. Previously, first-level dependencies were scanned for TLD-collision packages. Users who relied on this behavior must now explicitly pass `nodeModulesDepth: 1` (programmatic API) or `--node-modules-depth 1` (CLI) to restore the old behavior.
  *Reason: default scanning of node_modules caused ~210s scan times on large repos with deep dependency trees.*

## [0.10.0] - 2026-03-27

### Added
- **MCP OAuth 2.0 Misconfiguration Scanner** — detects insecure OAuth flows in MCP server configurations
- **GitHub MCP Toxic Agent Flow Scanner** — identifies private repo leakage via MCP tool chains (OWASP MCP06)
- **MCP Sampling Abuse Scanner** — detects abuse of MCP sampling/completion endpoints
- **`--discover` mode** — auto-scan common agent config paths without manual specification
- **Japanese prompt injection patterns** (PI-200~207) — multilingual coverage for JP-targeted attacks
- **ReDoS heuristic** for `.sentori.yml` custom rules — warns on catastrophic backtracking patterns
- **YAML custom rules** — warnings display and documentation improvements

### Changed
- **License: MIT → BSL 1.1** — protects against competing scanning services (converts to Apache 2.0 on 2030-03-16)
- **Scanner execution parallelized** — all scanners now run concurrently via scanner-registry
- **Channel Surface Auditor** — rewritten with stream-based file scanning to prevent OOM on large repos
- **A2A Security Scanner** — HTTP redirect following (max 3 hops) for agent card discovery
- Config warnings now emitted as info-level findings visible in JSON/SARIF output
- Confidence levels added across channel-surface, defense-analyzer, permission-analyzer, skill-auditor

### Fixed
- **Shell injection in git-utils** — replaced `execSync` with `execFileSync` to prevent injection via crafted filenames
- `--include-vendored` flag fully threaded through all remaining scanner paths
- `--sarifMode` + `--output` flag combination bug resolved
- Custom Rules Scanner now has per-file timeout (5s) and `SENTORI_DEBUG` mode

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
