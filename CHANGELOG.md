# Changelog

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
- CLI interface (`npx agentshield`)

## [0.1.0] - Initial Release

### Added
- Core scanner registry and orchestration
- File walker utility
- Type definitions for Scanner, Finding, ScanResult
