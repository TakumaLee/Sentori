# AgentShield

Security scanner for AI agent ecosystems. Detects supply chain poisoning, malicious payloads, and other threats in agent skill packages.

## Features

- **Supply Chain Scanner** — Detects skill poisoning attacks:
  - Base64 hidden commands (SUPPLY-001)
  - Remote code execution patterns (SUPPLY-002)
  - IOC blocklist matching (SUPPLY-003)
  - Credential theft detection (SUPPLY-004)
  - Data exfiltration patterns (SUPPLY-005)
  - Persistence mechanisms (SUPPLY-006)

## Usage

```bash
# Scan a directory
npx agentshield ./path/to/agent

# With external IOC blocklist
npx agentshield ./path/to/agent ./custom-ioc-blocklist.json
```

## IOC Blocklist

The built-in blocklist is at `src/data/ioc-blocklist.json`. You can provide an external JSON file with the same format to extend it.

## Development

```bash
npm install
npm run build
npm test
```

## Architecture

- `src/types.ts` — Core type definitions (Scanner, Finding, ScanResult)
- `src/scanner-registry.ts` — Scanner registration and orchestration
- `src/scanners/` — Individual scanner implementations
- `src/utils/` — Shared utilities (file walking, etc.)
- `src/data/` — Static data (IOC blocklists)
