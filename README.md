# Sentori

![Sentori](./assets/logo.png)

> **AI Agent Security Scanner — 守るべきものを、守る。**

[![npm version](https://img.shields.io/npm/v/@nexylore/sentori.svg)](https://www.npmjs.com/package/@nexylore/sentori)
[![license](https://img.shields.io/npm/l/@nexylore/sentori.svg)](./LICENSE)
[![tests](https://img.shields.io/github/actions/workflow/status/TakumaLee/AgentShield/ci.yml?label=tests)](https://github.com/TakumaLee/AgentShield/actions)

**Sentori** is a security scanner purpose-built for the MCP (Model Context Protocol) ecosystem and AI agent toolchains. Where broad surface-area tools scan everything loosely, Sentori goes deep — covering prompt injection, supply chain poisoning, MCP misconfigs, secret leaks, and agentic attack vectors that generic scanners miss entirely.

*Depth over breadth. MCP-native from day one.*

---

## 🚀 Quick Start

```bash
# Scan current directory
npx @nexylore/sentori scan

# Scan a specific agent project
npx @nexylore/sentori scan ./path/to/agent

# JSON output for CI/CD pipelines
npx @nexylore/sentori scan ./path/to/agent --json

# Save report to file
npx @nexylore/sentori scan ./path/to/agent --output report.json

# Enable deep scan (OCR on images)
npx @nexylore/sentori scan ./path/to/agent --deep-scan
```

---

## Why Sentori?

AI agents in 2026 operate with real tool access: file systems, APIs, databases, code execution. A single compromised MCP server or skill package can escalate to full system access — no exploit chain required.

**Generic SAST tools don't understand agent attack surfaces.** They won't catch:
- Prompt injection embedded in MCP tool descriptions
- Convention squatting attacks on skill registries
- Covert DNS/ICMP exfiltration channels in agent tools
- Visual prompt injection hidden in image metadata
- RAG poisoning via repetition attacks in knowledge bases

Sentori was built specifically for these agentic threat vectors.

---

## 🔍 20 Security Scanners

Sentori v0.8.1 ships with **20 scanners** across 5 categories:

### 🔗 Supply Chain & Code Integrity

| Scanner | What it catches |
|---------|----------------|
| **Supply Chain Scanner** | Base64 hidden commands, RCE patterns, IOC blocklist, credential theft, data exfiltration, persistence mechanisms |
| **Postinstall Scanner** | Malicious `postinstall` scripts that execute on package installation |
| **LangChain Serialization Scanner** | Unsafe pickle/deserialization in LangChain and agent pipelines |
| **Convention Squatting Scanner** | Typosquatting, prefix hijacking, namespace confusion on skill and MCP server names |

### 💉 Prompt Injection & Adversarial

| Scanner | What it catches |
|---------|----------------|
| **Prompt Injection Tester** | Known injection patterns in prompts, MCP tool descriptions, and user-facing text |
| **Visual Prompt Injection Scanner** | Hidden instructions embedded in images (alt text, metadata, steganography) |
| **RAG Poisoning Scanner** | Repetition attacks and content poisoning in RAG knowledge bases |
| **Red Team Simulator** | Simulates jailbreaks, role-play exploits, multi-turn attacks, and indirect injection vectors |

### 🔐 Secrets & Data Protection

| Scanner | What it catches |
|---------|----------------|
| **Secret Leak Scanner** | API keys, tokens, passwords, private keys across code and configs |
| **Clipboard Exfiltration Scanner** | Clipboard access patterns used for silent data theft |
| **DNS/ICMP Tool Scanner** | Covert data exfiltration via DNS tunneling or ICMP channels in agent tools |

### 🛡️ Configuration & Permissions

| Scanner | What it catches |
|---------|----------------|
| **DXT Security Scanner** | Insecure Claude Desktop Extensions — unsandboxed execution, unrestricted file/network access |
| **MCP Config Auditor** | Dangerous MCP server configurations, overprivileged tools, missing authentication |
| **Agent Config Auditor** | Risky agent configurations, missing safety guardrails and rate limits |
| **Hygiene Auditor** | Overly broad permissions, missing access controls, risky defaults |
| **Permission Analyzer** | Excessive permission grants, missing least-privilege enforcement |
| **Environment Isolation Auditor** | Missing sandboxing, shared environments, container escape risks |

### 🧪 Architecture & Defense

| Scanner | What it catches |
|---------|----------------|
| **Skill Auditor** | Skill package structure issues, unsafe patterns, missing validation |
| **Channel Surface Auditor** | Multi-channel attack surfaces, unprotected input channels |
| **Defense Analyzer** | Missing defense layers, gaps in security architecture |

### 🔮 Coming Soon — MCP Specialist Suite

The next release targets MCP-specific attack surfaces not covered by any existing tool:

- **MCP Tool Shadowing Detector** — detects tools that mimic legitimate MCP server names to intercept calls
- **Cross-Agent Trust Boundary Scanner** — flags unsafe agent-to-agent communication patterns
- **MCP Schema Injection Scanner** — finds injection vectors in MCP tool schema definitions
- **Agentic Loop Detector** — identifies infinite loop / resource exhaustion risks in multi-step agent plans

---

## 📊 Security Scoring

Sentori outputs a **Security Grade** (A+ to F) based on weighted findings across 4 dimensions:

```
╔══════════════════════════════════════════╗
║         Sentori Security Report          ║
╠══════════════════════════════════════════╣
║  Security Grade:  B+    (78/100)         ║
║  Findings:  2 high · 5 medium · 3 low   ║
║  Scanners:  20/20 active                 ║
╚══════════════════════════════════════════╝
```

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| Code Safety | 40% | Supply chain, secrets, injection patterns in code |
| Config Safety | 30% | MCP configs, DXT manifests, agent YAML |
| Defense Score | 20% | Presence of guardrails, sandboxing, rate limits |
| Env Safety | 10% | Isolation, shared environment risks |

---

## 🆚 Sentori vs MEDUSA (and others)

| Capability | Sentori | MEDUSA | Generic SAST |
|------------|---------|--------|-------------|
| MCP config auditing | ✅ Deep | ❌ | ❌ |
| DXT (Claude Desktop) scanning | ✅ | ❌ | ❌ |
| Visual prompt injection (OCR) | ✅ | ❌ | ❌ |
| Convention squatting detection | ✅ | ❌ | ❌ |
| DNS/ICMP exfil channels | ✅ | ✅ | ❌ |
| RAG poisoning | ✅ | ❌ | ❌ |
| Red team simulation | ✅ | ✅ | ❌ |
| Supply chain (npm scripts) | ✅ | ✅ | Partial |
| Secret detection | ✅ | Partial | ✅ |
| Zero config, npx-ready | ✅ | ❌ | Varies |
| CI/CD GitHub Action | ✅ | ❌ | Varies |

**MEDUSA** is a framework-level red-teaming tool for testing live agent endpoints. **Sentori** is a static/source-level scanner for agent codebases and MCP servers before deployment. They're complementary, not competing.

---

## 💰 Pricing

| Plan | Price | Features |
|------|-------|---------|
| **Free** | $0 | All 20 scanners, CLI + npx, JSON output, GitHub Action, unlimited local scans |
| **Pro Cloud** | $29/mo | Everything in Free + cloud scan dashboard, team reports, Slack/GitHub notifications, scan history, priority support |
| **Enterprise** | Custom | Everything in Pro + custom scanner rules, SSO/SAML, air-gapped deployment, SLA, dedicated security review |

> Pro Cloud and Enterprise ship Q2 2026. [Join the waitlist →](https://nexylore.com/sentori)

---

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
- name: Sentori Security Scan
  uses: TakumaLee/AgentShield@main
  with:
    scan-path: '.'
    fail-on-critical: 'true'
    output-format: 'text'
```

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Path to scan | `.` |
| `fail-on-critical` | Fail workflow on critical findings | `true` |
| `output-format` | Output format (`text` or `json`) | `text` |

---

## 📦 Programmatic API

```typescript
import { ScannerRegistry, SupplyChainScanner, DxtSecurityScanner } from '@nexylore/sentori';

const registry = new ScannerRegistry();
registry.register(new SupplyChainScanner());
registry.register(new DxtSecurityScanner());

const report = await registry.runAll('./target-directory');
console.log(report.summary);
```

---

## Configuration

### `.sentoriignore`

Create a `.sentoriignore` file in your project root to exclude paths from scanning (gitignore syntax):

```
# Exclude vendored dependencies
vendor/
third_party/

# Exclude specific directories
docs/
examples/
```

### IOC Blocklist

The built-in IOC blocklist is at `src/data/ioc-blocklist.json`. Provide an external JSON file to extend it:

```bash
npx @nexylore/sentori scan ./agent --ioc ./custom-ioc-blocklist.json
```

---

## Development

```bash
npm install
npm run build
npm test
```

---

## About Nexylore

**Sentori** is built and maintained by [Nexylore](https://nexylore.com) — a security tooling company focused on the agentic AI era.

*守るべきものを、守る。* — Protect what must be protected.

---

## License

MIT © Nexylore
