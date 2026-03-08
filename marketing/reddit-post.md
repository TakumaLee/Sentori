# Reddit r/netsec + r/cybersecurity Post

**Title:** I built an open-source security scanner with 30+ scanners specifically for AI agents and MCP servers — it catches attack vectors that Snyk/Semgrep miss entirely

---

AI agents in 2026 operate with full system access: file systems, APIs, databases, code execution. A single compromised MCP server or skill package can escalate to full system access — no exploit chain required.

Generic SAST tools don't understand agent attack surfaces. They won't catch prompt injection in MCP tool descriptions, convention squatting on skill registries, or covert DNS exfiltration channels in agent tools. That's why I built **Sentori**.

## What it does

[**Sentori**](https://github.com/TakumaLee/Sentori) is a free, open-source CLI that runs **30+ security scanners** purpose-built for the AI agent era:

**MCP-specific** — config auditing, tool shadowing detection (lookalike names), git CVE checking, tool result injection, manifest validation

**Prompt injection** — static detection in prompts/tool descriptions, visual prompt injection via OCR on images, RAG poisoning

**Supply chain** — malicious postinstall scripts, convention file squatting (.cursorrules, AGENTS.md registered as domains), IDE rule injection, dependency gate

**DXT (Claude Desktop Extensions)** — unsandboxed execution, dangerous permission combos (the CVSS 10/10 zero-click RCE attack class from LayerX disclosure)

**Covert channels** — DNS/ICMP data exfiltration, clipboard theft

**Agent architecture** — A2A protocol security, permission analyzer, environment isolation audit, defense gap analysis

Outputs a **Security Grade** (A+ to F) with weighted scoring.

## How to use it

```bash
# One command, zero config
npx @nexylore/sentori scan ./your-agent-project

# CI/CD
- uses: TakumaLee/Sentori@main
  with:
    fail-on-critical: 'true'
    upload-sarif: 'true'
```

Ships as a **GitHub Action** with SARIF upload to Code Scanning.

## How it compares

Snyk recently acquired Invariant Labs (mcp-scan) — but mcp-scan only does basic MCP config checking. SentinelOne bought Prompt Security for runtime protection. MEDUSA does live endpoint red-teaming with 76 analyzers.

Sentori is **shift-left**: scan source code before deploy, not react after breach. It's narrower than MEDUSA but deeper on MCP/agent-specific attack vectors (DXT, tool shadowing, result injection, A2A protocol — none of which MEDUSA covers).

**Free, MIT licensed, zero dependencies**: [github.com/TakumaLee/Sentori](https://github.com/TakumaLee/Sentori)

---

**Discussion**: The MCP ecosystem is growing fast but security is an afterthought. CoSAI just published their first MCP security whitepaper (12 threat categories, 40 attack vectors). Should MCP mandate sandboxing? What agent security risks are you seeing in the wild?
