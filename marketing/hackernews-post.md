# Hacker News Post

**Title:** Show HN: Sentori – 31 security scanners for AI agents and MCP servers (free, open-source)

---

Sentori is an open-source security scanner built specifically for the AI agent era — MCP servers, Claude Desktop Extensions, agent frameworks, and LLM toolchains.

One command, 31 scanners:

```
npx @nexylore/sentori scan ./your-agent-project
```

What it catches that generic SAST tools miss:

- **MCP attack surface**: config misconfigs, tool shadowing (lookalike names that intercept calls), git CVE checking, tool result injection, manifest validation
- **Prompt injection**: static detection in prompts/tool descriptions, visual prompt injection via OCR on images, RAG poisoning via repetition attacks
- **Supply chain**: malicious postinstall scripts, convention file squatting (AGENTS.md, .cursorrules registered as domains), LangChain deserialization exploits
- **DXT (Claude Desktop Extensions)**: unsandboxed execution, dangerous permission combos — detects the CVSS 10/10 zero-click RCE attack vector (LayerX disclosure, Feb 2026)
- **Covert channels**: DNS/ICMP data exfiltration patterns, clipboard theft
- **Agent architecture**: permission analyzer, environment isolation audit, defense gap analysis, IDE rule injection

Outputs a security grade (A+ to F) with weighted scoring across code safety, config, defense, and environment dimensions.

**CI/CD**: Ships as a GitHub Action with SARIF upload to Code Scanning.

```yaml
- uses: TakumaLee/Sentori@main
  with:
    scan-path: '.'
    fail-on-critical: 'true'
```

**Why now**: Snyk just acquired Invariant Labs, SentinelOne bought Prompt Security, Runlayer raised $11M for MCP gateway security. The market is forming fast, but most tools focus on runtime protection. Sentori is shift-left — scan before deploy, not react after breach.

**Compared to MEDUSA** (76 analyzers, general AI/ML security): Sentori is narrower but deeper on MCP/agent-specific attack vectors. MEDUSA tests live endpoints; Sentori scans source code. Complementary, not competing.

Free and MIT licensed. Built with TypeScript.

GitHub: https://github.com/TakumaLee/Sentori
npm: https://www.npmjs.com/package/@nexylore/sentori
