# Hacker News Post

**Title:** Show HN: Sentori – Open-source security scanner for AI Agent projects (13 scanners, CLI + web)

---

Sentori is a free, open-source tool that scans AI Agent projects for security vulnerabilities. It runs 13 specialized scanners:

- Supply Chain Scanner (vulnerable/malicious deps)
- Deployment Hygiene Auditor (leaked secrets, misconfigs)
- Convention File Squatting Detector (malicious AGENTS.md, .cursorrules, etc.)
- MCP configuration risk analysis
- Prompt injection surface detection
- ...and 8 more

**CLI:**
```
npx @nexylore/sentori /path/to/project
```

**Web:** Paste a GitHub URL at https://sentori-web.vercel.app — no signup.

**GitHub:** https://github.com/TakumaLee/Sentori

Timely context: LayerX just disclosed a CVSS 10/10 zero-click RCE in Anthropic's DXT (Claude Desktop Extensions) — unsandboxed MCP servers + autonomous tool chaining = a calendar event can execute arbitrary code. Anthropic declined to fix. We're adding a DXT-specific scanner to detect unsandboxed extensions and dangerous permission combos.

The broader problem: AI agent frameworks are shipping with full system access and no privilege separation. Sentori tries to give developers visibility into these risks before deployment.

Built with TypeScript. PRs welcome.
