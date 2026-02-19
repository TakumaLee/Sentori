# Reddit r/cybersecurity Post

**Title:** Anthropic's DXT just got a CVSS 10/10 zero-click RCE — here's a free open-source tool to scan your AI Agent projects for similar risks

---

By now you've probably seen the LayerX disclosure: Claude Desktop Extensions (DXT) run **unsandboxed with full system privileges**, and a single malicious Google Calendar event can chain through MCP connectors to achieve zero-click RCE on the host system. CVSS 10/10. Anthropic declined to fix it, saying it "falls outside our current threat model."

This affects 10,000+ active users and 50+ DXT extensions. The core issue isn't just DXT — it's that **MCP-based AI agents blur trust boundaries** between low-risk data sources (calendars, emails) and high-risk local executors (file system, shell). And most projects have zero visibility into these risks.

## What we built

I've been working on [**Sentori**](https://github.com/TakumaLee/Sentori), an open-source CLI that scans AI Agent projects for security issues. It runs **20 scanners** covering:

- **Supply Chain Scanner** — detects vulnerable or malicious dependencies
- **Deployment Hygiene Auditor** — checks for leaked secrets, misconfigured permissions
- **Convention File Squatting Detector** — catches malicious files disguised as config files (AGENTS.md, .cursorrules, etc.)
- **DXT Security Scanner** — flags unsandboxed extensions and dangerous permission combinations
- And 16 more covering prompt injection surface, MCP config risks, visual prompt injection, and more (v0.8.1)

We're also building a **DXT Scanner** specifically designed to flag unsandboxed extensions and dangerous permission combinations — directly inspired by this vulnerability class.

## How to use it (free)

**CLI (scan local projects):**
```bash
npx @nexylore/sentori /path/to/project
```

**Web (scan any GitHub repo):**
Just paste a GitHub URL at [sentori-web.vercel.app](https://sentori-web.vercel.app) — no signup, no cost.

It's fully open source (latest: v0.8.1 with Security Grade + 20 scanners): [github.com/TakumaLee/Sentori](https://github.com/TakumaLee/Sentori)

## Discussion

The DXT vulnerability is a symptom of a bigger problem: AI agent frameworks are shipping fast and treating security as an afterthought. MCP has no built-in privilege separation, no mandatory sandboxing, no workflow validation.

**What's your take?** Should MCP servers be sandboxed by default? Is Anthropic's "outside our threat model" response acceptable for a platform that grants full system access? Curious what this community thinks.
