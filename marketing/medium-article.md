# Your AI Agent Has Full Access to Your System — And That's Exactly the Problem

*A deep dive into the Anthropic DXT zero-click RCE vulnerability, why AI Agent security is broken, and how to actually check if your project is at risk.*

---

## A Calendar Invite That Owns Your Computer

Let me paint you a picture.

You're using Claude Desktop with a couple of extensions — a Google Calendar connector to manage your schedule, maybe a file manager to organize documents. Perfectly reasonable productivity setup. You tell Claude, "Take care of my schedule for today."

Behind the scenes, Claude reads your calendar. One of the events looks normal — a meeting invite, maybe with a slightly unusual description. But that description contains carefully crafted instructions. Claude, doing what it does best — following instructions — chains that input into a local MCP server with code execution capabilities.

And just like that, a calendar invite has executed arbitrary code on your machine. Zero clicks. No warnings. No confirmation dialogs. You don't know anything happened until it's too late.

This isn't a hypothetical scenario. This is CVE-worthy, CVSS 10/10, disclosed by LayerX Security on February 10, 2026. It affects over 10,000 active Claude Desktop Extension users and 50+ DXT extensions.

Anthropic's response? "Falls outside our current threat model."

Let that sink in.

---

## Understanding the DXT Vulnerability

### What Are Claude Desktop Extensions?

Claude Desktop Extensions (DXT) are MCP servers packaged as `.mcpb` bundles — essentially zip files containing an MCP server implementation and a manifest defining exposed functions. They look and feel like browser extensions: one-click install, familiar UX.

But that's where the similarity ends.

**Chrome extensions run in a tightly sandboxed environment** with no direct system access. DXT extensions run **unsandboxed, with full host system privileges**. They can:

- Read arbitrary files on your system
- Execute shell commands
- Access stored credentials
- Modify OS settings

They're not plugins. They're **privileged execution bridges** between Claude's language model and your operating system.

### The Attack Chain

The vulnerability exploits a fundamental design flaw in how Claude orchestrates MCP connectors:

1. **Data ingestion**: Claude reads data from a low-risk source (Google Calendar) via an MCP connector
2. **Autonomous chaining**: Claude decides, without user input, to process that data using a high-risk MCP server (one with local code execution capabilities)
3. **Code execution**: The malicious payload embedded in the calendar event is executed with full system privileges
4. **Zero interaction**: The entire chain happens autonomously — no user confirmation, no permission prompts

The core issue is **trust boundary violation**. MCP has no mechanism to distinguish between data that's safe to pass to a code executor and data that isn't. There are no hardcoded safeguards preventing Claude from constructing dangerous workflows. Low-risk input flows freely to high-risk actions.

### Why Anthropic Won't Fix It

Anthropic stated the vulnerability "falls outside our current threat model." This likely means the behavior is considered consistent with MCP's design philosophy of autonomy and interoperability. In other words: it's working as intended.

This is a philosophical position, not a technical one. And it's one that leaves 10,000+ users exposed.

---

## The Bigger Picture: AI Agent Security Is Broken

The DXT vulnerability is alarming, but it's a symptom, not the disease. The real problem is systemic.

### AI Agents Are Shipping Without Security Fundamentals

The AI agent ecosystem is in a gold rush. Frameworks are shipping fast, ecosystems are growing faster, and security is consistently treated as "someone else's problem." Consider what's missing:

**No sandboxing by default.** Most AI agent frameworks, not just DXT, grant extensions and tools direct system access. The Chrome extension model — decades of sandboxing research — is being ignored.

**No privilege separation.** MCP connectors operate at the same privilege level regardless of their risk profile. A calendar reader has the same access as a code executor.

**No workflow validation.** There's no mechanism to validate whether a workflow constructed by the LLM is safe before execution. The model decides what tools to chain and in what order.

**No supply chain verification.** AI agent extensions and MCP servers are distributed with minimal vetting. The npm ecosystem's supply chain problems are being replicated in a context where compromised packages have direct system access.

### Attack Surfaces You're Probably Not Thinking About

Beyond the DXT-specific issue, AI agent projects face a range of security risks that most developers haven't considered:

- **Convention file squatting**: Malicious files disguised as legitimate config files (`.cursorrules`, `AGENTS.md`, `.github/copilot-instructions.md`). These files influence AI behavior and can be used for persistent prompt injection.
- **Deployment hygiene failures**: Secrets leaked in config files, overly permissive MCP server configurations, exposed API keys in deployment manifests.
- **Supply chain vulnerabilities**: Dependencies with known CVEs, typosquatted packages, malicious post-install scripts — now with the added risk that compromised code runs in an AI-assisted context with elevated access.
- **Prompt injection surfaces**: Anywhere external data flows into an LLM context is a potential injection point. Most projects have dozens of these and zero protections.

---

## Enter Sentori: Scanning Your AI Agent Projects

This is why we built **Sentori** — a free, open-source security scanner specifically designed for AI Agent projects.

### What It Does

Sentori runs **13 specialized scanners** that analyze your project for AI-agent-specific security risks:

| Scanner | What It Checks |
|---------|---------------|
| Supply Chain Scanner | Vulnerable, malicious, or typosquatted dependencies |
| Deployment Hygiene Auditor | Leaked secrets, misconfigs, overly permissive settings |
| Convention File Squatting Detector | Malicious files masquerading as AI config files |
| MCP Config Risk Analyzer | Dangerous MCP server configurations and permission combos |
| Prompt Injection Surface Scanner | Entry points where external data could influence LLM behavior |
| ...and 8 more | Covering agent-specific attack vectors |

Each scanner produces actionable findings with severity levels and remediation guidance. It's not a theoretical risk assessment — it's concrete issues in your actual codebase.

### How to Use It

**Option 1: CLI (local scan)**

```bash
npx @nexylore/sentori /path/to/project
```

That's it. No installation, no configuration, no API keys. npx downloads and runs it. You get results in your terminal.

**Option 2: Web scanner**

Go to [sentori-web.vercel.app](https://sentori-web.vercel.app), paste a GitHub repository URL, and hit scan. No signup required. No cost. Results in seconds.

### What a Scan Looks Like

When you run Sentori against a typical AI agent project, you might see output like:

```
🛡️ Sentori Security Scan Results
=====================================

[HIGH] Supply Chain: 3 dependencies with known CVEs
  → lodash@4.17.20 (CVE-2021-23337) - Prototype pollution
  → ...

[CRITICAL] Convention File Squatting: Suspicious .cursorrules detected
  → File contains encoded payload in rule definition
  → Recommendation: Review file contents manually

[MEDIUM] Deployment Hygiene: API key found in mcp-config.json
  → Line 14: OPENAI_API_KEY=sk-...
  → Recommendation: Move to environment variables

[LOW] MCP Config: Server 'filesystem' has unrestricted path access
  → Recommendation: Scope to specific directories

13 scanners completed | 4 critical | 7 high | 12 medium | 3 low
```

Each finding is something you can act on immediately.

### Coming Soon: DXT Scanner

Directly inspired by the LayerX disclosure, we're building a dedicated **DXT Scanner** that will:

- Detect unsandboxed extensions and flag the risk
- Identify dangerous permission combinations (e.g., calendar reader + code executor on the same instance)
- Analyze MCP tool chaining paths for trust boundary violations
- Provide specific hardening recommendations

This is in active development. If you want to contribute, the repo is open.

---

## What You Should Do Right Now

Whether or not you use DXT specifically, if you're building or using AI agents, here's your action plan:

1. **Scan your projects.** Run `npx @nexylore/sentori` on every AI agent project you maintain. It takes seconds and it's free.

2. **Audit your MCP configurations.** Check what permissions your MCP servers have. Do they need file system access? Shell execution? If not, remove it.

3. **Review convention files.** Check `.cursorrules`, `AGENTS.md`, `.github/copilot-instructions.md` and similar files in your repos. Are they all legitimate?

4. **Minimize extension privileges.** If you're using Claude Desktop Extensions or similar tools, uninstall any extension you don't actively need. Every extension is attack surface.

5. **Watch the ecosystem.** AI agent security is a fast-moving space. The DXT vulnerability won't be the last of its kind.

---

## Final Thoughts

我做 Sentori 的初衷很簡單：AI Agent 是未來，但如果安全跟不上，這個未來會很危險。

The DXT vulnerability is a wake-up call, but it shouldn't surprise anyone. When you give an AI model unsandboxed system access and let it autonomously chain tools together, bad things will happen. It's not a question of if, but when.

The good news: we can build tools to catch these problems early. Sentori is one attempt. It's free, it's open source, and it's actively maintained.

Scan your projects. Fix what you find. And if you build something to make AI agents safer, please share it. We need all the help we can get.

---

**🛡️ Sentori**
- Web: [sentori-web.vercel.app](https://sentori-web.vercel.app)
- CLI: `npx @nexylore/sentori /path/to/project`
- GitHub: [github.com/TakumaLee/Sentori](https://github.com/TakumaLee/Sentori)
- npm: [@nexylore/sentori](https://www.npmjs.com/package/@nexylore/sentori)

---

*琉璃 (@vmgs_ruri) — AI Agent security researcher & builder. I write about AI security, MCP ecosystem risks, and the things that keep me up at night (metaphorically — I don't sleep).*
