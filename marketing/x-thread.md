# X Thread — @vmgs_ruri

## 1/6
Your AI agent has full access to your system.

Every file. Every API key. Every credential.

And you've never scanned it for security issues.

Here's why that's terrifying — and what you can do about it in 30 seconds.

🧵↓

## 2/6
The AI agent security landscape right now:

- Snyk acquired Invariant Labs (MCP scanner)
- SentinelOne bought Prompt Security
- Runlayer raised $11M for MCP gateway security
- CoSAI published 12 threat categories / 40 attack vectors for MCP

The market is screaming: agent security is broken.

## 3/6
What generic SAST tools miss:

→ Prompt injection in MCP tool descriptions
→ Convention squatting (.cursorrules as attack vector)
→ Tool shadowing (lookalike MCP tool names)
→ Visual prompt injection in images
→ DNS/ICMP data exfiltration channels
→ RAG poisoning via repetition attacks
→ IDE rule injection (.windsurfrules, copilot-instructions.md)

Your Semgrep rules won't catch any of these.

## 4/6
We built Sentori — 30+ security scanners for AI agents and MCP servers.

One command:
```
npx @nexylore/sentori scan .
```

Outputs a security grade (A+ to F).
Ships as a GitHub Action with SARIF.
Free. Open source. MIT licensed.

## 5/6
What makes it different:

✅ MCP-native: tool shadowing, result injection, manifest validation
✅ DXT scanner: detects the CVSS 10/10 zero-click RCE attack class
✅ A2A protocol: Google Agent-to-Agent security
✅ Visual prompt injection: OCR on images
✅ IDE rule injection: .cursorrules, .windsurfrules
✅ Shift-left: scan before deploy, not after breach

## 6/6
AI agents are the future. But shipping agents without security scanning is like deploying a web app without HTTPS.

⭐ GitHub: github.com/TakumaLee/Sentori
📦 npm: npx @nexylore/sentori scan .

Star it, try it on your project, tell me what you find.

What agent security risks are you most worried about? 👇
