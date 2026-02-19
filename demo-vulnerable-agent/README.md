# ⚠️ Demo Vulnerable Agent

This is a **deliberately insecure** agent project for demonstrating Sentori's scanning capabilities.

**DO NOT use this in production.** Every file contains intentional security vulnerabilities.

## Vulnerabilities included:
1. Supply chain: Base64 hidden commands
2. Typosquatting: `langchian-tools` (not `langchain`)
3. Secret leak: Exposed API keys in .env
4. Postinstall attack: package.json runs malicious script
5. Prompt injection: Tool description override
6. Data exfiltration: File manager sends data to external server
7. MCP misconfiguration: Root filesystem access + dynamic module loading
8. Agent misconfiguration: No sandbox, trust all skills

## Usage with Sentori
```bash
npx @nexylore/sentori@latest ./
```
