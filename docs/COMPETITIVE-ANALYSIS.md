# Sentori 競品分析（2026-02-04）

## 市場概況
- CyberArk：AI agent security 已成為 CISO 最大挑戰之一（2026-01）
- KPMG：企業正在 embedding privacy by design + 確保 agent actions 可審計
- Google：預測 2026 AI Agent 從工具進化為數位同事，安全風險同步增加

## 直接競品

### 1. Invariant Labs MCP-Scan
- **定位**：MCP-specific 威脅掃描（tool poisoning、context manipulation、prompt injection）
- **優勢**：專注 MCP、持續更新
- **劣勢**：學習曲線陡、只掃 MCP
- **Sentori 差異**：我們掃 **整個 agent 生態系**（config、secret、defense、channel surface），不只 MCP

### 2. MCPSafetyScanner
- **定位**：Role-based 攻擊模擬 + audit logging
- **優勢**：開源、多角色模擬
- **劣勢**：需技術背景、結果解讀困難
- **Sentori 差異**：我們有 **分數 + 等級系統**，一眼看懂，不需要安全專家解讀

### 3. CyberMCP
- **定位**：14+ 安全工具、自然語言查詢
- **優勢**：整合 Claude/Cursor IDE
- **劣勢**：IDE 綁定、非企業向
- **Sentori 差異**：我們是 **CLI-first**，可整合任何 CI/CD

### 4. Proximity (NOVA)
- **定位**：MCP 靜態分析 + 規則引擎
- **優勢**：開源、幫助 Net Security 報導過
- **劣勢**：只掃 MCP server
- **Sentori 差異**：9 個 scanner 涵蓋更廣，包含 agent config、channel surface

### 5. AI-Infra-Guard
- **定位**：AI 基礎設施安全掃描
- **優勢**：CLI + Web UI、Apache-2.0
- **劣勢**：範圍太廣（不是 agent-specific）
- **Sentori 差異**：我們 **專注 AI Agent**，更精準的 pattern matching

### 6. Salt Security MCP Server
- **定位**：企業級 API 安全延伸到 MCP
- **優勢**：企業級、全面
- **劣勢**：商業產品、價格高
- **Sentori 差異**：免費 CLI + 低價 Pro，**個人開發者和小團隊友善**

## Sentori 獨特賣點（USP）

1. **唯一做 Agent Config Auditing 的** — 掃 gateway bind/auth/allowFrom/port/logging
2. **Channel Surface Auditor** — 偵測 agent 能控制什麼通道（email/twitter/telegram），評估攻擊面
3. **三維度計分系統** — Code Safety + Config Safety + Defense Score，有地板規則
4. **一條指令見結果** — `npx @nexylore/sentori scan .` → 分數 + 等級 + 建議
5. **Context-aware** — test/doc 自動降級、開發密碼不誤判
6. **Dogfooding 驗證** — 用自己掃自己，不斷修 false positive

## 缺口（Phase 2+ 要補的）

1. **Web Dashboard** — 競品多數有 Web UI，我們目前只有 CLI
2. **CI/CD 整合** — GitHub Action / GitLab CI 一鍵掃描
3. **Runtime 監控** — 目前只做靜態掃描，沒有 runtime protection
4. **MCP Server 深度掃描** — tool poisoning、rug pull 偵測（Invariant Labs 的強項）
5. **修復建議 + 自動加固** — 不只告訴你問題，還幫你修

## 定價對比

| 工具 | 定價 |
|------|------|
| MCP-Scan | 免費開源 |
| MCPSafetyScanner | 免費開源 |
| CyberMCP | 免費開源 |
| Salt Security | 企業報價（$$$$） |
| **Sentori** | **免費 CLI + Pro $9/月** |

我們的 sweet spot：**比免費工具更全面，比企業工具便宜 100 倍**。
