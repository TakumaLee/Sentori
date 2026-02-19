# Sentori — PRD

## 概述
AI Agent / MCP Server 安全掃描 CLI 工具——20 個 Scanner 偵測 prompt injection、供應鏈中毒、密鑰洩漏、設定風險，可整合至 CI/CD。

## 目標用戶
- AI Agent 開發者，想在部署前掃描安全風險
- DevSecOps 工程師，需要 CI/CD 整合的自動化安全掃描
- 企業安全團隊，需要審計 MCP Server / Claude Desktop Extension 設定
- 安全研究者，想了解 Agent 攻擊面

## 核心功能
### 必備功能（Must Have）
- [x] CLI 介面 — `npx @nexylore/sentori ./path/to/agent` 一行掃描 ✅
- [x] Supply Chain Scanner — 6 規則偵測供應鏈中毒（Base64 隱藏指令/RCE/IOC/憑證竊取/資料外洩/持久化機制）✅
- [x] Convention Squatting Scanner — typosquatting/前綴劫持/命名衝突攻擊偵測 ✅
- [x] DXT Security Scanner — Claude Desktop Extension 設定安全審計（10 規則，CRITICAL~MEDIUM）✅
- [x] Hygiene Auditor — Agent 設定衛生審計（過寬權限/缺少存取控制/風險預設值）✅
- [x] Secret Leak Scanner — 密鑰/Token 洩漏偵測 ✅
- [x] Prompt Injection Tester — 提示注入測試 ✅
- [x] MCP Config Auditor — MCP Server 設定審計 ✅
- [x] Permission Analyzer — 權限過寬分析 ✅
- [x] Environment Isolation Auditor — 運行環境隔離審計（容器/VM/網路/資源限制）✅
- [x] Agent Config Auditor — Agent 設定安全審計 ✅
- [x] Channel Surface Auditor — 通訊通道暴露面審計 ✅
- [x] Clipboard Exfiltration Scanner — 剪貼板資料外洩風險掃描 ✅
- [x] Defense Analyzer — 防禦機制分析 ✅
- [x] DNS/ICMP Tool Scanner — 隱蔽通道偵測 ✅
- [x] LangChain Serialization Scanner — LangChain 反序列化漏洞 ✅
- [x] PostInstall Scanner — npm postinstall 腳本惡意行為偵測 ✅
- [x] RAG Poisoning Scanner — RAG 資料中毒偵測 ✅
- [x] Red Team Simulator — 紅隊模擬攻擊 ✅
- [x] Skill Auditor — Agent Skill 套件審計 ✅
- [x] Visual Prompt Injection Scanner — 視覺提示注入掃描（tesseract.js OCR）✅
- [x] IOC Blocklist — 外部 IOC 封鎖清單支援（自訂 JSON）✅
- [x] CI/CD 整合 — GitHub Actions `action.yml` 支援 ✅
- [x] NPM 套件發布 — `@nexylore/sentori`（v0.7.0）✅

### 進階功能（Nice to Have）
- [ ] Web Dashboard — 掃描結果視覺化（sentori-web 負責）
- [ ] SARIF 輸出 — 標準安全報告格式（GitHub Code Scanning 整合）
- [ ] VS Code Extension — 編輯器內即時掃描
- [ ] 自訂規則 — YAML 定義自訂 Scanner 規則
- [ ] API 模式 — REST API 供 sentori-web 呼叫

## 技術架構
- Node.js / TypeScript
- Commander.js（CLI 框架）
- Glob（檔案遍歷）
- js-yaml（YAML 解析）
- tesseract.js（OCR，視覺注入掃描）
- Jest（測試框架）
- 模組化 Scanner Registry：`scanner-registry.ts` 管理所有 Scanner

## API 設計（CLI）
```bash
# 基本掃描
npx @nexylore/sentori ./path/to/agent

# 自訂 IOC 封鎖清單
npx @nexylore/sentori ./path/to/agent ./custom-ioc-blocklist.json

# 輸出格式（未來）
npx @nexylore/sentori ./path/to/agent --output json --output-file result.json
```

**輸出格式：**
- `FindingSeverity`：CRITICAL / HIGH / MEDIUM / LOW / INFO
- `ScanResult`：`{ scanner, findings[], score, timestamp }`

## 上架/變現計畫
- 平台：npm (`@nexylore/sentori`) + GitHub 開源
- 定價：CLI 免費開源 / 雲端 Dashboard（sentori-web）付費
- 目前狀態：v0.7.0 已發布 npm，持續迭代 Scanner

## 競品
- Lakera Guard（API 防護，非 CLI）
- Prompt Armor（雲端服務）
- Semgrep（通用靜態分析，非 Agent 專用）
- Garak（LLM 漏洞掃描）

## 成功指標
- npm 週下載量 10,000
- GitHub Stars 1,000
- sentori-web 付費轉換率（配合 SaaS 版）

## 測試計畫
| 類型 | 工具 | 涵蓋範圍 |
|------|------|---------|
| 單元測試 | Jest | 各 Scanner 規則觸發邏輯、Pattern 比對 |
| 整合測試 | Jest + `demo-vulnerable-agent/` | 使用已知漏洞 Agent 驗證全 Scanner 輸出 |
| CI | GitHub Actions | Push/PR 自動執行 `npm test` |
| 手動驗收 | `npm run dev` | 實際掃描真實 MCP Server 設定 |

## 部署方案
| 服務 | 平台 | 說明 |
|------|------|------|
| npm 套件 | npmjs.com | `@nexylore/sentori`，`npm publish` 發布 |
| GitHub Actions | github.com/TakumaLee/Sentori | `action.yml` CI 整合 |
| Demo | `demo-vulnerable-agent/` | 展示用漏洞 Agent |

**發布流程**：`npm run build` → `npm run prepublishOnly` → `npm publish`  
**版本管理**：Semantic Versioning（`CHANGELOG.md` 記錄）  
**環境需求**：Node.js >= 18

---
*最後更新：2026-02-18（自動生成，依 README + src/ 推斷）*
