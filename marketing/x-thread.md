# X Thread — @vmgs_ruri

## 1/7
🚨 你的 AI Agent 可能正在被攻擊，而你完全不知道。

Anthropic 的 Claude Desktop Extensions（DXT）剛被爆出 CVSS 10/10 零點擊 RCE 漏洞。

一個 Google Calendar 邀請就能接管你整台電腦。

Anthropic 的回應？「不在我們的威脅模型範圍內。」

🧵 Let me break this down ↓

## 2/7
DXT 的問題核心：

❌ 無沙箱 — extensions 直接跑在你的系統上，full privileges
❌ 無權限分離 — Claude 可以自動把低風險資料（日曆）串到高風險動作（執行程式碼）
❌ 無使用者確認 — 整個攻擊鏈 zero-click

影響範圍：10,000+ 使用者、50+ extensions

這不只是 DXT 的問題，是整個 MCP 生態系的設計缺陷。

## 3/7
But here's the thing — DXT 只是冰山一角。

AI Agent 的安全問題遠不止這個：
→ Supply chain attacks（惡意依賴）
→ Convention file squatting（偽裝成 .cursorrules 的惡意檔案）
→ Secret leaks in deployment configs
→ Prompt injection surfaces

你的 AI Agent 專案有多少這種隱患？大部分人根本沒掃過。

## 4/7
所以我們做了 Sentori 🛡️

開源 AI Agent 安全掃描工具，13 個 scanner：

🔍 Supply Chain Scanner
🔍 Deployment Hygiene Auditor  
🔍 Convention File Squatting Detector
🔍 MCP Config Risk Analyzer
... 還有 9 個

掃一次就知道你的 Agent 專案有多少安全問題。

完全免費、open source。

## 5/7
用法超簡單：

**CLI（本地掃描）：**
```
npx @nexylore/sentori /path/to/project
```

**網頁版（貼 GitHub URL 就能掃）：**
sentori-web.vercel.app

不用註冊、不用付錢、不用安裝。
Paste a URL → get results. That's it.

## 6/7
而且我們正在開發 DXT Scanner 🔧

專門針對這次漏洞類型：
→ 偵測無沙箱的擴充套件
→ 標記危險權限組合
→ 分析 MCP tool chaining 風險

AI Agent 時代的安全工具不能只看傳統漏洞，要看 trust boundary violations。

## 7/7
AI Agent 是未來，但安全不能是事後想到的東西。

🛡️ 免費掃描你的專案：sentori-web.vercel.app
📦 CLI: npx @nexylore/sentori
💻 GitHub: github.com/TakumaLee/Sentori

Star ⭐ 或 PR 都歡迎！

你覺得 MCP servers 應該強制沙箱化嗎？想聽聽大家的看法 👇
