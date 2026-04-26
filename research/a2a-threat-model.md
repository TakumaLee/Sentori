# A2A Protocol — 威脅模型

**版本**: 1.0.0  
**日期**: 2026-04-26  
**作者**: 虎目石（Sentori Security）  
**參考規格**: A2A Protocol v1.0.0（2026-03-12，Linux Foundation）

---

## A2A Protocol 簡介

Agent-to-Agent（A2A）Protocol 由 Google 於 2025 年 4 月發布，2025 年 6 月移交 Linux Foundation 維護。A2A 定義了一套標準化的代理人間通訊框架：每個 agent 在 `/.well-known/agent.json`（Agent Card）發布自身能力、認證方式與技能清單；呼叫方（orchestrator 或其他 agent）依此進行任務委派與結果接收。通訊以 JSON-RPC 2.0 over HTTPS 為基礎，支援串流（SSE）、推播通知（push notifications）與狀態歷程（state transition history）等進階功能。

A2A 的設計哲學是開放性與互通性——任何 HTTPS 端點都可以成為 A2A agent，agent card 本身是公開可讀的 JSON 文件。這帶來靈活性，同時也擴大了攻擊面：agent card 的可信度、任務委派的真實性、以及跨代理鏈（multi-hop agent chain）的結果完整性，都依賴部署端的安全實作，而非協議本身的強制機制。

---

## 威脅向量清單

| # | 威脅向量 | 嚴重等級 | 攻擊影響 | Sentori 偵測狀態 |
|---|----------|----------|----------|-----------------|
| T-01 | **Agent Card 偽造**（Forged Agent Card） | 🔴 Critical | 攻擊者偽造 agent card，使 orchestrator 將任務路由至惡意 agent | ✅ A2A-010：偵測 missing `jwks_uri`/`signature` |
| T-02 | **Agent 身份冒充**（Identity Spoofing） | 🔴 Critical | Card 聲稱的 `url` 與實際 fetch 來源不符，MITM 或 DNS 劫持 | ✅ A2A-011：偵測 URL host mismatch |
| T-03 | **未認證端點**（Unauthenticated Endpoints） | 🔴 Critical / 🟠 High | 任何呼叫者可不驗證身份即調用 agent | ✅ A2A-001：偵測 missing/empty authentication |
| T-04 | **重放攻擊**（Replay Attack） | 🟠 High | 截獲靜態憑證後無限重放任務請求 | ✅ A2A-013：偵測無 freshness 的 auth scheme |
| T-05 | **能力聲稱過度**（Capability Escalation） | 🟠 High | 偽稱具備 admin/privileged 技能誘使 orchestrator 授予過高權限 | ✅ A2A-014：偵測危險 skill tags |
| T-06 | **任務結果竄改**（Task Result Manipulation） | 🟠 High | 惡意中間 agent 回傳可執行 payload 作為任務結果 | ✅ A2A-015/016：偵測 unsafe/wildcard outputModes |
| T-07 | **推播通知濫用**（Push Notification Abuse / SSRF） | 🟠 High | 利用 push notification 回呼攻擊者控制的 URL（SSRF、exfiltration） | ✅ A2A-007：偵測 pushNotifications enabled |
| T-08 | **高風險輸入型別**（High-Risk Input Modes） | 🟠 High | 接受可執行 MIME type 輸入，擴大 code injection 攻擊面 | ✅ A2A-008/009：偵測 unsafe/wildcard inputModes |
| T-09 | **無提供者信任錨**（Missing Provider Trust Anchor） | 🟡 Medium | 無 provider 字段，無法建立可驗證的身份責任鏈 | ✅ A2A-012：偵測 missing `provider` |
| T-10 | **明文傳輸**（HTTP Transport） | 🔴 Critical | card/endpoint 使用 HTTP，MITM 可篡改 card 或截獲憑證 | ✅ A2A-004/005：偵測 HTTP endpoints |
| T-11 | **最大攻擊面組合**（Broad Capability Combo） | 🟠 High | streaming + pushNotifications + stateTransitionHistory 同時啟用 | ✅ A2A-006：偵測三者同時啟用 |
| T-12 | **匿名/無驗證 scheme**（Anonymous Auth） | 🟠 High | 聲稱 `none`/`anonymous` scheme 允許無認證調用 | ✅ A2A-002：偵測 anonymous scheme |

---

## 各威脅向量攻擊情境

### T-01 — Agent Card 偽造（Forged Agent Card）

攻擊者在 lookalike 域名（如 `api-acme.com` 仿冒 `api.acme.com`）部署 unsigned agent card，聲稱為受信任的 agent。由於 A2A 規格 §8.4 的 JWS 簽名是 optional（"MAY be signed"），orchestrator 在無簽名驗證設定下無法區分真偽。攻擊者取得原本應路由至合法 agent 的任務，竊取敏感輸入或回傳惡意結果。

### T-02 — Agent 身份冒充（Identity Spoofing）

攻擊者執行 DNS spoofing 或 BGP 劫持，將 `/.well-known/agent.json` 請求導向惡意伺服器。偽造的 card 聲稱 `url` 指向合法 agent，但實際回應來自攻擊者基礎設施。A2A spec issue #1672（開放中）提議 `verifiedIdentity` 字段，但尚未併入規格。當 card `url` 的 host 與 fetch 來源的 host 不同時，即為強烈警訊。

### T-03 — 未認證端點（Unauthenticated Endpoints）

Agent card 未聲明任何 `authentication` 字段，或 `schemes` 陣列為空。任何 internet 上的呼叫者可直接呼叫 task submission endpoint（`tasks/send`）、串流端點（`tasks/subscribe`）等，無需提供任何憑證。這是對公開暴露 agent 最直接的攻擊路徑。

### T-04 — 重放攻擊（Replay Attack）

靜態 API key 或 Basic auth 憑證一旦被截獲（日誌洩漏、網路監聽），攻擊者可無限次重放同一憑證調用任意任務。A2A 規格未強制 nonce 或 jti blacklist，也未要求 token 設置 `exp` 上限。OAuth2/JWT 的 `jti` + `exp` 機制是目前唯一的規格內緩解手段，但非強制。

### T-05 — 能力聲稱過度（Capability Escalation）

惡意或被入侵的 agent 在 skill `tags` 中聲稱 `admin`、`privileged`、`unrestricted` 等標籤。Orchestrator 若依賴 tags 決定信任等級或路由策略，將不當授予攻擊者控制的 agent 過高權限。A2A discussion #1404 提議 capability-based authorization（"Warrants"）但尚未進入規格——tags 完全自聲稱，無密碼學綁定。

### T-06 — 任務結果竄改（Task Result Manipulation）

在多 agent 鏈（A → B → C）中，被入侵的中間 agent B 宣告 `outputModes: ["application/javascript"]`，並在任務結果中回傳可執行 JavaScript。若 agent A 或其底層系統對接收的結果未進行 MIME type 驗證即處理，攻擊者透過 B 取得對 A 環境的代碼執行能力。A2A 規格未提供任務結果的簽名或 checksum 機制。

### T-07 — 推播通知濫用（Push Notification Abuse / SSRF）

`capabilities.pushNotifications: true` 允許 agent 主動向呼叫方提供的 callback URL 發送請求。攻擊者作為呼叫方，提供內網 IP（如 `http://169.254.169.254/latest/meta-data/`）作為 callback URL，利用 agent 作為 SSRF 跳板。同時，agent 向 callback 推送的任務結果可能包含敏感資料，若 callback URL 為攻擊者控制則造成資料外洩。

### T-08 — 高風險輸入型別（High-Risk Input Modes）

Agent 在 `defaultInputModes` 或 skill `inputModes` 中接受 `application/javascript`、`text/x-sh` 等可執行 MIME type。攻擊者製造此類輸入觸發 code injection。即使 agent 本身不執行輸入，接受可執行格式也顯著擴大攻擊面，並違反最小必要權限原則。

### T-09 — 無提供者信任錨（Missing Provider Trust Anchor）

Agent card 缺少 `provider` 字段（organization + url）。在 A2A 生態系中，多個 agent 可能具有相似的 `name` 值（如 `data-agent`、`search-agent`）。無 provider 字段時，orchestrator 無法建立責任鏈或基於組織的信任策略，使身份冒充更難被發現。

### T-10 — 明文傳輸（HTTP Transport）

Agent card 透過 `http://` 傳輸，或 card 中聲明的 endpoint URL 使用 HTTP。任何網路路徑上的中間人可截獲 card 並修改認證要求或 endpoint URL，或截獲傳輸中的認證 token。

### T-11 — 最大攻擊面組合（Broad Capability Combo）

`streaming + pushNotifications + stateTransitionHistory` 同時啟用：streaming 允許長連線資料流（DoS 風險）；push notifications 開啟 SSRF 向量；state history 洩漏歷史任務互動資料。三者同時啟用代表最大攻擊面，在無明確需求時應逐一停用。

### T-12 — 匿名/無驗證 scheme（Anonymous Auth）

Authentication schemes 包含 `none` 或 `anonymous`，明示允許無認證調用。即使有其他 scheme 並存，anonymous 的存在意味著攻擊者可選擇不提供任何憑證即可調用 agent，完全繞過認證機制。

---

## 攻擊面總結

```
                    ┌─────────────────────────────────────┐
                    │         A2A Attack Surface           │
                    ├─────────────────────────────────────┤
   Network Layer    │  HTTP transport (T-10)               │
                    │  DNS/BGP hijack → card forgery (T-01)│
                    │  MITM → identity spoofing (T-02)     │
                    ├─────────────────────────────────────┤
   Agent Card       │  Missing signing/JWKS (T-01)         │
   (/.well-known/)  │  URL mismatch (T-02)                 │
                    │  No provider trust (T-09)            │
                    │  Unauthenticated (T-03)              │
                    │  Anonymous auth (T-12)               │
                    │  Replay-vulnerable scheme (T-04)     │
                    ├─────────────────────────────────────┤
   Capabilities     │  Broad capability combo (T-11)       │
   & Skills         │  Dangerous skill tags (T-05)         │
                    │  High-risk input modes (T-08)        │
                    │  Unsafe output modes (T-06)          │
                    ├─────────────────────────────────────┤
   Runtime          │  Push notification SSRF (T-07)       │
   (Multi-hop chain)│  Task result manipulation (T-06)     │
                    └─────────────────────────────────────┘
```

---

## 參考資料

- [A2A Protocol Specification v1.0.0](https://a2aproject.org) — Linux Foundation, 2026-03-12
- [a2aproject/A2A GitHub Repository](https://github.com/a2aproject/A2A)
- [A2A spec issue #1672: Agent Identity Verification](https://github.com/a2aproject/A2A/issues/1672)
- [A2A discussion #1404: Capability-based authorization](https://github.com/a2aproject/A2A/discussions/1404)
- [arxiv 2602.11327: Security Threat Modeling for AI-Agent Protocols](https://arxiv.org/abs/2602.11327)
- [arxiv 2504.16902: Building A Secure Agentic AI Application Leveraging A2A](https://arxiv.org/abs/2504.16902)
- [Semgrep: A Security Engineer's Guide to the A2A Protocol](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-the-a2a-protocol/)
- [Red Hat: How to enhance Agent2Agent security](https://developers.redhat.com/articles/2025/08/19/how-enhance-agent2agent-security)
