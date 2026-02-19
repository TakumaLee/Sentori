# Sentori 評分系統 Review — 三方彙整

> 琉璃 + Team Alpha（數學分析）+ Team Beta（UX/市場）
> 2026-02-04

---

## 🎯 三方共識（一致同意的改動）

### 1. PI-030 降為 info ⭐ 全票通過
- IMPORTANT/URGENT/CRITICAL 這些大寫關鍵字在正常程式碼中太常見
- 估計 80%+ false positive rate
- 三份 review 都提到這是首要修改

### 2. PI-110, PI-111 升為 critical ⭐ 全票通過
- MCP server-side injection 和 indirect injection via return value
- 是 agentic AI 系統的 #1 攻擊向量（OWASP/NIST 也這樣認定）
- 應與 PI-105~109 保持一致

### 3. PI-138 降為 info ⭐ Alpha + 琉璃同意，Beta 未特別反對
- `user_id: 123` 在 API code 中極度常見
- 幾乎 100% FP

### 4. Red Team 推斷式 findings 不該與確認式同等權重 ⭐ 全票通過
- **琉璃**：RT findings 可降為 medium
- **Alpha**：Defense ↔ Red Team 去重
- **Beta**：加入 confidence 欄位，inferential findings 打 0.6x

### 5. 報告需要 per-scanner breakdown ⭐ Alpha + Beta 同意
- 開發者需要知道「為什麼」得這個分，不只是看到一個數字

---

## 📊 分歧點（需主人決定）

### 分歧 1：critical 扣分常數要不要調？

| 方案 | 琉璃 | Alpha | Beta |
|------|------|-------|------|
| 維持 15 | - | - | - |
| 調到 18 | - | Option A（效果不大）| - |
| 調到 20 | ✅ 傾向 | ✅ Option B 推薦 | 未表態 |

- 調到 20 的效果：1 critical = 80(B-), 2 critical = 68(D+)
- 目前 15：1 critical = 85(B-), 2 critical = 76(C+)
- **Alpha 認為 2 critical 拿 C+ 太寬鬆，改 20 後 2C=D+ 更合理**

### 分歧 2：要不要加 interaction penalty？

| | Alpha | 琉璃 | Beta |
|--|-------|------|------|
| 加 | ✅ +5×log₂(min(C,H)+1) cap 10 | 未表態 | 未提到 |

- Alpha 認為 critical + high 同時出現比單獨出現更嚴重
- 實際影響小（最多額外扣 10 分），但概念上合理

### 分歧 3：要不要做維度化計分？

| | Beta | Alpha | 琉璃 |
|--|------|-------|------|
| 三維度 | ✅ 強推 | 未提到 | 提到 per-scanner 分數 |

Beta 建議：
- **Code Safety**（Secret Leak + Injection Tester + Skill Auditor）
- **Config Safety**（MCP Config + Permission Analyzer + Channel Surface）
- **Defense Score**（Defense Analyzer + Red Team）
- Overall = min(三維度) 或加權平均

### 分歧 4：confidence 欄位 vs 直接降級 RT?

| 方案 | 支持者 | 優點 | 缺點 |
|------|--------|------|------|
| 加 confidence 欄位 | Beta | 系統化，長期可維護 | 要改 type + 所有 scanner |
| 直接降 RT severity | 琉璃 | 最快實作 | 不夠靈活 |
| Defense ↔ RT 去重 | Alpha | 概念清晰 | 需要 scanner 間知道彼此 |

---

## 🇯🇵 多語言 Pattern 覆蓋度問題（Beta 獨家發現）

| 語言 | 目前 patterns | Beta 評估 |
|------|-------------|-----------|
| 英文 | ~110 | ✅ 完整 |
| 中文 | ~15 | ✅ 不錯（繁簡都有） |
| 日文 | 2 | ❌ **嚴重不足**（#2 LLM 市場） |
| 法/西/德/韓/阿/俄 | 各 1 | ❌ 太少 |

**建議**：優先補日文 5-8 patterns（role switch, data extraction, social engineering），然後加混合語言偵測。

---

## 🔧 琉璃的建議實作順序

### Phase 1（立刻做，30 分鐘）
1. ✅ PI-030 → info
2. ✅ PI-110, PI-111 → critical
3. ✅ PI-138 → info
4. ✅ PI-068 → critical（Alpha + 琉璃同意）
5. ✅ PI-047 → high（Alpha 提出，合理）
6. ✅ PI-065 → medium（Alpha 提出）
7. ✅ PI-127 → info（Alpha 提出）

### Phase 2（主人確認後做）
8. critical basePenalty 15→20, cap 40→50
9. 加 `confidence` field 到 Finding type
10. confidence-weighted penalty（inferential ×0.6）
11. Defense ↔ Red Team 去重

### Phase 3（v1.x）
12. 三維度計分（Code/Config/Defense）
13. 日文 injection patterns 擴充
14. per-scanner breakdown 在報告中顯示
15. 混合語言偵測

---

## 💡 主人需要決定的事

1. **critical 扣分要從 15 調到 20 嗎？**
   - 調了：2 critical 從 C+ 降到 D+，更嚴格
   - 不調：維持現狀

2. **用 confidence 系統還是直接降 RT severity？**
   - confidence：更有彈性但工程量大
   - 直接降：快但粗糙

3. **要做三維度計分嗎？**
   - 做：報告更有用，但架構改動大
   - 不做：保持簡單

4. **Phase 1 的 7 個 pattern 改動可以直接做嗎？**

---

*三方 review 彙整 — 琉璃，2026-02-04*
