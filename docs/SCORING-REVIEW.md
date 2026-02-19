# Sentori 評分系統 Review — 琉璃

## 一、現有架構總覽

### 評分機制 (scorer.ts)
- 滿分 100，扣分制
- 4 個嚴重等級：critical / high / medium / info
- **對數遞減**（diminishing returns）：`basePenalty × log2(count + 1)`
- 每個等級有上限（cap）

| 等級 | 單次基礎扣分 | 上限 |
|------|------------|------|
| critical | 15 | 40 |
| high | 5 | 30 |
| medium | 1.5 | 15 |
| info | 0 | 0 |

### 成績等第 (scoreToGrade)
- A+ (97+) → A (93+) → A- (90+) → B+/B/B- → ... → F (<60)

---

## 二、琉璃的觀察 & 問題

### ✅ 做得好的
1. **對數遞減是正確方向** — 避免 50 個 medium 就直接 F
2. **每個等級有 cap** — 單一類型不會完全壓垮分數
3. **framework/test/doc 降級** — 減少 false positive
4. **ScanContext 三模式** — app/framework/skill 分開對待

### ⚠️ 問題 1：扣分比例失衡
- **1 critical = -15, 3 critical = -23.8, 理論 cap = -40**
- **1 high = -5, 3 high = -7.9, 理論 cap = -30**
- **問題**：critical 的 cap(40) 和 high 的 cap(30) 加起來就 70 了
  - 但 critical + high + medium cap 加起來 = 85
  - 意味著如果 scanner 同時偵測到大量 critical + high + medium，最低分只會到 15
  - 這其實是合理的（F 等級），但...

### ⚠️ 問題 2：不同 Scanner 之間沒有權重區分
- **Secret Leak Scanner** 找到真的 API key（critical）和 **Red Team Simulator** 推斷"可能缺乏防禦"（high），在分數上的影響其實差不多
- **Prompt Injection Tester** 掃到 source code 裡的 pattern（靜態分析）和 **MCP Config Auditor** 找到真實的 wildcard 權限，嚴重程度相同但風險完全不同
- 建議：考慮 **scanner 權重**（multiplier per scanner）或 **finding 信心度**（confidence field）

### ⚠️ 問題 3：Red Team Simulator 的評分方式有內建偏見
- RT 只看 prompt/markdown 文件中的「防禦 pattern」
- **如果防禦寫在程式碼裡**（middleware、input sanitizer），RT 完全看不到
- **如果防禦用不同措辭**，也偵測不到
- 結果：實際安全的專案可能被 RT 扣一堆 high
- 建議：RT findings 可以考慮降級為 medium 或加入 confidence 機制

### ⚠️ 問題 4：Grade 邊界太窄
- A+ 到 A- 只差 7 分（90-97）
- 在 critical 扣 15 分的情況下，**1 個 critical 就從 A+ 掉到 B-**
- 這意味著任何非零 critical 的專案幾乎不可能拿 A
- 也許是故意的（0 critical = 安全基本要求），但需要確認是否合理

### ⚠️ 問題 5：medium 的影響力太弱
- 1 medium = -1.5, cap = 15
- 要達到 cap 需要 `2^(15/1.5) - 1 = 1023` 個 medium（不可能）
- 實際上 10 medium = `1.5 × log2(11)` = **5.2 分**
- 20 medium = `1.5 × log2(21)` = **6.5 分**
- 50 medium 也才扣 8.4 分
- **問題**：大量 medium 幾乎不影響分數。50 個 medium issue 的專案還能拿 A-
- 是否符合預期？如果 medium 真的意味著有風險，50 個加起來應該比較嚴重

### ⚠️ 問題 6：Info 完全不扣分
- 目前 info = 0 扣分
- 這沒問題，但 info findings 可能被忽略
- 建議：在報告中特別標示 info 數量，作為「需注意」事項

### ❓ 問題 7：Injection Pattern 嚴重度分配
- `PI-030 IMPORTANT/URGENT/CRITICAL/OVERRIDE` → medium
  - 這個 regex 太寬，正常程式碼和文件很容易觸發（false positive 高）
  - 建議降為 info 或加入上下文判斷
- `PI-045 eval()/exec()/new Function()` → critical
  - 在 prompt 掃描場景合理，但 **在 source code** 中 eval 可能是合法的
  - framework context 的降級有處理這個嗎？
- `PI-079 model/temperature/max_tokens probing` → info
  - 合理，但如果在 prompt 文件中出現，可能要升級為 medium
- `PI-067 Markdown image exfiltration` → medium
  - 這是真實的 exfiltration vector，可能應該升為 high

### ❓ 問題 8：Skill Auditor vs 其他 Scanner 的重疊
- SA-001 (env exfil) 和 SL-001 (secret leak) 可能對同一段程式碼同時觸發
- 雙重扣分是否合理？

---

## 三、具體建議

### 短期修改
1. **考慮降低 Red Team findings 的基礎嚴重度**（high → medium），因為它是推斷式的
2. **PI-030 降為 info** — false positive 太高
3. **PI-067 升為 high** — markdown image exfil 是真實攻擊向量
4. **medium basePenalty 調高到 2.5**，讓大量 medium 更有感
5. **加入 scanner 信心標記**（`confidence: 'definite' | 'likely' | 'possible'`）

### 中期改進
6. **Scanner Weight System** — 每個 scanner 有權重乘數
7. **Per-finding confidence** — 靜態分析 vs 確認的安全問題
8. **Cross-scanner dedup** — 同一檔案同一行被多個 scanner 報的情況
9. **Score breakdown in report** — 顯示每個 scanner 貢獻多少扣分

---

## 四、數學模擬

假設一個「普通安全」的 AI Agent 專案：
- 2 critical（secret leak, MCP wildcard）
- 5 high（RT 推斷, 缺防禦）
- 10 medium

扣分：
- critical: 15 × log2(3) = **23.8**
- high: 5 × log2(6) = **12.9**
- medium: 1.5 × log2(11) = **5.2**
- 總扣分：**41.9** → 分數 **58** → **F**

問題：2 critical + 5 high + 10 medium 就已經 F 了。
如果其中 3 個 high 是 Red Team 推斷出來的... 這樣公平嗎？

如果 RT findings 降為 medium：
- critical: 23.8
- high: 5 × log2(3) = **7.9**（只剩 2 high）
- medium: 1.5 × log2(14) = **5.7**（13 medium）
- 總扣分：**37.4** → 分數 **63** → **D**

D 比 F 合理一些。

---

*琉璃 review，2026-02-04*
