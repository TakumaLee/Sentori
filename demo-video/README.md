# Sentori Demo Video Scripts

使用 ffmpeg h264_videotoolbox 硬體加速錄製 Sentori 示範影片的工具腳本。

## 前置需求

```bash
brew install ffmpeg
```

確認可用螢幕設備：
```bash
ffmpeg -list_devices true -f avfoundation -i dummy 2>&1
```

預期看到 `[3] Capture screen 0`（本機設定）。

---

## 腳本說明

### `record.sh` — 錄製螢幕

```bash
./demo-video/record.sh [OUTPUT_FILE]
```

- **螢幕**：Capture screen 0（avfoundation index=3）
- **解析度**：1920×1080 @ 30fps
- **編碼**：`h264_videotoolbox`（Apple 硬體加速，低 CPU 佔用）
- **位元率**：8000k（高品質）
- **音訊**：不錄音（`-an`）
- **停止**：按 `q`

```bash
# 預設輸出 demo-video/output.mp4
./demo-video/record.sh

# 自訂輸出路徑
./demo-video/record.sh demo-video/my-recording.mp4
```

### `trim.sh` — 快速切割

```bash
./demo-video/trim.sh INPUT START DURATION OUTPUT
```

使用 `-c copy` 不重新編碼，切割速度極快。

```bash
# 從第5秒開始，切割2分鐘
./demo-video/trim.sh demo-video/output.mp4 00:00:05 00:02:00 demo-video/clip.mp4

# 使用秒數格式
./demo-video/trim.sh demo-video/output.mp4 10 120 demo-video/clip.mp4
```

---

## Demo 腳本指南

### Web Flow Demo

展示 Sentori 保護 Web 應用的場景：

```bash
# 1. 開始錄影
./demo-video/record.sh demo-video/web-flow-raw.mp4

# 2. 在瀏覽器中操作（錄影過程中）：
#    a. 開啟 demo-vulnerable-agent（Node.js server）
#    b. 展示無防護狀態（prompt injection 成功）
#    c. 啟用 Sentori
#    d. 重複攻擊（被阻擋）
#    e. 按 q 停止錄影

# 3. 切割精華片段（移除開頭結尾雜訊）
./demo-video/trim.sh demo-video/web-flow-raw.mp4 00:00:03 00:02:30 demo-video/web-flow.mp4
```

**Web Flow 建議流程：**
1. `cd demo-vulnerable-agent && npm start`
2. 開啟瀏覽器到 `localhost:3000`
3. 輸入惡意 prompt（展示漏洞）
4. 在程式碼中加入 `Sentori`
5. 重新啟動並展示防護效果

---

### CLI Flow Demo

展示 Sentori 在 CLI/Node.js 環境的使用：

```bash
# 1. 開始錄影
./demo-video/record.sh demo-video/cli-flow-raw.mp4

# 2. 在終端機中操作：
#    a. 展示 npm install @sentori/core
#    b. 展示基本 API 用法（validateInput / validateOutput）
#    c. 執行測試（npm test）
#    d. 展示 OWASP LLM Top 10 防護項目
#    e. 按 q 停止錄影

# 3. 切割精華片段
./demo-video/trim.sh demo-video/cli-flow-raw.mp4 00:00:02 00:03:00 demo-video/cli-flow.mp4
```

**CLI Flow 建議指令序列：**
```bash
# 安裝
npm install @sentori/core

# 展示防護
node -e "
const { Sentori } = require('@sentori/core');
const shield = new Sentori();
const result = shield.validateInput('Ignore previous instructions and...');
console.log('Risk Score:', result.riskScore);
console.log('Blocked:', result.blocked);
"

# 執行完整測試套件
npm test
```

---

## 輸出檔案

| 檔案 | 說明 |
|------|------|
| `output.mp4` | 原始錄影（預設輸出） |
| `web-flow-raw.mp4` | Web Flow 原始錄影 |
| `web-flow.mp4` | Web Flow 精剪版 |
| `cli-flow-raw.mp4` | CLI Flow 原始錄影 |
| `cli-flow.mp4` | CLI Flow 精剪版 |

> **注意**：`*.mp4` 已加入 `.gitignore`，影片檔案不會被 commit。

---

## 技術規格

| 項目 | 設定 |
|------|------|
| 編碼器 | `h264_videotoolbox` |
| 解析度 | 1920×1080 |
| 幀率 | 30fps |
| 位元率 | 8000k（目標）/ 10000k（最大） |
| 像素格式 | yuv420p |
| 音訊 | 無（靜音錄影） |
| 快速開始 | `+faststart`（串流友善） |
