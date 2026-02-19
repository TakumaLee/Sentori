#!/usr/bin/env bash
# =============================================================================
# record.sh — Sentori Demo Screen Recorder
# =============================================================================
# 使用 ffmpeg h264_videotoolbox 硬體編碼錄製螢幕
#
# 用法：
#   ./record.sh [OUTPUT_FILE]
#
# 預設輸出：demo-video/output.mp4
# 解析度：1920x1080 @ 30fps
# 編碼：h264_videotoolbox（Apple Silicon/Intel 硬體加速）
# 螢幕：Capture screen 0（index=3）
#
# 停止錄影：按 q 鍵
#
# 範例：
#   ./demo-video/record.sh
#   ./demo-video/record.sh demo-video/my-recording.mp4
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${1:-${SCRIPT_DIR}/output.mp4}"

# 確認 ffmpeg 存在
if ! command -v ffmpeg &>/dev/null; then
  echo "❌ ffmpeg 未安裝。請執行：brew install ffmpeg"
  exit 1
fi

echo "🎬 Sentori Demo Recorder"
echo "================================"
echo "輸出檔案：$OUTPUT"
echo "解析度：1920x1080 @ 30fps"
echo "編碼：h264_videotoolbox（硬體加速）"
echo "螢幕裝置：Capture screen 0（index=3）"
echo ""
echo "▶ 開始錄影... 按 [q] 停止"
echo ""

ffmpeg \
  -f avfoundation \
  -capture_cursor 1 \
  -capture_mouse_clicks 1 \
  -framerate 30 \
  -video_size 1920x1080 \
  -i "3" \
  -vcodec h264_videotoolbox \
  -b:v 8000k \
  -maxrate 10000k \
  -bufsize 16000k \
  -pix_fmt yuv420p \
  -movflags +faststart \
  -an \
  "$OUTPUT"

echo ""
echo "✅ 錄影完成：$OUTPUT"
