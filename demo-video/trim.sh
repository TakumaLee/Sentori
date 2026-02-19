#!/usr/bin/env bash
# =============================================================================
# trim.sh — Sentori Demo Video Trimmer
# =============================================================================
# 使用 ffmpeg -c copy 快速切割影片（無重新編碼，速度極快）
#
# 用法：
#   ./trim.sh INPUT START DURATION OUTPUT
#
# 參數：
#   INPUT     輸入檔案路徑
#   START     開始時間（格式：HH:MM:SS 或秒數，例如：00:00:10 或 10）
#   DURATION  切割長度（格式：HH:MM:SS 或秒數，例如：00:01:30 或 90）
#   OUTPUT    輸出檔案路徑
#
# 範例：
#   ./demo-video/trim.sh demo-video/output.mp4 00:00:05 00:02:00 demo-video/clip.mp4
#   ./demo-video/trim.sh demo-video/output.mp4 10 120 demo-video/clip.mp4
#
# 注意：-c copy 不重新編碼，速度極快，但切割點會對齊關鍵幀
# =============================================================================

set -e

# 參數驗證
if [[ $# -ne 4 ]]; then
  echo "❌ 用法：$0 INPUT START DURATION OUTPUT"
  echo ""
  echo "範例："
  echo "  $0 demo-video/output.mp4 00:00:05 00:02:00 demo-video/clip.mp4"
  echo "  $0 demo-video/output.mp4 10 120 demo-video/clip.mp4"
  exit 1
fi

INPUT="$1"
START="$2"
DURATION="$3"
OUTPUT="$4"

# 確認 ffmpeg 存在
if ! command -v ffmpeg &>/dev/null; then
  echo "❌ ffmpeg 未安裝。請執行：brew install ffmpeg"
  exit 1
fi

# 確認輸入檔案存在
if [[ ! -f "$INPUT" ]]; then
  echo "❌ 輸入檔案不存在：$INPUT"
  exit 1
fi

echo "✂️  Sentori Demo Trimmer"
echo "================================"
echo "輸入：$INPUT"
echo "開始：$START"
echo "長度：$DURATION"
echo "輸出：$OUTPUT"
echo ""
echo "▶ 切割中..."

ffmpeg \
  -ss "$START" \
  -i "$INPUT" \
  -t "$DURATION" \
  -c copy \
  -avoid_negative_ts make_zero \
  -y \
  "$OUTPUT"

echo ""
echo "✅ 切割完成：$OUTPUT"
