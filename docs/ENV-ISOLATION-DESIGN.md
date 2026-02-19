# Environment Isolation Auditor — v0.4.0 設計

> 靈感來源：AI Agent 社群文章（UTM 虛擬機隔離方案）
> 核心觀點：目前掃的都是軟體層，缺少「Agent 跑在什麼環境裡」的檢查

## Scanner 名稱
`EnvironmentIsolationAuditor` — 第 10 個 Scanner

## 檢查項目

### 1. 容器/VM 偵測
- `/.dockerenv` 存在 → Docker
- `/proc/1/cgroup` 包含 docker/lxc → 容器
- `systemd-detect-virt` 或 VM indicators（DMI、hypervisor CPUID）
- macOS: `sysctl kern.hv_vmm_present`
- 沒偵測到任何隔離 → MEDIUM warning + 建議

### 2. 檔案系統權限
- Agent config 檔案（.json, .yaml, .env）是否 world-readable (o+r)
- 敏感檔案（含 key/token）權限應為 600 或 640
- 目錄權限應為 700 或 750
- world-readable 的敏感檔案 → HIGH

### 3. 網路隔離
- 檢查是否有 firewall rules（iptables/nftables/pf）
- Docker: 是否用 `--network=none` 或自定義 bridge
- 無任何 outbound 限制 → MEDIUM（Agent 可以隨便打任何 API）

### 4. 資源限制
- Docker: 檢查 `--memory`, `--cpus` 限制
- cgroup: 檢查 memory.limit_in_bytes, cpu.cfs_quota_us
- ulimit: 檢查 nofile, nproc, memlock
- 無資源限制 → LOW info

### 5. 快照/回滾能力
- Docker: 有 Dockerfile / docker-compose → 可重建
- Git: agent config 有 git 追蹤 → 可回滾
- VM: 偵測 UTM/VirtualBox/VMware snapshot markers
- 純資訊性（INFO），不扣分

### 6. 跨環境共享（Docker 專用）
- `docker inspect` 或 docker-compose.yml 中的 volumes/mounts
- mount 了 `/` 或 `$HOME` → HIGH（等同沒隔離）
- mount 了 `/var/run/docker.sock` → CRITICAL（container escape）
- `--privileged` → CRITICAL

## 評分邏輯

| 情境 | 評分影響 |
|------|---------|
| 裸機 + 無隔離 + config world-readable | 大扣分 |
| 裸機 + 檔案權限正確 | 小扣分 |
| Docker + 有限制 + 無 privileged | 加分 |
| Docker + privileged 或 mount / | 警告（假隔離） |
| VM + 資源限制 + 網路隔離 | 滿分 |

## 實作注意
- 這個 scanner 需要讀系統狀態，不只是掃檔案
- 要處理跨平台（Linux/macOS/Windows）
- 部分檢查需要 root 權限才能完整偵測（無權限時標記 UNKNOWN）
- 靜態分析為主（掃 docker-compose.yml、Dockerfile），動態偵測為輔

## 競品差異化
- 目前沒有任何 agent security tool 在掃運行環境
- 這是 Sentori 獨有的維度
- 配合現有的 9 個 scanner，形成「軟體 + 環境」的完整安全評估
