# Sentori - Agentic AI Security 架構設計

> 版本：1.0  
> 更新日期：2026-02-20  
> 作者：琉璃開發團隊

## 概述

Sentori 是一個專為 Agentic AI 系統設計的安全掃描平台，整合 5 個專門的 scanners 來檢測 Model Context Protocol (MCP)、Tool Calling、Workflow、Autonomous Execution 和 Agent Communication 的安全風險。

### 設計目標

- **統一介面**：所有 scanners 遵循統一的輸入/輸出格式
- **可擴展性**：易於新增新的 scanner 或檢測規則
- **即時掃描**：支援 on-demand 和 scheduled 掃描
- **可視化報告**：直觀的 Dashboard 呈現風險儀表板、歷史趨勢
- **API 優先**：所有功能透過 RESTful API 提供

---

## 系統架構圖

```mermaid
graph TB
    subgraph "Client Layer"
        UI[Web Dashboard]
        CLI[CLI Tool]
        API_Client[Third-party API Client]
    end
    
    subgraph "API Gateway"
        Gateway[API Gateway<br/>Authentication & Rate Limiting]
    end
    
    subgraph "Application Layer"
        ScanOrchestrator[Scan Orchestrator]
        ReportGenerator[Report Generator]
        RiskScorer[Risk Scorer]
    end
    
    subgraph "Scanner Layer"
        Scanner1[MCP Server Auditor]
        Scanner2[Workflow Analyzer]
        Scanner3[Execution Risk Scanner]
        Scanner4[Tool Permission Checker]
        Scanner5[Communication Security]
    end
    
    subgraph "Data Layer"
        DB[(PostgreSQL<br/>scan_jobs, scan_results)]
        Cache[(Redis<br/>scan queue, session)]
        Storage[S3/MinIO<br/>uploaded artifacts]
    end
    
    subgraph "Integration Layer"
        Notifier[Notification Service<br/>Slack, Email, Webhook]
        Metrics[Prometheus Metrics]
        Logger[Centralized Logging]
    end
    
    UI --> Gateway
    CLI --> Gateway
    API_Client --> Gateway
    
    Gateway --> ScanOrchestrator
    Gateway --> ReportGenerator
    
    ScanOrchestrator --> Scanner1
    ScanOrchestrator --> Scanner2
    ScanOrchestrator --> Scanner3
    ScanOrchestrator --> Scanner4
    ScanOrchestrator --> Scanner5
    
    Scanner1 --> RiskScorer
    Scanner2 --> RiskScorer
    Scanner3 --> RiskScorer
    Scanner4 --> RiskScorer
    Scanner5 --> RiskScorer
    
    RiskScorer --> DB
    RiskScorer --> ReportGenerator
    
    ReportGenerator --> DB
    ReportGenerator --> Storage
    ReportGenerator --> Notifier
    
    ScanOrchestrator --> Cache
    ScanOrchestrator --> DB
    
    Scanner1 -.logs.-> Logger
    Scanner2 -.logs.-> Logger
    Scanner3 -.logs.-> Logger
    Scanner4 -.logs.-> Logger
    Scanner5 -.logs.-> Logger
    
    ScanOrchestrator -.metrics.-> Metrics
```

---

## Scanner 統一介面

### Scanner 基礎類別

所有 scanners 實作 `BaseScanner` 介面：

```python
from abc import ABC, abstractmethod
from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ScanInput:
    """統一的掃描輸入格式"""
    scan_id: str
    target_type: str  # 'mcp_config', 'workflow_graph', 'tool_registry', etc.
    target_data: Dict[str, Any]  # 實際要掃描的資料
    options: Dict[str, Any] = None  # scanner 特定選項
    
@dataclass
class Finding:
    """單一檢測結果"""
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # 威脅類別
    title: str
    description: str
    evidence: Dict[str, Any]  # 證據資料
    remediation: str  # 修復建議
    references: List[str] = None  # 相關文件連結
    
@dataclass
class ScanOutput:
    """統一的掃描輸出格式"""
    scanner_name: str
    scanner_version: str
    scan_id: str
    timestamp: datetime
    duration_seconds: float
    findings: List[Finding]
    metadata: Dict[str, Any]  # scanner 特定 metadata
    
class BaseScanner(ABC):
    """Scanner 基礎介面"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner 名稱"""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Scanner 版本"""
        pass
    
    @property
    @abstractmethod
    def supported_target_types(self) -> List[str]:
        """支援的目標類型"""
        pass
    
    @abstractmethod
    async def scan(self, input: ScanInput) -> ScanOutput:
        """執行掃描"""
        pass
    
    @abstractmethod
    def validate_input(self, input: ScanInput) -> bool:
        """驗證輸入格式"""
        pass
```

### Scanner 實作範例

```python
class MCPServerAuditor(BaseScanner):
    """MCP Server 安全掃描器"""
    
    @property
    def name(self) -> str:
        return "mcp_server_auditor"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    @property
    def supported_target_types(self) -> List[str]:
        return ["mcp_config", "mcp_server_code"]
    
    async def scan(self, input: ScanInput) -> ScanOutput:
        start_time = datetime.now()
        findings = []
        
        # 執行各項檢測規則
        findings.extend(await self._detect_confused_deputy(input.target_data))
        findings.extend(await self._detect_token_passthrough(input.target_data))
        findings.extend(await self._detect_ssrf_risk(input.target_data))
        findings.extend(await self._audit_config_permissions(input.target_data))
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ScanOutput(
            scanner_name=self.name,
            scanner_version=self.version,
            scan_id=input.scan_id,
            timestamp=datetime.now(),
            duration_seconds=duration,
            findings=findings,
            metadata={
                'total_rules_checked': 4,
                'target_type': input.target_type
            }
        )
    
    def validate_input(self, input: ScanInput) -> bool:
        if input.target_type not in self.supported_target_types:
            return False
        
        # 驗證必要欄位
        required_fields = ['oauth_config', 'server_endpoints']
        return all(field in input.target_data for field in required_fields)
```

---

## 資料流設計

### 掃描流程

```
┌──────────────┐
│ 1. 使用者發起掃描 │
│   POST /api/scans │
└────────┬─────────┘
         │
         ▼
┌──────────────────────┐
│ 2. API Gateway 驗證  │
│   - 檢查 API key     │
│   - Rate limiting    │
└────────┬─────────────┘
         │
         ▼
┌──────────────────────────────┐
│ 3. Scan Orchestrator         │
│   - 建立 scan_job 記錄       │
│   - 將任務放入 Redis queue   │
│   - 回傳 scan_id 給 client   │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ 4. Scanner Workers (並行)    │
│   - 從 queue 取得任務        │
│   - 執行對應的 scanner       │
│   - 產生 findings            │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ 5. Risk Scorer               │
│   - 彙整所有 findings        │
│   - 計算風險分數 (0-100)     │
│   - 分類風險等級             │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ 6. Report Generator          │
│   - 產生 JSON/HTML/PDF 報告  │
│   - 儲存到 S3                │
│   - 更新 scan_job 狀態       │
└────────┬─────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│ 7. Notification Service      │
│   - 發送 Slack/Email 通知    │
│   - Trigger webhook          │
└──────────────────────────────┘
```

### 資料轉換流程

```
輸入資料 (target_data)
    │
    ├─> Scanner 1 ──> Finding[] ─┐
    ├─> Scanner 2 ──> Finding[] ─┤
    ├─> Scanner 3 ──> Finding[] ─┼─> Risk Scorer ──> RiskScore
    ├─> Scanner 4 ──> Finding[] ─┤
    └─> Scanner 5 ──> Finding[] ─┘
                                   │
                                   └──> Report Generator ──> Report (JSON/HTML/PDF)
```

---

## API 設計

### RESTful API Endpoints

#### 1. 掃描管理

```http
POST /api/v1/scans
Content-Type: application/json
Authorization: Bearer <api_key>

Request:
{
  "name": "Production MCP Server Audit",
  "target_type": "mcp_config",
  "target_data": {
    "oauth_config": {...},
    "server_endpoints": [...]
  },
  "scanners": ["mcp_server_auditor", "tool_permission_checker"],
  "options": {
    "severity_threshold": "MEDIUM",
    "include_recommendations": true
  }
}

Response (202 Accepted):
{
  "scan_id": "scan_550e8400-e29b-41d4-a716",
  "status": "queued",
  "created_at": "2026-02-20T01:30:00Z",
  "estimated_duration_seconds": 120
}
```

```http
GET /api/v1/scans/{scan_id}

Response (200 OK):
{
  "scan_id": "scan_550e8400-e29b-41d4-a716",
  "status": "completed",  // queued, running, completed, failed
  "progress": 100,
  "started_at": "2026-02-20T01:30:05Z",
  "completed_at": "2026-02-20T01:32:15Z",
  "duration_seconds": 130,
  "summary": {
    "total_findings": 12,
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 2,
    "risk_score": 78
  },
  "report_url": "https://sentori.nexylore.com/reports/scan_550e8400-e29b-41d4-a716.html"
}
```

```http
GET /api/v1/scans
Query params: ?status=completed&limit=20&offset=0

Response (200 OK):
{
  "scans": [
    {
      "scan_id": "scan_550e8400-e29b-41d4-a716",
      "name": "Production MCP Server Audit",
      "status": "completed",
      "created_at": "2026-02-20T01:30:00Z",
      "risk_score": 78
    },
    ...
  ],
  "total": 145,
  "limit": 20,
  "offset": 0
}
```

```http
DELETE /api/v1/scans/{scan_id}

Response (204 No Content)
```

#### 2. 掃描結果與 Findings

```http
GET /api/v1/scans/{scan_id}/findings
Query params: ?severity=CRITICAL,HIGH&scanner=mcp_server_auditor

Response (200 OK):
{
  "scan_id": "scan_550e8400-e29b-41d4-a716",
  "findings": [
    {
      "finding_id": "finding_abc123",
      "scanner": "mcp_server_auditor",
      "rule_id": "MCP-001",
      "severity": "CRITICAL",
      "category": "Confused Deputy",
      "title": "缺少 per-client consent 機制",
      "description": "MCP proxy server 使用 static client_id 且未實作 per-client consent，可能遭受 Confused Deputy 攻擊",
      "evidence": {
        "config_file": "/etc/mcp/config.json",
        "line": 42,
        "snippet": "\"oauth_client_id_static\": true"
      },
      "remediation": "實作 per-client consent 機制，在轉發到第三方 OAuth 之前顯示 MCP server 自己的同意畫面",
      "references": [
        "https://www.paloaltonetworks.com/resources/guides/simplified-guide-to-model-context-protocol-vulnerabilities"
      ]
    },
    ...
  ],
  "total": 12
}
```

```http
PATCH /api/v1/findings/{finding_id}

Request:
{
  "status": "resolved",  // open, acknowledged, resolved, false_positive
  "assignee": "security@nexylore.com",
  "notes": "已在 v2.1.0 修復"
}

Response (200 OK):
{
  "finding_id": "finding_abc123",
  "status": "resolved",
  "updated_at": "2026-02-20T02:00:00Z"
}
```

#### 3. 報告生成

```http
GET /api/v1/reports/{scan_id}
Accept: application/json | text/html | application/pdf

Response (200 OK):
Content-Type: application/json

{
  "scan_id": "scan_550e8400-e29b-41d4-a716",
  "generated_at": "2026-02-20T01:32:15Z",
  "summary": {...},
  "findings_by_severity": {...},
  "findings_by_scanner": {...},
  "risk_timeline": [...],
  "recommendations": [...]
}
```

```http
POST /api/v1/reports/{scan_id}/export
Content-Type: application/json

Request:
{
  "format": "pdf",  // json, html, pdf, csv
  "include_evidence": true,
  "include_resolved": false
}

Response (200 OK):
{
  "export_url": "https://sentori-storage.s3.amazonaws.com/reports/scan_550e8400.pdf",
  "expires_at": "2026-02-27T01:32:15Z"
}
```

#### 4. Scanner 管理

```http
GET /api/v1/scanners

Response (200 OK):
{
  "scanners": [
    {
      "name": "mcp_server_auditor",
      "version": "1.0.0",
      "description": "檢測 MCP Server 配置與實作的安全漏洞",
      "supported_target_types": ["mcp_config", "mcp_server_code"],
      "rules_count": 4,
      "enabled": true
    },
    ...
  ]
}
```

```http
GET /api/v1/scanners/{scanner_name}/rules

Response (200 OK):
{
  "scanner": "mcp_server_auditor",
  "rules": [
    {
      "rule_id": "MCP-001",
      "name": "Confused Deputy Detection",
      "severity": "CRITICAL",
      "enabled": true,
      "description": "檢查 MCP proxy server 是否存在 confused deputy 漏洞"
    },
    ...
  ]
}
```

#### 5. 統計與儀表板

```http
GET /api/v1/dashboard/stats
Query params: ?time_range=7d

Response (200 OK):
{
  "time_range": "7d",
  "total_scans": 42,
  "avg_risk_score": 65.3,
  "findings_distribution": {
    "critical": 8,
    "high": 23,
    "medium": 45,
    "low": 12
  },
  "top_vulnerabilities": [
    {
      "rule_id": "MCP-001",
      "title": "缺少 per-client consent",
      "occurrences": 12
    },
    ...
  ],
  "risk_trend": [
    {"date": "2026-02-13", "avg_score": 72},
    {"date": "2026-02-14", "avg_score": 68},
    ...
  ]
}
```

---

## 資料結構設計

### Database Schema (PostgreSQL)

```sql
-- 1. 掃描任務表
CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL, -- queued, running, completed, failed, cancelled
    target_type VARCHAR(100) NOT NULL,
    target_data JSONB NOT NULL,
    options JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds FLOAT,
    created_by VARCHAR(255), -- user/api_key
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

-- 2. 掃描結果表
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    scanner_name VARCHAR(100) NOT NULL,
    scanner_version VARCHAR(50) NOT NULL,
    total_findings INT NOT NULL,
    duration_seconds FLOAT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    INDEX idx_scan_id (scan_id),
    INDEX idx_scanner_name (scanner_name)
);

-- 3. 檢測結果 (Findings) 表
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    category VARCHAR(100) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    evidence JSONB NOT NULL,
    remediation TEXT NOT NULL,
    references JSONB, -- array of URLs
    status VARCHAR(50) DEFAULT 'open', -- open, acknowledged, resolved, false_positive
    assignee VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    INDEX idx_scan_id (scan_id),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_rule_id (rule_id)
);

-- 4. 風險分數表
CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    overall_score FLOAT NOT NULL, -- 0-100
    critical_count INT NOT NULL,
    high_count INT NOT NULL,
    medium_count INT NOT NULL,
    low_count INT NOT NULL,
    info_count INT NOT NULL,
    risk_level VARCHAR(20) NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
    calculated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    INDEX idx_scan_id (scan_id),
    INDEX idx_overall_score (overall_score)
);

-- 5. 報告表
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    format VARCHAR(20) NOT NULL, -- json, html, pdf, csv
    storage_path VARCHAR(500) NOT NULL,
    file_size_bytes BIGINT,
    generated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    INDEX idx_scan_id (scan_id)
);

-- 6. Scanner 配置表
CREATE TABLE scanner_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scanner_name VARCHAR(100) NOT NULL UNIQUE,
    version VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    config JSONB, -- scanner-specific config
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- 7. Scanner 規則表
CREATE TABLE scanner_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scanner_name VARCHAR(100) NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(scanner_name, rule_id),
    INDEX idx_scanner_name (scanner_name)
);

-- 8. 用戶/API Keys 表
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(128) NOT NULL UNIQUE, -- bcrypt hash
    name VARCHAR(255) NOT NULL,
    permissions JSONB, -- e.g., ["scans:create", "scans:read"]
    rate_limit_per_hour INT DEFAULT 100,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP,
    last_used_at TIMESTAMP,
    INDEX idx_key_hash (key_hash)
);

-- 9. 掃描歷史統計 (每日彙總)
CREATE TABLE daily_stats (
    date DATE PRIMARY KEY,
    total_scans INT NOT NULL,
    avg_risk_score FLOAT,
    critical_findings INT,
    high_findings INT,
    medium_findings INT,
    low_findings INT,
    unique_rules_triggered INT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
```

### Redis 資料結構

```python
# 1. 掃描任務佇列
scan_queue = "sentori:scan_queue"  # List
# LPUSH sentori:scan_queue '{"scan_id": "...", "scanners": [...]}'

# 2. 掃描狀態快取
scan_status_key = f"sentori:scan:{scan_id}:status"  # String
# SET sentori:scan:{scan_id}:status "running" EX 3600

# 3. Rate Limiting
rate_limit_key = f"sentori:ratelimit:{api_key}:{hour}"  # String
# INCR sentori:ratelimit:{api_key}:2026-02-20-01
# EXPIRE sentori:ratelimit:{api_key}:2026-02-20-01 3600

# 4. Scanner 執行鎖 (避免重複執行)
scan_lock_key = f"sentori:lock:scan:{scan_id}"  # String
# SET sentori:lock:scan:{scan_id} "worker-1" NX EX 300

# 5. 即時 Findings 快取 (供 WebSocket 推送)
findings_key = f"sentori:findings:{scan_id}"  # List
# RPUSH sentori:findings:{scan_id} '{"finding_id": "...", "severity": "CRITICAL"}'
```

---

## UI 架構設計

### 前端技術棧

- **框架**: React 18 + TypeScript
- **狀態管理**: Zustand (輕量化)
- **路由**: React Router v6
- **UI 元件**: Tailwind CSS + shadcn/ui
- **圖表**: Recharts (風險趨勢圖、分佈圖)
- **即時更新**: WebSocket (掃描進度推送)
- **API 呼叫**: TanStack Query (React Query)

### 頁面結構

```
/
├── /dashboard              # 風險儀表板
│   ├── 風險分數卡片 (總分、趨勢)
│   ├── Findings 分佈圖 (圓餅圖)
│   ├── Top 5 漏洞類型
│   └── 最近掃描列表
│
├── /scans                  # 掃描管理
│   ├── /scans/new          # 新增掃描
│   ├── /scans/:id          # 掃描詳情
│   └── /scans/:id/findings # Findings 列表
│
├── /findings               # 全域 Findings 檢視
│   ├── 過濾器 (severity, scanner, status)
│   ├── 分組檢視 (by scanner / by severity)
│   └── Bulk 操作 (批次 resolve/assign)
│
├── /reports                # 報告中心
│   ├── 報告列表
│   ├── /reports/:id        # 報告詳情 (HTML 檢視)
│   └── 匯出功能 (PDF, CSV)
│
├── /scanners               # Scanner 管理
│   ├── Scanner 列表
│   ├── /scanners/:name     # Scanner 詳情
│   └── 規則管理 (啟用/停用)
│
└── /settings               # 設定
    ├── API Keys
    ├── 通知設定 (Slack, Email)
    └── 使用者管理
```

### Dashboard 線框圖

```
┌─────────────────────────────────────────────────────────────────┐
│ Sentori Dashboard                                    [User] ▼   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ 總風險分數    │  │ 本週掃描     │  │ 開放 Findings│         │
│  │     78       │  │     42       │  │     156      │         │
│  │   ▲ +5       │  │   ▼ -3       │  │   ▲ +12      │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                 │
│  ┌───────────────────────────────┐  ┌─────────────────────┐   │
│  │ 風險趨勢 (30 天)               │  │ Findings 分佈       │   │
│  │                               │  │                     │   │
│  │   100 ┤                       │  │  ◉ Critical: 8      │   │
│  │    80 ┤     ╱─╲               │  │  ◉ High: 23         │   │
│  │    60 ┤    ╱   ╲─╮            │  │  ◉ Medium: 45       │   │
│  │    40 ┤───╱       ╰─          │  │  ◉ Low: 12          │   │
│  │       └──────────────          │  │                     │   │
│  └───────────────────────────────┘  └─────────────────────┘   │
│                                                                 │
│  Top Vulnerabilities                                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 1. [MCP-001] 缺少 per-client consent        CRITICAL x12 │  │
│  │ 2. [TOOL-003] 權限過度授予                  HIGH     x8  │  │
│  │ 3. [EXEC-002] 缺少 Human-in-the-Loop        HIGH     x7  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  最近掃描                                         [+ New Scan]  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Production MCP Server  | Completed | 78 | 2h ago        │  │
│  │ Staging Tool Registry  | Running   | -  | 10m ago       │  │
│  │ Dev Workflow Audit     | Completed | 45 | 1d ago        │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 掃描詳情頁面

```
┌─────────────────────────────────────────────────────────────────┐
│ ← Back to Scans                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Production MCP Server Audit                                     │
│ Status: Completed | Risk Score: 78 | Duration: 2m 10s           │
│                                                                 │
│ ┌─ Progress ────────────────────────────────────────────────┐  │
│ │ ████████████████████████████████████████████████ 100%      │  │
│ │ ✓ MCP Server Auditor      (30s)                            │  │
│ │ ✓ Tool Permission Checker (45s)                            │  │
│ │ ✓ Execution Risk Scanner  (25s)                            │  │
│ │ ✓ Workflow Analyzer       (20s)                            │  │
│ │ ✓ Communication Security  (10s)                            │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                 │
│ ┌─ Findings Summary ──────────────────────────────────────┐    │
│ │ Total: 12 | Critical: 2 | High: 5 | Medium: 3 | Low: 2  │    │
│ └──────────────────────────────────────────────────────────┘    │
│                                                                 │
│ ┌─ Critical Findings ───────────────────────────────────────┐  │
│ │ [MCP-001] 缺少 per-client consent 機制                    │  │
│ │   Scanner: MCP Server Auditor                             │  │
│ │   Evidence: /etc/mcp/config.json:42                       │  │
│ │   [View Details] [Mark as Resolved]                       │  │
│ │                                                            │  │
│ │ [SSRF-001] 檢測到內部 IP 的 metadata URL                  │  │
│ │   Scanner: MCP Server Auditor                             │  │
│ │   Evidence: http://169.254.169.254/...                    │  │
│ │   [View Details] [Mark as False Positive]                 │  │
│ └────────────────────────────────────────────────────────────┘  │
│                                                                 │
│ [Export Report ▼] [Re-run Scan] [Schedule Periodic Scan]       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 技術棧選擇

### 後端

| 元件 | 技術 | 理由 |
|------|------|------|
| API 框架 | **FastAPI** (Python 3.11+) | 原生 async 支援、自動 OpenAPI 文件、型別檢查 |
| 任務佇列 | **Celery + Redis** | 成熟的分散式任務執行、支援排程 |
| 資料庫 | **PostgreSQL 15** | JSONB 欄位支援、強大的查詢能力 |
| 快取/佇列 | **Redis 7** | 高效能、支援 pub/sub |
| 物件儲存 | **MinIO** (self-hosted S3) | 開源、S3 相容、適合本地部署 |
| 認證 | **JWT** (PyJWT) | Stateless、易於橫向擴展 |
| ORM | **SQLAlchemy 2.0** | 強大的 async 支援、型別安全 |
| 驗證 | **Pydantic v2** | 高效能資料驗證、與 FastAPI 整合 |

### 前端

| 元件 | 技術 | 理由 |
|------|------|------|
| 框架 | **React 18 + TypeScript** | 成熟生態系、型別安全 |
| 建置工具 | **Vite** | 極快的 HMR、現代化開發體驗 |
| UI 元件 | **Tailwind CSS + shadcn/ui** | 高度客製化、無需額外 bundle size |
| 狀態管理 | **Zustand** | 輕量級、簡單 API |
| API 呼叫 | **TanStack Query** | 自動快取、背景重新整理 |
| 圖表 | **Recharts** | 宣告式、與 React 整合良好 |
| WebSocket | **Socket.IO Client** | 易用、fallback 機制 |

### DevOps

| 元件 | 技術 | 理由 |
|------|------|------|
| 容器化 | **Docker + Docker Compose** | 簡化部署、環境一致性 |
| CI/CD | **GitHub Actions** | 原生整合、免費額度 |
| 監控 | **Prometheus + Grafana** | 開源、豐富的視覺化 |
| 日誌 | **ELK Stack** (Elasticsearch + Logstash + Kibana) | 集中式日誌管理 |
| 反向代理 | **Nginx** | 高效能、SSL 終止 |

---

## 部署架構

### Docker Compose 架構

```yaml
version: '3.8'

services:
  # API Gateway (Nginx)
  nginx:
    image: nginx:1.25
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - api
      - frontend
  
  # API Server (FastAPI)
  api:
    build: ./backend
    environment:
      DATABASE_URL: postgresql://sentori:password@postgres:5432/sentori
      REDIS_URL: redis://redis:6379/0
      S3_ENDPOINT: http://minio:9000
    depends_on:
      - postgres
      - redis
      - minio
    deploy:
      replicas: 3  # 橫向擴展
  
  # Celery Workers (Scanner Execution)
  worker:
    build: ./backend
    command: celery -A sentori.celery worker --loglevel=info
    environment:
      DATABASE_URL: postgresql://sentori:password@postgres:5432/sentori
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - postgres
      - redis
    deploy:
      replicas: 5  # 並行執行多個掃描
  
  # Celery Beat (Scheduled Scans)
  beat:
    build: ./backend
    command: celery -A sentori.celery beat --loglevel=info
    depends_on:
      - redis
  
  # Frontend (React)
  frontend:
    build: ./frontend
    environment:
      VITE_API_URL: https://api.sentori.nexylore.com
  
  # PostgreSQL
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: sentori
      POSTGRES_USER: sentori
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
  
  # Redis
  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
  
  # MinIO (S3-compatible storage)
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: sentori
      MINIO_ROOT_PASSWORD: password
    volumes:
      - minio_data:/data
    ports:
      - "9000:9000"
      - "9001:9001"
  
  # Prometheus (Metrics)
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
  
  # Grafana (Visualization)
  grafana:
    image: grafana/grafana:latest
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"

volumes:
  postgres_data:
  redis_data:
  minio_data:
  prometheus_data:
  grafana_data:
```

---

## 風險評分演算法

### 計算公式

```python
def calculate_risk_score(findings: List[Finding]) -> float:
    """
    計算綜合風險分數 (0-100)
    
    分數計算邏輯:
    - CRITICAL: 20 分/個
    - HIGH: 10 分/個
    - MEDIUM: 5 分/個
    - LOW: 2 分/個
    - INFO: 1 分/個
    
    加權係數:
    - Confused Deputy, SSRF: 1.5x
    - 資料洩漏: 1.3x
    - 權限問題: 1.2x
    """
    severity_weights = {
        'CRITICAL': 20,
        'HIGH': 10,
        'MEDIUM': 5,
        'LOW': 2,
        'INFO': 1
    }
    
    category_multipliers = {
        'Confused Deputy': 1.5,
        'SSRF': 1.5,
        'Data Leakage': 1.3,
        'Excessive Permissions': 1.2,
        'default': 1.0
    }
    
    total_score = 0
    
    for finding in findings:
        base_score = severity_weights.get(finding.severity, 0)
        multiplier = category_multipliers.get(finding.category, 1.0)
        total_score += base_score * multiplier
    
    # 正規化到 0-100（假設 100 分 = 10 個 CRITICAL findings）
    normalized_score = min(total_score / 2, 100)
    
    return round(normalized_score, 1)

def get_risk_level(score: float) -> str:
    """根據分數判斷風險等級"""
    if score >= 80:
        return 'CRITICAL'
    elif score >= 60:
        return 'HIGH'
    elif score >= 40:
        return 'MEDIUM'
    else:
        return 'LOW'
```

---

## 安全性考量

### API 安全

1. **認證機制**
   - JWT tokens (HS256, 1 小時過期)
   - API Keys (stored as bcrypt hash)
   - Rate limiting: 100 requests/hour per API key

2. **授權控制**
   - Role-based permissions: `admin`, `scanner`, `viewer`
   - Resource-level ACL: users can only access their own scans

3. **輸入驗證**
   - Pydantic models 驗證所有 API 輸入
   - 限制檔案上傳大小 (max 50MB)
   - 白名單允許的 `target_type`

### 資料安全

1. **傳輸加密**
   - 強制 HTTPS (TLS 1.3)
   - WebSocket over WSS

2. **儲存加密**
   - Database: 敏感欄位使用 AES-256-GCM 加密
   - S3: Server-side encryption (SSE)

3. **日誌脫敏**
   - 自動 redact API keys, tokens
   - PII 資料不記錄到 logs

---

## 效能優化

### 快取策略

```python
# 1. API Response Cache (Redis)
# GET /api/v1/scans → cache 60 秒
@cache(ttl=60)
async def list_scans():
    ...

# 2. Database Query Cache
# 常用統計資料 cache 10 分鐘
@cache(ttl=600)
async def get_dashboard_stats():
    ...

# 3. Report Cache
# 已生成的報告永久 cache (直到新掃描)
@cache(ttl=-1)  # never expire
async def get_report(scan_id):
    ...
```

### 非同步處理

- **掃描執行**: 所有 scanners 使用 Celery 背景執行，避免阻塞 API
- **Findings 寫入**: 批次寫入 (每 100 個 findings 一次)
- **WebSocket 推送**: 使用 Redis Pub/Sub 廣播進度更新

### 資料庫優化

- **索引策略**: 在 `scan_id`, `severity`, `status`, `created_at` 建立索引
- **分區表**: `findings` 表按月份分區 (避免單表過大)
- **連線池**: SQLAlchemy pool_size=20, max_overflow=10

---

## 監控與告警

### Prometheus Metrics

```python
# 自訂 metrics
from prometheus_client import Counter, Histogram, Gauge

# 掃描執行次數
scans_total = Counter('sentori_scans_total', 'Total number of scans', ['status', 'scanner'])

# 掃描耗時
scan_duration = Histogram('sentori_scan_duration_seconds', 'Scan duration', ['scanner'])

# 當前佇列長度
queue_length = Gauge('sentori_queue_length', 'Number of scans in queue')

# Findings 數量
findings_total = Counter('sentori_findings_total', 'Total findings', ['severity', 'scanner'])
```

### Grafana Dashboard

- **掃描概覽**: 成功率、平均耗時、佇列長度
- **風險趨勢**: 每日平均風險分數、Critical findings 數量
- **Scanner 效能**: 各 scanner 的執行時間、錯誤率
- **API 效能**: 請求量、回應時間、錯誤率

### 告警規則

```yaml
# Prometheus Alertmanager 規則
groups:
  - name: sentori_alerts
    rules:
      - alert: HighRiskScoreDetected
        expr: sentori_avg_risk_score > 80
        for: 5m
        annotations:
          summary: "高風險分數偵測 ({{ $value }})"
        
      - alert: ScanFailureRate
        expr: rate(sentori_scans_total{status="failed"}[5m]) > 0.1
        for: 10m
        annotations:
          summary: "掃描失敗率過高"
      
      - alert: QueueBacklog
        expr: sentori_queue_length > 50
        for: 15m
        annotations:
          summary: "掃描佇列堆積 ({{ $value }} 個任務)"
```

---

## 未來擴展計劃

### Phase 2 功能

1. **AI 輔助修復建議**
   - 使用 LLM 生成具體的 code patch
   - 自動產生 PR 到 GitHub

2. **Policy as Code**
   - 允許用戶定義自訂檢測規則 (YAML/Python)
   - 規則市場 (community-contributed rules)

3. **CI/CD 整合**
   - GitHub Actions plugin
   - GitLab CI/CD template
   - 在 PR 時自動執行掃描，block merge if risk > threshold

4. **Multi-tenant SaaS 版本**
   - 組織管理、團隊權限
   - Usage-based pricing
   - White-label 選項

### 技術債管理

- **測試覆蓋率目標**: 80% (unit tests + integration tests)
- **文件維護**: 每次新增 scanner 必須更新架構文件
- **效能基準**: 每次 release 前執行 load testing (1000 concurrent scans)

---

## 總結

本架構設計提供了一個可擴展、高效能的 Agentic AI 安全掃描平台：

### 核心優勢

✅ **統一介面**: 所有 scanners 遵循相同的 `BaseScanner` 介面，易於擴展  
✅ **非同步執行**: Celery + Redis 支援大規模並行掃描  
✅ **豐富 API**: RESTful API 涵蓋掃描、報告、統計等所有功能  
✅ **直觀 UI**: React + Tailwind 提供現代化的使用者體驗  
✅ **完整監控**: Prometheus + Grafana 提供即時系統健康度  
✅ **安全設計**: JWT 認證、TLS 加密、輸入驗證等多層防護  

### 技術亮點

- **模組化設計**: Scanner Layer 完全獨立，可單獨測試與部署
- **容器化部署**: Docker Compose 一鍵啟動所有服務
- **可水平擴展**: API 與 Worker 皆可透過調整 replicas 擴展
- **資料驅動**: PostgreSQL + Redis 提供強大的查詢與快取能力

---

**文件維護**：本架構文件應隨系統演進持續更新  
**審查週期**：每季度 review 一次架構決策  
**聯絡方式**：architecture@nexylore.com
