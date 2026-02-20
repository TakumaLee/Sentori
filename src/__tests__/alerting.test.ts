/**
 * Tests for Sentori AlertManager + AuditLogger
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { AlertManager } from '../runtime/alerting';
import { AuditLogger } from '../runtime/audit-log';
import type { AlertConfig } from '../runtime/alerting';
import type { AnomalyMatch } from '../runtime/anomaly-rules';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal AnomalyMatch fixture. */
function makeMatch(
  severity: AnomalyMatch['severity'] = 'high',
  overrides: Partial<AnomalyMatch> = {},
): AnomalyMatch {
  return {
    ruleId: 'RULE-001',
    type: 'high_frequency',
    severity,
    description: `Test anomaly (${severity})`,
    relatedEvents: ['evt-0001', 'evt-0002'],
    score: 60,
    ...overrides,
  };
}

/** Create a temp directory and return its path. Auto-cleaned after test. */
function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sentori-test-'));
}

// ---------------------------------------------------------------------------
// 1. Console channel
// ---------------------------------------------------------------------------

describe('AlertManager — console channel', () => {
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('writes a formatted alert to stderr for a high-severity match', async () => {
    const manager = new AlertManager([{ channel: 'console' }]);
    const match = makeMatch('high');

    await manager.sendAlert(match, { toolName: 'bash', sessionId: 'ses-123' });

    expect(stderrSpy).toHaveBeenCalled();
    const output = (stderrSpy.mock.calls as Array<[string]>)
      .map(([s]) => s)
      .join('');

    expect(output).toContain('SENTORI ALERT');
    expect(output).toContain('RULE-001');
    expect(output).toContain('HIGH');
    expect(output).toContain('bash');
    expect(output).toContain('ses-123');
  });

  it('includes critical emoji for critical severity', async () => {
    const manager = new AlertManager([{ channel: 'console' }]);
    await manager.sendAlert(makeMatch('critical'));

    const output = (stderrSpy.mock.calls as Array<[string]>)
      .map(([s]) => s)
      .join('');
    expect(output).toContain('🔴');
  });

  it('includes medium emoji for medium severity', async () => {
    const manager = new AlertManager([{ channel: 'console' }]);
    await manager.sendAlert(makeMatch('medium'));

    const output = (stderrSpy.mock.calls as Array<[string]>)
      .map(([s]) => s)
      .join('');
    expect(output).toContain('🟡');
  });

  it('does NOT output anything when severity is below minSeverity threshold', async () => {
    const manager = new AlertManager([
      { channel: 'console', minSeverity: 'high' },
    ]);

    await manager.sendAlert(makeMatch('low'));
    await manager.sendAlert(makeMatch('medium'));

    // Nothing should have been written to stderr for these suppressed alerts
    const alertOutput = (stderrSpy.mock.calls as Array<[string]>)
      .map(([s]) => s)
      .join('');
    expect(alertOutput).not.toContain('SENTORI ALERT');
  });
});

// ---------------------------------------------------------------------------
// 2. File channel
// ---------------------------------------------------------------------------

describe('AlertManager — file channel', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('appends a JSON Lines entry to the specified file', async () => {
    const filePath = path.join(tmpDir, 'alerts.jsonl');
    const manager = new AlertManager([{ channel: 'file', filePath }]);

    await manager.sendAlert(makeMatch('high'), { toolName: 'exec' });

    expect(fs.existsSync(filePath)).toBe(true);

    const content = fs.readFileSync(filePath, 'utf-8').trim();
    const lines = content.split('\n').filter(Boolean);
    expect(lines).toHaveLength(1);

    const parsed = JSON.parse(lines[0]);
    expect(parsed.ruleId).toBe('RULE-001');
    expect(parsed.severity).toBe('high');
    expect(parsed.context?.toolName).toBe('exec');
  });

  it('appends multiple lines on successive calls', async () => {
    const filePath = path.join(tmpDir, 'alerts.jsonl');
    const manager = new AlertManager([{ channel: 'file', filePath }]);

    await manager.sendAlert(makeMatch('high'));
    await manager.sendAlert(makeMatch('critical'));
    await manager.sendAlert(makeMatch('medium'));

    const lines = fs
      .readFileSync(filePath, 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean);

    expect(lines).toHaveLength(3);
    const severities = lines.map((l) => (JSON.parse(l) as { severity: string }).severity);
    expect(severities).toEqual(['high', 'critical', 'medium']);
  });

  it('creates intermediate directories if they do not exist', async () => {
    const filePath = path.join(tmpDir, 'nested', 'deep', 'alerts.jsonl');
    const manager = new AlertManager([{ channel: 'file', filePath }]);

    await manager.sendAlert(makeMatch('low'));

    expect(fs.existsSync(filePath)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3. minSeverity filtering (file channel)
// ---------------------------------------------------------------------------

describe('AlertManager — minSeverity filtering', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('only writes entries at or above minSeverity threshold', async () => {
    const filePath = path.join(tmpDir, 'alerts.jsonl');
    const manager = new AlertManager([{ channel: 'file', filePath, minSeverity: 'high' }]);

    await manager.sendAlert(makeMatch('low'));      // suppressed
    await manager.sendAlert(makeMatch('medium'));   // suppressed
    await manager.sendAlert(makeMatch('high'));     // written
    await manager.sendAlert(makeMatch('critical')); // written

    const lines = fs
      .readFileSync(filePath, 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean);

    expect(lines).toHaveLength(2);
    const severities = lines.map((l) => (JSON.parse(l) as { severity: string }).severity);
    expect(severities).toEqual(['high', 'critical']);
  });

  it('passes everything through when minSeverity is "low" (default)', async () => {
    const filePath = path.join(tmpDir, 'alerts.jsonl');
    const manager = new AlertManager([{ channel: 'file', filePath, minSeverity: 'low' }]);

    await manager.sendAlert(makeMatch('low'));
    await manager.sendAlert(makeMatch('medium'));
    await manager.sendAlert(makeMatch('high'));
    await manager.sendAlert(makeMatch('critical'));

    const lines = fs
      .readFileSync(filePath, 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean);

    expect(lines).toHaveLength(4);
  });

  it('passes everything through when minSeverity is omitted', async () => {
    const filePath = path.join(tmpDir, 'alerts.jsonl');
    const manager = new AlertManager([{ channel: 'file', filePath }]);

    await manager.sendAlert(makeMatch('low'));
    await manager.sendAlert(makeMatch('critical'));

    const lines = fs
      .readFileSync(filePath, 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean);

    expect(lines).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// 4. Webhook channel (mocked)
// ---------------------------------------------------------------------------

describe('AlertManager — webhook channel', () => {
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    jest.restoreAllMocks();
  });

  it('calls fetch with POST and JSON body on success', async () => {
    const mockFetch = jest.fn().mockResolvedValue({ ok: true } as Response);
    global.fetch = mockFetch;

    const manager = new AlertManager([
      { channel: 'webhook', webhookUrl: 'https://example.com/hook' },
    ]);

    await manager.sendAlert(makeMatch('critical'));

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://example.com/hook');
    expect(init.method).toBe('POST');

    const body = JSON.parse(init.body as string) as { severity: string };
    expect(body.severity).toBe('critical');
  });

  it('retries once on failure then logs to stderr', async () => {
    jest.useFakeTimers();
    try {
      const mockFetch = jest.fn().mockRejectedValue(new Error('network error'));
      global.fetch = mockFetch;

      const manager = new AlertManager([
        { channel: 'webhook', webhookUrl: 'https://example.com/hook' },
      ]);

      const alertPromise = manager.sendAlert(makeMatch('high'));

      // Run all pending timers and flush async microtasks
      await jest.runAllTimersAsync();
      await alertPromise;

      expect(mockFetch).toHaveBeenCalledTimes(2); // 1 attempt + 1 retry
      const errOutput = (stderrSpy.mock.calls as Array<[string]>)
        .map(([s]) => s)
        .join('');
      expect(errOutput).toContain('Webhook delivery failed');
    } finally {
      jest.useRealTimers();
    }
  });

  it('warns to stderr when webhookUrl is not configured', async () => {
    const manager = new AlertManager([{ channel: 'webhook' }]);

    await manager.sendAlert(makeMatch('high'));

    const errOutput = (stderrSpy.mock.calls as Array<[string]>)
      .map(([s]) => s)
      .join('');
    expect(errOutput).toContain('without webhookUrl');
  });
});

// ---------------------------------------------------------------------------
// 5. AuditLogger — log + query
// ---------------------------------------------------------------------------

describe('AuditLogger — log and query', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    logPath = path.join(tmpDir, 'audit.jsonl');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('generates a unique id and timestamp for each entry', async () => {
    const logger = new AuditLogger(logPath);

    await logger.log({ eventType: 'tool_call', data: { tool: 'bash' } });
    await logger.log({ eventType: 'anomaly_detected', severity: 'high', data: { ruleId: 'RULE-001' } });

    const entries = await logger.query();
    expect(entries).toHaveLength(2);

    const ids = entries.map((e) => e.id);
    expect(ids[0]).not.toBe(ids[1]); // unique UUIDs

    for (const entry of entries) {
      expect(entry.id).toMatch(/^[0-9a-f-]{36}$/); // UUID format
      expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('query with no filter returns all entries (most recent first)', async () => {
    const logger = new AuditLogger(logPath);

    await logger.log({ eventType: 'tool_call', data: {} });
    await logger.log({ eventType: 'scan_complete', data: {} });
    await logger.log({ eventType: 'anomaly_detected', data: {} });

    const entries = await logger.query();
    expect(entries).toHaveLength(3);
    // Should be descending by timestamp
    for (let i = 0; i < entries.length - 1; i++) {
      const a = new Date(entries[i].timestamp).getTime();
      const b = new Date(entries[i + 1].timestamp).getTime();
      expect(a).toBeGreaterThanOrEqual(b);
    }
  });

  it('filters by eventType', async () => {
    const logger = new AuditLogger(logPath);

    await logger.log({ eventType: 'tool_call', data: {} });
    await logger.log({ eventType: 'anomaly_detected', data: {} });
    await logger.log({ eventType: 'tool_call', data: {} });

    const results = await logger.query({ eventType: 'tool_call' });
    expect(results).toHaveLength(2);
    expect(results.every((e) => e.eventType === 'tool_call')).toBe(true);
  });

  it('filters by since timestamp', async () => {
    // Write log lines directly with controlled timestamps to avoid real setTimeout delays
    const oldTs = new Date(Date.now() - 10_000).toISOString();  // 10s ago
    const cutoff = new Date(Date.now() - 1_000).toISOString();  // 1s ago
    const newTs = new Date().toISOString();                       // now

    const oldEntry = {
      id: 'old-id',
      timestamp: oldTs,
      eventType: 'tool_call' as const,
      data: { old: true },
    };
    const newEntry = {
      id: 'new-id',
      timestamp: newTs,
      eventType: 'tool_call' as const,
      data: { recent: true },
    };

    // Write directly to the log file (bypass auto-timestamp to control times)
    await fs.promises.writeFile(
      logPath,
      JSON.stringify(oldEntry) + '\n' + JSON.stringify(newEntry) + '\n',
      'utf-8',
    );

    const logger = new AuditLogger(logPath);
    const results = await logger.query({ since: cutoff });

    expect(results).toHaveLength(1);
    expect((results[0].data as { recent?: boolean }).recent).toBe(true);
  });

  it('respects the limit parameter', async () => {
    const logger = new AuditLogger(logPath);

    for (let i = 0; i < 5; i++) {
      await logger.log({ eventType: 'tool_call', data: { i } });
    }

    const results = await logger.query({ limit: 2 });
    expect(results).toHaveLength(2);
  });

  it('returns empty array when log file does not exist', async () => {
    const logger = new AuditLogger(path.join(tmpDir, 'nonexistent.jsonl'));
    const results = await logger.query();
    expect(results).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 6. AuditLogger — getStats
// ---------------------------------------------------------------------------

describe('AuditLogger — getStats', () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    logPath = path.join(tmpDir, 'audit.jsonl');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns correct total and byType counts', async () => {
    const logger = new AuditLogger(logPath);

    await logger.log({ eventType: 'tool_call', data: {} });
    await logger.log({ eventType: 'tool_call', data: {} });
    await logger.log({ eventType: 'tool_call', data: {} });
    await logger.log({ eventType: 'anomaly_detected', data: {} });
    await logger.log({ eventType: 'scan_complete', data: {} });

    const stats = await logger.getStats();

    expect(stats.total).toBe(5);
    expect(stats.byType['tool_call']).toBe(3);
    expect(stats.byType['anomaly_detected']).toBe(1);
    expect(stats.byType['scan_complete']).toBe(1);
  });

  it('returns zero total and empty byType for an empty / non-existent log', async () => {
    const logger = new AuditLogger(path.join(tmpDir, 'empty.jsonl'));
    const stats = await logger.getStats();

    expect(stats.total).toBe(0);
    expect(stats.byType).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// 7. Multi-channel dispatch
// ---------------------------------------------------------------------------

describe('AlertManager — multiple channels', () => {
  let tmpDir: string;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('dispatches to all configured channels simultaneously', async () => {
    const filePath = path.join(tmpDir, 'alerts.jsonl');
    const configs: AlertConfig[] = [
      { channel: 'console' },
      { channel: 'file', filePath },
    ];

    const manager = new AlertManager(configs);
    await manager.sendAlert(makeMatch('critical'), { sessionId: 'multi-test' });

    // Console was written
    const output = (stderrSpy.mock.calls as Array<[string]>)
      .map(([s]) => s)
      .join('');
    expect(output).toContain('SENTORI ALERT');

    // File was written
    expect(fs.existsSync(filePath)).toBe(true);
    const line = fs.readFileSync(filePath, 'utf-8').trim();
    const parsed = JSON.parse(line) as { context?: { sessionId?: string } };
    expect(parsed.context?.sessionId).toBe('multi-test');
  });
});
