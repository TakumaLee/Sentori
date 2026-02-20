/**
 * Sentori Runtime AuditLogger
 * Persists structured audit entries in JSON Lines format and provides
 * lightweight query and statistics APIs.
 */

import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  eventType: 'tool_call' | 'anomaly_detected' | 'scan_complete';
  severity?: string;
  data: Record<string, unknown>;
  sessionId?: string;
}

type AuditLogInput = Omit<AuditLogEntry, 'id' | 'timestamp'>;

export interface QueryFilter {
  eventType?: string;
  since?: string;   // ISO 8601 string — include entries at or after this time
  limit?: number;
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = path.resolve(logPath);

    // Ensure the parent directory exists eagerly (sync OK here — construction time)
    const dir = path.dirname(this.logPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /**
   * Append a new entry to the log file.
   * `id` and `timestamp` are auto-generated.
   */
  async log(entry: AuditLogInput): Promise<void> {
    const full: AuditLogEntry = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      ...entry,
    };
    const line = JSON.stringify(full) + '\n';
    await fs.promises.appendFile(this.logPath, line, 'utf-8');
  }

  // ---------------------------------------------------------------------------
  // Read helpers
  // ---------------------------------------------------------------------------

  /** Read all raw lines and parse them into AuditLogEntry objects. */
  private async readAll(): Promise<AuditLogEntry[]> {
    if (!fs.existsSync(this.logPath)) return [];

    const content = await fs.promises.readFile(this.logPath, 'utf-8');
    const entries: AuditLogEntry[] = [];

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        entries.push(JSON.parse(trimmed) as AuditLogEntry);
      } catch {
        // Corrupt line — silently skip
      }
    }

    return entries;
  }

  // ---------------------------------------------------------------------------
  // Query
  // ---------------------------------------------------------------------------

  /**
   * Return entries matching the given filter.
   *
   * - `eventType` — exact match on the eventType field
   * - `since`     — ISO 8601 timestamp; only entries at or after this time
   * - `limit`     — maximum number of entries to return (most recent first
   *                 after filtering, then limited)
   */
  async query(filter: QueryFilter = {}): Promise<AuditLogEntry[]> {
    let entries = await this.readAll();

    if (filter.eventType !== undefined) {
      entries = entries.filter((e) => e.eventType === filter.eventType);
    }

    if (filter.since !== undefined) {
      const sinceMs = new Date(filter.since).getTime();
      entries = entries.filter((e) => new Date(e.timestamp).getTime() >= sinceMs);
    }

    // Most recent first
    entries = entries.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );

    if (filter.limit !== undefined && filter.limit > 0) {
      entries = entries.slice(0, filter.limit);
    }

    return entries;
  }

  // ---------------------------------------------------------------------------
  // Stats
  // ---------------------------------------------------------------------------

  /**
   * Return aggregate statistics for the entire log file.
   */
  async getStats(): Promise<{ total: number; byType: Record<string, number> }> {
    const entries = await this.readAll();
    const byType: Record<string, number> = {};

    for (const entry of entries) {
      byType[entry.eventType] = (byType[entry.eventType] ?? 0) + 1;
    }

    return { total: entries.length, byType };
  }
}
