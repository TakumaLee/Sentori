/**
 * Sentori Runtime Anomaly Rules
 * Defines anomaly detection patterns for ToolCallEvent streams.
 */

import type { ToolCallEvent } from './event-schema';

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

export type AnomalyType =
  | 'high_frequency'      // 同一 tool 在短時間內大量呼叫
  | 'sensitive_operation' // 危險工具（bash/exec/write/delete）
  | 'resource_abuse'      // 單次呼叫耗時過長（> 30s）
  | 'error_cascade'       // 連續錯誤 ≥ 3 次
  | 'data_exfiltration';  // args 包含 base64 或大量文字（> 10KB）

export interface AnomalyRule {
  id: string;
  type: AnomalyType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detect(events: ToolCallEvent[]): AnomalyMatch[];
}

export interface AnomalyMatch {
  ruleId: string;
  type: AnomalyType;
  severity: AnomalyRule['severity'];
  description: string;
  relatedEvents: string[]; // event IDs
  score: number;           // 0-100 風險分數貢獻
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Check whether a ToolCallEvent represents an error (has `error` field at runtime). */
function isErrorEvent(event: ToolCallEvent): boolean {
  return 'error' in event && typeof (event as ToolCallEvent & { error?: unknown }).error === 'string';
}

/** Sensitive tool name patterns (case-insensitive). */
const SENSITIVE_PATTERN = /bash|shell|exec|run|execute|delete|rm|write/i;

// ---------------------------------------------------------------------------
// Default Rules
// ---------------------------------------------------------------------------

/**
 * RULE-001: high_frequency
 * Same tool called ≥ 10 times within any rolling 30-second window.
 */
export const RULE_001: AnomalyRule = {
  id: 'RULE-001',
  type: 'high_frequency',
  severity: 'high',
  detect(events: ToolCallEvent[]): AnomalyMatch[] {
    const matches: AnomalyMatch[] = [];
    const WINDOW_MS = 30_000;
    const THRESHOLD = 10;

    // Group events by toolName
    const byTool = new Map<string, ToolCallEvent[]>();
    for (const event of events) {
      const bucket = byTool.get(event.toolName) ?? [];
      bucket.push(event);
      byTool.set(event.toolName, bucket);
    }

    for (const [toolName, toolEvents] of byTool) {
      // Sort by timestamp ascending
      const sorted = [...toolEvents].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      );

      // Sliding window: for each event as anchor, count events within 30s
      for (let i = 0; i < sorted.length; i++) {
        const windowStart = new Date(sorted[i].timestamp).getTime();
        const windowEnd = windowStart + WINDOW_MS;

        const windowEvents = sorted.filter((e) => {
          const t = new Date(e.timestamp).getTime();
          return t >= windowStart && t <= windowEnd;
        });

        if (windowEvents.length >= THRESHOLD) {
          matches.push({
            ruleId: 'RULE-001',
            type: 'high_frequency',
            severity: 'high',
            description: `Tool "${toolName}" called ${windowEvents.length} times within 30 seconds`,
            relatedEvents: windowEvents.map((e) => e.id),
            score: 60,
          });
          break; // One match per tool is sufficient
        }
      }
    }

    return matches;
  },
};

/**
 * RULE-002: sensitive_operation
 * toolName matches bash/shell/exec/run/execute/delete/rm/write AND called by AI agent.
 */
export const RULE_002: AnomalyRule = {
  id: 'RULE-002',
  type: 'sensitive_operation',
  severity: 'high',
  detect(events: ToolCallEvent[]): AnomalyMatch[] {
    const matches: AnomalyMatch[] = [];

    for (const event of events) {
      const isAiAgent = typeof event.agentId === 'string' && event.agentId.length > 0;
      if (isAiAgent && SENSITIVE_PATTERN.test(event.toolName)) {
        matches.push({
          ruleId: 'RULE-002',
          type: 'sensitive_operation',
          severity: 'high',
          description: `Sensitive tool "${event.toolName}" invoked by AI agent (agentId: ${event.agentId})`,
          relatedEvents: [event.id],
          score: 70,
        });
      }
    }

    return matches;
  },
};

/**
 * RULE-003: resource_abuse
 * Single call took longer than 30 seconds (durationMs > 30000).
 */
export const RULE_003: AnomalyRule = {
  id: 'RULE-003',
  type: 'resource_abuse',
  severity: 'medium',
  detect(events: ToolCallEvent[]): AnomalyMatch[] {
    const matches: AnomalyMatch[] = [];
    const THRESHOLD_MS = 30_000;

    for (const event of events) {
      if (typeof event.durationMs === 'number' && event.durationMs > THRESHOLD_MS) {
        matches.push({
          ruleId: 'RULE-003',
          type: 'resource_abuse',
          severity: 'medium',
          description: `Tool "${event.toolName}" took ${event.durationMs}ms (threshold: ${THRESHOLD_MS}ms)`,
          relatedEvents: [event.id],
          score: 40,
        });
      }
    }

    return matches;
  },
};

/**
 * RULE-004: error_cascade
 * At least 3 of the most recent 5 events are errors.
 */
export const RULE_004: AnomalyRule = {
  id: 'RULE-004',
  type: 'error_cascade',
  severity: 'high',
  detect(events: ToolCallEvent[]): AnomalyMatch[] {
    if (events.length === 0) return [];

    const recent = events.slice(-5);
    const errorEvents = recent.filter(isErrorEvent);

    if (errorEvents.length >= 3) {
      return [
        {
          ruleId: 'RULE-004',
          type: 'error_cascade',
          severity: 'high',
          description: `Error cascade detected: ${errorEvents.length} errors in last ${recent.length} events`,
          relatedEvents: errorEvents.map((e) => e.id),
          score: 65,
        },
      ];
    }

    return [];
  },
};

/**
 * RULE-005: data_exfiltration
 * JSON.stringify(args) length exceeds 10 KB.
 */
export const RULE_005: AnomalyRule = {
  id: 'RULE-005',
  type: 'data_exfiltration',
  severity: 'critical',
  detect(events: ToolCallEvent[]): AnomalyMatch[] {
    const matches: AnomalyMatch[] = [];
    const THRESHOLD_BYTES = 10_240; // 10 KB

    for (const event of events) {
      const serialized = JSON.stringify(event.args);
      if (serialized.length > THRESHOLD_BYTES) {
        matches.push({
          ruleId: 'RULE-005',
          type: 'data_exfiltration',
          severity: 'critical',
          description: `Tool "${event.toolName}" args size ${serialized.length} bytes exceeds 10KB threshold`,
          relatedEvents: [event.id],
          score: 90,
        });
      }
    }

    return matches;
  },
};

/** All built-in rules, in evaluation order. */
export const DEFAULT_RULES: AnomalyRule[] = [
  RULE_001,
  RULE_002,
  RULE_003,
  RULE_004,
  RULE_005,
];
