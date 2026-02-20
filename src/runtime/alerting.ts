/**
 * Sentori Runtime AlertManager
 * Dispatches anomaly alerts through console / webhook / file channels.
 */

import fs from 'fs';
import path from 'path';
import type { AnomalyMatch } from './anomaly-rules';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AlertChannel = 'console' | 'webhook' | 'file';

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface AlertConfig {
  channel: AlertChannel;
  webhookUrl?: string;   // for webhook channel
  filePath?: string;     // for file channel
  minSeverity?: SeverityLevel;  // filter threshold (default: 'low' = all)
}

// ---------------------------------------------------------------------------
// Severity ordering
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function severityPasses(matchSeverity: string, minSeverity: SeverityLevel = 'low'): boolean {
  const matchRank = SEVERITY_RANK[matchSeverity] ?? 0;
  const minRank = SEVERITY_RANK[minSeverity] ?? 0;
  return matchRank >= minRank;
}

// ---------------------------------------------------------------------------
// Alert payload
// ---------------------------------------------------------------------------

interface AlertPayload {
  alertId: string;
  timestamp: string;
  ruleId: string;
  type: string;
  severity: string;
  description: string;
  relatedEvents: string[];
  score: number;
  context?: {
    toolName?: string;
    sessionId?: string;
  };
}

function buildPayload(
  match: AnomalyMatch,
  context?: { toolName?: string; sessionId?: string },
): AlertPayload {
  return {
    alertId: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    ruleId: match.ruleId,
    type: match.type,
    severity: match.severity,
    description: match.description,
    relatedEvents: match.relatedEvents,
    score: match.score,
    ...(context ? { context } : {}),
  };
}

// ---------------------------------------------------------------------------
// Channel handlers
// ---------------------------------------------------------------------------

function handleConsole(payload: AlertPayload): void {
  const severityEmoji: Record<string, string> = {
    low: '🔵',
    medium: '🟡',
    high: '🟠',
    critical: '🔴',
  };
  const emoji = severityEmoji[payload.severity] ?? '⚪';
  const lines = [
    `${emoji} [SENTORI ALERT] ${payload.timestamp}`,
    `  Rule     : ${payload.ruleId} (${payload.type})`,
    `  Severity : ${payload.severity.toUpperCase()} (score: ${payload.score})`,
    `  Message  : ${payload.description}`,
    `  Events   : ${payload.relatedEvents.join(', ') || '—'}`,
  ];
  if (payload.context?.toolName) {
    lines.push(`  Tool     : ${payload.context.toolName}`);
  }
  if (payload.context?.sessionId) {
    lines.push(`  Session  : ${payload.context.sessionId}`);
  }
  process.stderr.write(lines.join('\n') + '\n');
}

async function handleWebhook(payload: AlertPayload, webhookUrl: string): Promise<void> {
  const body = JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json' };

  const attempt = async (): Promise<void> => {
    const response = await fetch(webhookUrl, { method: 'POST', headers, body });
    if (!response.ok) {
      throw new Error(`Webhook responded with ${response.status}`);
    }
  };

  try {
    await attempt();
  } catch (_firstErr) {
    // Retry once after 500 ms
    await new Promise<void>((resolve) => setTimeout(resolve, 500));
    try {
      await attempt();
    } catch (retryErr) {
      // Log to stderr and continue — alert delivery failure should not crash the runtime
      process.stderr.write(
        `[SENTORI] Webhook delivery failed (${webhookUrl}): ${retryErr instanceof Error ? retryErr.message : String(retryErr)}\n`,
      );
    }
  }
}

async function handleFile(payload: AlertPayload, filePath: string): Promise<void> {
  const resolved = path.resolve(filePath);
  const dir = path.dirname(resolved);

  // Ensure directory exists
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const line = JSON.stringify(payload) + '\n';
  await fs.promises.appendFile(resolved, line, 'utf-8');
}

// ---------------------------------------------------------------------------
// AlertManager
// ---------------------------------------------------------------------------

export class AlertManager {
  private configs: AlertConfig[];

  constructor(configs: AlertConfig[]) {
    this.configs = [...configs];
  }

  /**
   * Send an alert for the given AnomalyMatch through all configured channels,
   * respecting each channel's minSeverity filter.
   */
  async sendAlert(
    match: AnomalyMatch,
    context?: { toolName?: string; sessionId?: string },
  ): Promise<void> {
    const payload = buildPayload(match, context);
    const promises: Promise<void>[] = [];

    for (const config of this.configs) {
      // Apply severity filter
      if (!severityPasses(match.severity, config.minSeverity)) {
        continue;
      }

      switch (config.channel) {
        case 'console':
          handleConsole(payload);
          break;

        case 'webhook':
          if (config.webhookUrl) {
            promises.push(handleWebhook(payload, config.webhookUrl));
          } else {
            process.stderr.write('[SENTORI] Webhook channel configured without webhookUrl — skipped.\n');
          }
          break;

        case 'file':
          if (config.filePath) {
            promises.push(handleFile(payload, config.filePath));
          } else {
            process.stderr.write('[SENTORI] File channel configured without filePath — skipped.\n');
          }
          break;
      }
    }

    // Wait for all async channels (webhook + file) to settle
    await Promise.all(promises);
  }
}
