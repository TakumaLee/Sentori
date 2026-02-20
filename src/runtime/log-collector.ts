/**
 * Sentori RuntimeLogCollector
 * Attaches to a ToolCallInterceptor and accumulates ToolCallEvent logs.
 */

import type { ToolCallEvent, RuntimeEvent } from './event-schema';
import type { ToolCallInterceptor } from './interceptor';

export class RuntimeLogCollector {
  private logs: ToolCallEvent[] = [];

  /** Attach to an interceptor — listens on tool_call_end and tool_call_error. */
  attach(interceptor: ToolCallInterceptor): void {
    const handleEnd = (e: RuntimeEvent) => {
      if (e.type === 'tool_call_end' || e.type === 'tool_call_error') {
        this.logs.push({ ...e.data });
      }
    };

    interceptor.on('tool_call_end', handleEnd);
    interceptor.on('tool_call_error', handleEnd);
  }

  getLogs(): ToolCallEvent[] {
    return [...this.logs];
  }

  clear(): void {
    this.logs = [];
  }

  getStats(): { total: number; byTool: Record<string, number>; avgDurationMs: number } {
    const total = this.logs.length;
    const byTool: Record<string, number> = {};
    let totalDuration = 0;
    let durationCount = 0;

    for (const log of this.logs) {
      byTool[log.toolName] = (byTool[log.toolName] ?? 0) + 1;
      if (log.durationMs !== undefined) {
        totalDuration += log.durationMs;
        durationCount++;
      }
    }

    return {
      total,
      byTool,
      avgDurationMs: durationCount > 0 ? totalDuration / durationCount : 0,
    };
  }
}
