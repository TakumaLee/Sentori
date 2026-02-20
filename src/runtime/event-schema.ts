/**
 * Sentori Runtime Event Schema
 * Defines types for tool call interception events.
 */

export type ToolCallEvent = {
  id: string;               // UUID
  timestamp: string;        // ISO 8601
  toolName: string;
  args: Record<string, unknown>;
  result?: unknown;
  durationMs?: number;
  agentId?: string;
  sessionId?: string;
};

export type RuntimeEvent =
  | { type: 'tool_call_start'; data: ToolCallEvent }
  | { type: 'tool_call_end'; data: ToolCallEvent }
  | { type: 'tool_call_error'; data: ToolCallEvent & { error: string } };
