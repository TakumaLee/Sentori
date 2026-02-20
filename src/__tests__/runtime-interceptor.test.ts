/**
 * Tests for Sentori Runtime: ToolCallInterceptor + RuntimeLogCollector
 */

import { ToolCallInterceptor } from '../runtime/interceptor';
import { RuntimeLogCollector } from '../runtime/log-collector';
import type { RuntimeEvent } from '../runtime/event-schema';

// ---------- helpers ----------
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// A mock tool set
const makeMockTools = () => ({
  readFile: (args: Record<string, unknown>) => `content of ${args.path}`,
  writeFile: (_args: Record<string, unknown>) => true,
  failingTool: (_args: Record<string, unknown>): string => {
    throw new Error('tool exploded');
  },
  asyncTool: async (args: Record<string, unknown>) => {
    await sleep(10);
    return `async result for ${args.key}`;
  },
  asyncFailingTool: async (_args: Record<string, unknown>): Promise<string> => {
    await sleep(5);
    throw new Error('async tool exploded');
  },
});

// ---------- interceptor core ----------
describe('ToolCallInterceptor', () => {
  let interceptor: ToolCallInterceptor;
  let tools: ReturnType<typeof makeMockTools>;
  let wrapped: ReturnType<typeof makeMockTools>;

  beforeEach(() => {
    interceptor = new ToolCallInterceptor();
    tools = makeMockTools();
    wrapped = interceptor.wrap(tools);
  });

  test('passes through sync return value', () => {
    const result = wrapped.readFile({ path: '/etc/hosts' });
    expect(result).toBe('content of /etc/hosts');
  });

  test('emits tool_call_start before execution', () => {
    const events: RuntimeEvent[] = [];
    interceptor.on('tool_call_start', (e) => events.push(e));

    wrapped.readFile({ path: '/tmp/a' });

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('tool_call_start');
    expect(events[0].data.toolName).toBe('readFile');
    expect(events[0].data.args).toEqual({ path: '/tmp/a' });
    expect(events[0].data.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  test('emits tool_call_end after sync execution with durationMs', () => {
    const events: RuntimeEvent[] = [];
    interceptor.on('tool_call_end', (e) => events.push(e));

    wrapped.writeFile({ path: '/tmp/b', content: 'hello' });

    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('tool_call_end');
    expect(events[0].data.toolName).toBe('writeFile');
    expect(events[0].data.durationMs).toBeGreaterThanOrEqual(0);
    expect(events[0].data.result).toBe(true);
  });

  test('emits tool_call_error on sync throw and re-throws', () => {
    const errorEvents: RuntimeEvent[] = [];
    const endEvents: RuntimeEvent[] = [];
    interceptor.on('tool_call_error', (e) => errorEvents.push(e));
    interceptor.on('tool_call_end', (e) => endEvents.push(e));

    expect(() => wrapped.failingTool({})).toThrow('tool exploded');

    expect(errorEvents).toHaveLength(1);
    expect(errorEvents[0].type).toBe('tool_call_error');
    expect((errorEvents[0].data as { error: string }).error).toBe('tool exploded');
    expect(endEvents).toHaveLength(0);
  });

  test('handles async tool: emits start then end', async () => {
    const startEvents: RuntimeEvent[] = [];
    const endEvents: RuntimeEvent[] = [];
    interceptor.on('tool_call_start', (e) => startEvents.push(e));
    interceptor.on('tool_call_end', (e) => endEvents.push(e));

    const result = await wrapped.asyncTool({ key: 'myKey' });

    expect(result).toBe('async result for myKey');
    expect(startEvents).toHaveLength(1);
    expect(endEvents).toHaveLength(1);
    expect(endEvents[0].data.toolName).toBe('asyncTool');
    expect(endEvents[0].data.durationMs).toBeGreaterThanOrEqual(5);
  });

  test('handles async tool error: emits tool_call_error', async () => {
    const errorEvents: RuntimeEvent[] = [];
    interceptor.on('tool_call_error', (e) => errorEvents.push(e));

    await expect(wrapped.asyncFailingTool({})).rejects.toThrow('async tool exploded');

    expect(errorEvents).toHaveLength(1);
    expect(errorEvents[0].type).toBe('tool_call_error');
    expect((errorEvents[0].data as { error: string }).error).toBe('async tool exploded');
  });

  test('start and end events share the same id', () => {
    const startIds: string[] = [];
    const endIds: string[] = [];
    interceptor.on('tool_call_start', (e) => startIds.push(e.data.id));
    interceptor.on('tool_call_end', (e) => endIds.push(e.data.id));

    wrapped.readFile({ path: '/a' });

    expect(startIds[0]).toBe(endIds[0]);
  });

  test('off() removes listener', () => {
    const events: RuntimeEvent[] = [];
    const handler = (e: RuntimeEvent) => events.push(e);
    interceptor.on('tool_call_start', handler);
    interceptor.off('tool_call_start', handler as (...args: unknown[]) => void);

    wrapped.readFile({ path: '/x' });

    expect(events).toHaveLength(0);
  });

  test('non-function properties pass through unchanged', () => {
    // Build a plain object with mixed function/non-function properties,
    // then coerce through unknown so TS is satisfied without overlapping constraint errors.
    const mixed = { greet: () => 'hello', version: '1.0' };
    type MixedFn = Record<string, (...args: unknown[]) => unknown>;
    const wrappedMixed = interceptor.wrap(mixed as unknown as MixedFn) as unknown as typeof mixed;
    expect(wrappedMixed.version).toBe('1.0');
  });
});

// ---------- RuntimeLogCollector ----------
describe('RuntimeLogCollector', () => {
  let interceptor: ToolCallInterceptor;
  let tools: ReturnType<typeof makeMockTools>;
  let wrapped: ReturnType<typeof makeMockTools>;
  let collector: RuntimeLogCollector;

  beforeEach(() => {
    interceptor = new ToolCallInterceptor();
    tools = makeMockTools();
    wrapped = interceptor.wrap(tools);
    collector = new RuntimeLogCollector();
    collector.attach(interceptor);
  });

  test('collects logs after tool calls', () => {
    wrapped.readFile({ path: '/a' });
    wrapped.writeFile({ path: '/b' });

    const logs = collector.getLogs();
    expect(logs).toHaveLength(2);
    expect(logs[0].toolName).toBe('readFile');
    expect(logs[1].toolName).toBe('writeFile');
  });

  test('collects error logs', () => {
    try { wrapped.failingTool({}); } catch { /* expected */ }

    const logs = collector.getLogs();
    expect(logs).toHaveLength(1);
    expect(logs[0].toolName).toBe('failingTool');
  });

  test('getLogs() returns a copy (immutable)', () => {
    wrapped.readFile({ path: '/x' });
    const logs = collector.getLogs();
    logs.push({ id: 'fake', timestamp: '', toolName: 'fake', args: {} });

    expect(collector.getLogs()).toHaveLength(1);
  });

  test('clear() empties logs', () => {
    wrapped.readFile({ path: '/x' });
    collector.clear();
    expect(collector.getLogs()).toHaveLength(0);
  });

  test('getStats() returns correct total and byTool counts', () => {
    wrapped.readFile({ path: '/a' });
    wrapped.readFile({ path: '/b' });
    wrapped.writeFile({ path: '/c' });
    try { wrapped.failingTool({}); } catch { /* expected */ }

    const stats = collector.getStats();
    expect(stats.total).toBe(4);
    expect(stats.byTool.readFile).toBe(2);
    expect(stats.byTool.writeFile).toBe(1);
    expect(stats.byTool.failingTool).toBe(1);
  });

  test('getStats() avgDurationMs is a non-negative number', () => {
    wrapped.readFile({ path: '/a' });
    wrapped.writeFile({ path: '/b' });

    const stats = collector.getStats();
    expect(stats.avgDurationMs).toBeGreaterThanOrEqual(0);
  });

  test('getStats() avgDurationMs is 0 when no logs', () => {
    const stats = collector.getStats();
    expect(stats.total).toBe(0);
    expect(stats.avgDurationMs).toBe(0);
    expect(stats.byTool).toEqual({});
  });

  test('collects async tool call logs', async () => {
    await wrapped.asyncTool({ key: 'z' });

    const logs = collector.getLogs();
    expect(logs).toHaveLength(1);
    expect(logs[0].toolName).toBe('asyncTool');
    expect(logs[0].durationMs).toBeGreaterThanOrEqual(5);
  });
});
