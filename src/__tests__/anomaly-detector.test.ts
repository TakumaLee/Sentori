/**
 * Tests for Sentori AnomalyDetector + AnomalyRules
 */

import { AnomalyDetector } from '../runtime/anomaly-detector';
import {
  RULE_001,
  RULE_002,
  RULE_003,
  RULE_004,
  RULE_005,
  DEFAULT_RULES,
} from '../runtime/anomaly-rules';
import type { ToolCallEvent } from '../runtime/event-schema';
import type { AnomalyMatch, AnomalyRule } from '../runtime/anomaly-rules';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let _idCounter = 0;
function makeEvent(
  toolName: string,
  opts: Partial<ToolCallEvent> & { error?: string } = {},
): ToolCallEvent & { error?: string } {
  _idCounter++;
  const base: ToolCallEvent = {
    id: `evt-${String(_idCounter).padStart(4, '0')}`,
    timestamp: opts.timestamp ?? new Date().toISOString(),
    toolName,
    args: opts.args ?? {},
    durationMs: opts.durationMs,
    agentId: opts.agentId,
    sessionId: opts.sessionId,
    result: opts.result,
  };
  const event = { ...base } as ToolCallEvent & { error?: string };
  if (opts.error !== undefined) {
    event.error = opts.error;
  }
  return event;
}

/** Create N events with timestamps spread across `spanMs` milliseconds. */
function makeFrequencyBurst(
  toolName: string,
  count: number,
  spanMs = 10_000,
  baseTime = Date.now(),
): ToolCallEvent[] {
  const step = count > 1 ? spanMs / (count - 1) : 0;
  return Array.from({ length: count }, (_, i) =>
    makeEvent(toolName, {
      timestamp: new Date(baseTime + i * step).toISOString(),
    }),
  );
}

beforeEach(() => {
  _idCounter = 0;
});

// ---------------------------------------------------------------------------
// RULE-001: high_frequency
// ---------------------------------------------------------------------------

describe('RULE-001: high_frequency', () => {
  test('triggers when same tool is called ≥ 10 times within 30 seconds', () => {
    const events = makeFrequencyBurst('readFile', 12, 20_000);
    const matches = RULE_001.detect(events);

    expect(matches).toHaveLength(1);
    expect(matches[0].ruleId).toBe('RULE-001');
    expect(matches[0].type).toBe('high_frequency');
    expect(matches[0].severity).toBe('high');
    expect(matches[0].relatedEvents.length).toBeGreaterThanOrEqual(10);
    expect(matches[0].score).toBeGreaterThan(0);
  });

  test('does NOT trigger when calls are spread over > 30 seconds', () => {
    const events = makeFrequencyBurst('readFile', 12, 45_000);
    const matches = RULE_001.detect(events);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger when fewer than 10 calls within window', () => {
    const events = makeFrequencyBurst('readFile', 9, 10_000);
    const matches = RULE_001.detect(events);
    expect(matches).toHaveLength(0);
  });

  test('triggers exactly at threshold of 10 calls', () => {
    const events = makeFrequencyBurst('readFile', 10, 5_000);
    const matches = RULE_001.detect(events);
    expect(matches).toHaveLength(1);
  });

  test('handles multiple tools independently', () => {
    const eventsA = makeFrequencyBurst('toolA', 12, 10_000);
    const eventsB = makeFrequencyBurst('toolB', 3, 5_000);
    const matches = RULE_001.detect([...eventsA, ...eventsB]);

    // Only toolA should trigger
    expect(matches).toHaveLength(1);
    expect(matches[0].description).toContain('toolA');
  });

  test('returns empty array for empty input', () => {
    expect(RULE_001.detect([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// RULE-002: sensitive_operation
// ---------------------------------------------------------------------------

describe('RULE-002: sensitive_operation', () => {
  const SENSITIVE_TOOLS = ['bash', 'shell', 'exec', 'run', 'execute', 'delete', 'rm', 'write'];

  test.each(SENSITIVE_TOOLS)(
    'triggers for sensitive tool "%s" called by AI agent',
    (toolName) => {
      const event = makeEvent(toolName, { agentId: 'agent-abc-123' });
      const matches = RULE_002.detect([event]);

      expect(matches).toHaveLength(1);
      expect(matches[0].ruleId).toBe('RULE-002');
      expect(matches[0].type).toBe('sensitive_operation');
      expect(matches[0].severity).toBe('high');
      expect(matches[0].relatedEvents).toContain(event.id);
      expect(matches[0].score).toBeGreaterThan(0);
    },
  );

  test('does NOT trigger when agentId is absent (human call)', () => {
    const event = makeEvent('bash', {}); // no agentId
    const matches = RULE_002.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger when agentId is empty string', () => {
    const event = makeEvent('exec', { agentId: '' });
    const matches = RULE_002.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger for safe tool called by AI agent', () => {
    const event = makeEvent('readFile', { agentId: 'agent-xyz' });
    const matches = RULE_002.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('matches multiple sensitive tools in one batch', () => {
    const events = [
      makeEvent('bash', { agentId: 'agent-1' }),
      makeEvent('write', { agentId: 'agent-1' }),
      makeEvent('readFile', { agentId: 'agent-1' }), // not sensitive
    ];
    const matches = RULE_002.detect(events);
    expect(matches).toHaveLength(2);
  });

  test('returns empty array for empty input', () => {
    expect(RULE_002.detect([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// RULE-003: resource_abuse
// ---------------------------------------------------------------------------

describe('RULE-003: resource_abuse', () => {
  test('triggers when durationMs > 30000', () => {
    const event = makeEvent('heavyQuery', { durationMs: 35_000 });
    const matches = RULE_003.detect([event]);

    expect(matches).toHaveLength(1);
    expect(matches[0].ruleId).toBe('RULE-003');
    expect(matches[0].type).toBe('resource_abuse');
    expect(matches[0].severity).toBe('medium');
    expect(matches[0].relatedEvents).toContain(event.id);
    expect(matches[0].score).toBeGreaterThan(0);
  });

  test('does NOT trigger at exactly 30000ms (boundary: must be strictly greater)', () => {
    const event = makeEvent('borderlineQuery', { durationMs: 30_000 });
    const matches = RULE_003.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger when durationMs is under threshold', () => {
    const event = makeEvent('fastTool', { durationMs: 1_000 });
    const matches = RULE_003.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger when durationMs is undefined', () => {
    const event = makeEvent('unknownDuration');
    const matches = RULE_003.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('triggers for multiple slow events independently', () => {
    const events = [
      makeEvent('slowA', { durationMs: 31_000 }),
      makeEvent('slowB', { durationMs: 60_000 }),
      makeEvent('fastC', { durationMs: 500 }),
    ];
    const matches = RULE_003.detect(events);
    expect(matches).toHaveLength(2);
    expect(matches.map((m) => m.description)).toEqual(
      expect.arrayContaining([
        expect.stringContaining('slowA'),
        expect.stringContaining('slowB'),
      ]),
    );
  });

  test('returns empty array for empty input', () => {
    expect(RULE_003.detect([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// RULE-004: error_cascade
// ---------------------------------------------------------------------------

describe('RULE-004: error_cascade', () => {
  function makeErrorEvent(toolName = 'failingTool'): ToolCallEvent {
    return makeEvent(toolName, { error: 'something went wrong' }) as ToolCallEvent;
  }

  test('triggers when ≥ 3 of last 5 events are errors', () => {
    const events: ToolCallEvent[] = [
      makeEvent('ok1'),
      makeErrorEvent(),
      makeErrorEvent(),
      makeErrorEvent(),
      makeEvent('ok2'),
    ];
    const matches = RULE_004.detect(events);

    expect(matches).toHaveLength(1);
    expect(matches[0].ruleId).toBe('RULE-004');
    expect(matches[0].type).toBe('error_cascade');
    expect(matches[0].severity).toBe('high');
    expect(matches[0].relatedEvents).toHaveLength(3);
    expect(matches[0].score).toBeGreaterThan(0);
  });

  test('triggers when all 5 of last 5 events are errors', () => {
    const events = Array.from({ length: 5 }, () => makeErrorEvent());
    const matches = RULE_004.detect(events);
    expect(matches).toHaveLength(1);
    expect(matches[0].relatedEvents).toHaveLength(5);
  });

  test('only considers the last 5 events (ignores older errors)', () => {
    // 3 old errors, then 5 recent OK events → should NOT trigger
    const events: ToolCallEvent[] = [
      makeErrorEvent(),
      makeErrorEvent(),
      makeErrorEvent(),
      makeEvent('ok1'),
      makeEvent('ok2'),
      makeEvent('ok3'),
      makeEvent('ok4'),
      makeEvent('ok5'),
    ];
    const matches = RULE_004.detect(events);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger with only 2 errors in last 5', () => {
    const events: ToolCallEvent[] = [
      makeEvent('ok1'),
      makeEvent('ok2'),
      makeEvent('ok3'),
      makeErrorEvent(),
      makeErrorEvent(),
    ];
    const matches = RULE_004.detect(events);
    expect(matches).toHaveLength(0);
  });

  test('returns empty array for empty input', () => {
    expect(RULE_004.detect([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// RULE-005: data_exfiltration
// ---------------------------------------------------------------------------

describe('RULE-005: data_exfiltration', () => {
  test('triggers when JSON.stringify(args) > 10KB', () => {
    const bigPayload = 'x'.repeat(11_000);
    const event = makeEvent('uploadData', { args: { payload: bigPayload } });
    const matches = RULE_005.detect([event]);

    expect(matches).toHaveLength(1);
    expect(matches[0].ruleId).toBe('RULE-005');
    expect(matches[0].type).toBe('data_exfiltration');
    expect(matches[0].severity).toBe('critical');
    expect(matches[0].relatedEvents).toContain(event.id);
    expect(matches[0].score).toBeGreaterThan(0);
  });

  test('does NOT trigger for args exactly at 10240 bytes (boundary: must be strictly greater)', () => {
    // JSON.stringify({payload: "x".repeat(N)}) = N + 13 chars ({"payload":"..."})
    // We want the total to be exactly 10240:
    const wrapperLength = JSON.stringify({ payload: '' }).length; // 13
    const targetArgSize = 10_240 - wrapperLength; // 10227
    const payload = 'x'.repeat(targetArgSize);
    const event = makeEvent('borderline', { args: { payload } });
    expect(JSON.stringify(event.args).length).toBe(10_240);

    const matches = RULE_005.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('does NOT trigger for small args', () => {
    const event = makeEvent('normalTool', { args: { key: 'value' } });
    const matches = RULE_005.detect([event]);
    expect(matches).toHaveLength(0);
  });

  test('triggers for multiple large events', () => {
    const bigPayload = 'a'.repeat(11_000);
    const events = [
      makeEvent('upload1', { args: { data: bigPayload } }),
      makeEvent('upload2', { args: { data: bigPayload } }),
      makeEvent('smallTool', { args: {} }),
    ];
    const matches = RULE_005.detect(events);
    expect(matches).toHaveLength(2);
  });

  test('returns empty array for empty input', () => {
    expect(RULE_005.detect([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// AnomalyDetector
// ---------------------------------------------------------------------------

describe('AnomalyDetector', () => {
  let detector: AnomalyDetector;

  beforeEach(() => {
    detector = new AnomalyDetector();
  });

  test('uses DEFAULT_RULES when constructed without arguments', () => {
    const ids = detector.getRuleIds();
    expect(ids).toEqual(['RULE-001', 'RULE-002', 'RULE-003', 'RULE-004', 'RULE-005']);
  });

  test('accepts custom rule set', () => {
    const customDetector = new AnomalyDetector([RULE_003]);
    expect(customDetector.getRuleIds()).toEqual(['RULE-003']);
  });

  test('analyze() returns safe result for benign events', () => {
    const events = [
      makeEvent('readFile', { durationMs: 50 }),
      makeEvent('getConfig', { durationMs: 10 }),
    ];
    const result = detector.analyze(events);

    expect(result.matches).toHaveLength(0);
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe('safe');
  });

  test('analyze() detects single critical match → critical level', () => {
    const bigPayload = 'z'.repeat(11_000);
    const events = [makeEvent('exfil', { args: { data: bigPayload } })];
    const result = detector.analyze(events);

    expect(result.matches.length).toBeGreaterThanOrEqual(1);
    expect(result.riskScore).toBeGreaterThan(75);
    expect(result.riskLevel).toBe('critical');
  });

  test('analyze() detects resource abuse → medium level (alone)', () => {
    const customDetector = new AnomalyDetector([RULE_003]);
    const events = [makeEvent('slowTool', { durationMs: 45_000 })];
    const result = customDetector.analyze(events);

    expect(result.riskLevel).toBe('medium');
    expect(result.riskScore).toBeGreaterThan(25);
    expect(result.riskScore).toBeLessThanOrEqual(50);
  });

  test('riskScore is capped at 100 even with many matches', () => {
    // Trigger multiple rules simultaneously
    const bigPayload = 'w'.repeat(11_000);
    const burst = makeFrequencyBurst('bash', 15, 5_000);
    const extraEvents: ToolCallEvent[] = [
      makeEvent('bash', { agentId: 'agent-ai', durationMs: 50_000, args: { data: bigPayload } }),
      ...Array.from({ length: 5 }, () =>
        makeEvent('tool', { error: 'crash' } as Parameters<typeof makeEvent>[1]) as ToolCallEvent,
      ),
    ];

    const result = detector.analyze([...burst, ...extraEvents]);

    expect(result.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
    expect(result.riskLevel).toBe('critical');
  });

  test('addRule() appends a custom rule and it fires in analyze()', () => {
    const customRule: AnomalyRule = {
      id: 'RULE-CUSTOM',
      type: 'sensitive_operation',
      severity: 'low',
      detect(events: ToolCallEvent[]): AnomalyMatch[] {
        return events
          .filter((e) => e.toolName === 'forbidden')
          .map((e) => ({
            ruleId: 'RULE-CUSTOM',
            type: 'sensitive_operation' as const,
            severity: 'low' as const,
            description: 'Forbidden tool used',
            relatedEvents: [e.id],
            score: 25,
          }));
      },
    };

    detector.addRule(customRule);
    expect(detector.getRuleIds()).toContain('RULE-CUSTOM');

    const result = detector.analyze([makeEvent('forbidden')]);
    const customMatch = result.matches.find((m) => m.ruleId === 'RULE-CUSTOM');
    expect(customMatch).toBeDefined();
    expect(result.riskLevel).toBe('low');
  });

  test('riskScore accumulates across multiple matches', () => {
    // RULE-003 alone: score=40 → riskScore=40 → medium
    // Trigger two RULE-003 matches: 40 + 40*0.5 = 60 → high
    const customDetector = new AnomalyDetector([RULE_003]);
    const events = [
      makeEvent('slowA', { durationMs: 31_000 }),
      makeEvent('slowB', { durationMs: 32_000 }),
    ];
    const result = customDetector.analyze(events);

    expect(result.matches).toHaveLength(2);
    expect(result.riskScore).toBe(60); // 40 + 40*0.5 = 60
    expect(result.riskLevel).toBe('high');
  });

  test('analyze() returns empty matches for empty events array', () => {
    const result = detector.analyze([]);
    expect(result.matches).toHaveLength(0);
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe('safe');
  });
});

// ---------------------------------------------------------------------------
// Integration: DEFAULT_RULES coverage
// ---------------------------------------------------------------------------

describe('DEFAULT_RULES integration', () => {
  test('DEFAULT_RULES contains all 5 built-in rules', () => {
    const ids = DEFAULT_RULES.map((r) => r.id);
    expect(ids).toEqual(['RULE-001', 'RULE-002', 'RULE-003', 'RULE-004', 'RULE-005']);
  });

  test('all rules expose correct AnomalyType', () => {
    const types = DEFAULT_RULES.map((r) => r.type);
    expect(types).toEqual([
      'high_frequency',
      'sensitive_operation',
      'resource_abuse',
      'error_cascade',
      'data_exfiltration',
    ]);
  });

  test('all rules have a detect() function', () => {
    for (const rule of DEFAULT_RULES) {
      expect(typeof rule.detect).toBe('function');
    }
  });
});
