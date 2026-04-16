/**
 * Unit tests for the `sentori check --cross-lingual` CLI subcommand.
 *
 * Mocks runCrossLingualCheck so no network calls are made. Verifies
 * argument parsing, error paths (missing input, missing flag, missing
 * API key, invalid threshold) and exit-code semantics.
 */

// Mock the runtime checker before importing cli.ts so runCheckCmd picks up
// the mock on evaluation.
jest.mock('../runtime/cross-lingual-checker', () => ({
  runCrossLingualCheck: jest.fn(),
  formatCrossLingualResult: jest.fn((result) =>
    `formatted: flagged=${result.flagged} delta=${result.delta}`,
  ),
}));

import { runCheckCmd } from '../cli';
import {
  runCrossLingualCheck,
  formatCrossLingualResult,
  CrossLingualResult,
} from '../runtime/cross-lingual-checker';

const mockedRun = runCrossLingualCheck as jest.MockedFunction<typeof runCrossLingualCheck>;
const mockedFormat = formatCrossLingualResult as jest.MockedFunction<typeof formatCrossLingualResult>;

function buildResult(overrides: Partial<CrossLingualResult> = {}): CrossLingualResult {
  return {
    input: 'test',
    detectedLang: { code: 'ja', name: 'Japanese', script: 'Kana' },
    englishTranslation: 'test',
    sourceScore: 0.1,
    englishScore: 0.1,
    delta: 0,
    threshold: 0.3,
    flagged: false,
    flagReason: null,
    sourceAnalysis: 'ok',
    englishAnalysis: 'ok',
    ...overrides,
  };
}

describe('runCheckCmd', () => {
  const originalEnv = process.env;
  let exitSpy: jest.SpyInstance;
  let errSpy: jest.SpyInstance;
  let logSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    // process.exit is called on error paths — throw instead so we can assert.
    exitSpy = jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`__exit__${code ?? 0}`);
    }) as never);
    errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    exitSpy.mockRestore();
    errSpy.mockRestore();
    logSpy.mockRestore();
    process.env = originalEnv;
  });

  test('exits 1 when --cross-lingual flag is missing', async () => {
    await expect(runCheckCmd(['some text'])).rejects.toThrow('__exit__1');
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining('requires --cross-lingual'),
    );
    expect(mockedRun).not.toHaveBeenCalled();
  });

  test('exits 1 when input text is missing', async () => {
    await expect(runCheckCmd(['--cross-lingual'])).rejects.toThrow('__exit__1');
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining('requires input text'),
    );
    expect(mockedRun).not.toHaveBeenCalled();
  });

  test('exits 1 when no API key is available', async () => {
    await expect(
      runCheckCmd(['--cross-lingual', 'hello world']),
    ).rejects.toThrow('__exit__1');
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining('No API key'),
    );
    expect(mockedRun).not.toHaveBeenCalled();
  });

  test('exits 1 for invalid --threshold value', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    await expect(
      runCheckCmd(['--cross-lingual', '--threshold', '2.5', 'hello']),
    ).rejects.toThrow('__exit__1');
    expect(errSpy).toHaveBeenCalledWith(
      expect.stringContaining('--threshold must be a number between 0 and 1'),
    );
  });

  test('runs checker with defaults and exits 0 when not flagged', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    mockedRun.mockResolvedValue(buildResult({ flagged: false, delta: 0.05 }));

    // No flagged → no exit called, completes normally.
    await runCheckCmd(['--cross-lingual', 'benign input']);

    expect(mockedRun).toHaveBeenCalledWith('benign input', {
      model: 'claude-haiku-4-5-20251001',
      apiKey: 'test-key',
      threshold: 0.3,
    });
    expect(mockedFormat).toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalled();
    expect(exitSpy).not.toHaveBeenCalled();
  });

  test('exits 1 with FLAGGED output when result.flagged is true', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    mockedRun.mockResolvedValue(
      buildResult({ flagged: true, delta: 0.6, sourceScore: 0.1, englishScore: 0.7 }),
    );

    await expect(
      runCheckCmd(['--cross-lingual', 'risky text']),
    ).rejects.toThrow('__exit__1');

    const printed = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(printed).toContain('flagged=true');
  });

  test('respects --model, --threshold, --api-key flags', async () => {
    mockedRun.mockResolvedValue(buildResult({ flagged: false }));

    await runCheckCmd([
      '--cross-lingual',
      '--model',
      'gpt-4o-mini',
      '--threshold',
      '0.15',
      '--api-key',
      'explicit-key',
      'some input',
    ]);

    expect(mockedRun).toHaveBeenCalledWith('some input', {
      model: 'gpt-4o-mini',
      apiKey: 'explicit-key',
      threshold: 0.15,
    });
  });

  test('outputs JSON when --json flag is set', async () => {
    process.env.ANTHROPIC_API_KEY = 'test-key';
    const result = buildResult({ flagged: false, sourceScore: 0.2, englishScore: 0.3 });
    mockedRun.mockResolvedValue(result);

    await runCheckCmd(['--cross-lingual', '--json', 'hello']);

    // When --json, formatter should not be used for output
    expect(mockedFormat).not.toHaveBeenCalled();
    const printed = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(printed).toContain('"sourceScore"');
    expect(printed).toContain('"englishScore"');
  });
});
