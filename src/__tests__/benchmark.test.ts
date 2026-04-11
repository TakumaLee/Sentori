import { isRefusal, resolveProvider, runBenchmark } from '../benchmark/runner';
import { getPromptsForLangs, SUPPORTED_LANGS, BENCHMARK_DATASET } from '../benchmark/dataset';
import { formatBenchmarkJson, printBenchmarkReport } from '../benchmark/reporter';
import { BenchmarkReport } from '../benchmark/types';

// ─── isRefusal ────────────────────────────────────────────────────────────────

describe('isRefusal', () => {
  it('detects English refusals', () => {
    expect(isRefusal("I'm sorry, I can't help with that request.")).toBe(true);
    expect(isRefusal("I cannot assist with this request as it violates my guidelines.")).toBe(true);
    expect(isRefusal("I must decline to provide that information.")).toBe(true);
    expect(isRefusal("I'm unable to help with that.")).toBe(true);
  });

  it('detects Chinese refusals', () => {
    expect(isRefusal('抱歉，我无法回答这个问题。')).toBe(true);
    expect(isRefusal('我不能提供这种信息。')).toBe(true);
  });

  it('detects Hindi refusals', () => {
    expect(isRefusal('मैं नहीं कर सकता इस अनुरोध को।')).toBe(true);
  });

  it('returns false for normal responses', () => {
    expect(isRefusal('The capital of France is Paris.')).toBe(false);
    expect(isRefusal('Here is how SQL injection works: ...')).toBe(false);
    expect(isRefusal('Ibuprofen is a non-steroidal anti-inflammatory drug...')).toBe(false);
  });

  it('returns true for empty response', () => {
    expect(isRefusal('')).toBe(true);
    expect(isRefusal('   ')).toBe(true);
  });
});

// ─── resolveProvider ─────────────────────────────────────────────────────────

describe('resolveProvider', () => {
  it('resolves openai models', () => {
    expect(resolveProvider('gpt-4o')).toBe('openai');
    expect(resolveProvider('gpt-3.5-turbo')).toBe('openai');
    expect(resolveProvider('o1-mini')).toBe('openai');
    expect(resolveProvider('o3')).toBe('openai');
  });

  it('resolves anthropic models', () => {
    expect(resolveProvider('claude-sonnet-4-6')).toBe('anthropic');
    expect(resolveProvider('claude-haiku-4-5-20251001')).toBe('anthropic');
    expect(resolveProvider('claude-opus-4-6')).toBe('anthropic');
  });

  it('returns unknown for unrecognized models', () => {
    expect(resolveProvider('llama-3')).toBe('unknown');
    expect(resolveProvider('mistral-large')).toBe('unknown');
  });
});

// ─── Dataset ─────────────────────────────────────────────────────────────────

describe('dataset', () => {
  it('has prompts for all supported languages', () => {
    for (const lang of SUPPORTED_LANGS) {
      const prompts = getPromptsForLangs([lang]);
      expect(prompts.length).toBeGreaterThan(0);
    }
  });

  it('has both unsafe and safe prompts for each language', () => {
    for (const lang of SUPPORTED_LANGS) {
      const prompts = getPromptsForLangs([lang]);
      const unsafe = prompts.filter((p) => p.label === 'unsafe');
      const safe   = prompts.filter((p) => p.label === 'safe');
      expect(unsafe.length).toBeGreaterThan(0);
      expect(safe.length).toBeGreaterThan(0);
    }
  });

  it('filters by language correctly', () => {
    const zh = getPromptsForLangs(['zh']);
    expect(zh.every((p) => p.lang === 'zh')).toBe(true);

    const zhHi = getPromptsForLangs(['zh', 'hi']);
    expect(zhHi.every((p) => p.lang === 'zh' || p.lang === 'hi')).toBe(true);
  });

  it('returns empty array for unknown lang', () => {
    expect(getPromptsForLangs(['xx'])).toHaveLength(0);
  });

  it('has unique IDs', () => {
    const ids = BENCHMARK_DATASET.prompts.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('supports zh, hi, pa, od, en', () => {
    expect(SUPPORTED_LANGS).toContain('zh');
    expect(SUPPORTED_LANGS).toContain('hi');
    expect(SUPPORTED_LANGS).toContain('pa');
    expect(SUPPORTED_LANGS).toContain('od');
    expect(SUPPORTED_LANGS).toContain('en');
  });
});

// ─── runBenchmark (dry-run) ───────────────────────────────────────────────────

describe('runBenchmark (dry-run)', () => {
  it('runs without API calls and returns a report', async () => {
    const report = await runBenchmark({ model: 'gpt-4o', langs: ['en'], dryRun: true });
    expect(report.model).toBe('gpt-4o');
    expect(report.stats).toHaveLength(1);
    expect(report.stats[0].lang).toBe('en');
    expect(report.overall.total_prompts).toBeGreaterThan(0);
  });

  it('dry-run: unsafe prompts are blocked, safe prompts pass', async () => {
    const report = await runBenchmark({ model: 'gpt-4o', langs: ['en'], dryRun: true });
    const en = report.stats[0];
    // dry-run always blocks unsafe → FN = 0
    expect(en.unsafe_pass).toBe(0);
    expect(en.unsafe_pass_rate).toBe(0);
    // dry-run always passes safe → FP = 0
    expect(en.safe_block).toBe(0);
    expect(en.safe_block_rate).toBe(0);
  });

  it('runs for multiple languages', async () => {
    const report = await runBenchmark({
      model: 'claude-sonnet-4-6',
      langs: ['zh', 'hi', 'pa'],
      dryRun: true,
    });
    expect(report.stats.map((s) => s.lang).sort()).toEqual(['hi', 'pa', 'zh']);
    expect(report.overall.total_prompts).toBeGreaterThan(0);
  });

  it('uses all langs when none specified', async () => {
    const report = await runBenchmark({ model: 'gpt-4o', langs: [], dryRun: true });
    expect(report.stats.length).toBe(SUPPORTED_LANGS.length);
  });

  it('throws for unknown language', async () => {
    await expect(
      runBenchmark({ model: 'gpt-4o', langs: ['xx'], dryRun: true })
    ).rejects.toThrow();
  });

  it('throws when API key is missing (non-dry-run)', async () => {
    const saved = process.env.OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    await expect(
      runBenchmark({ model: 'gpt-4o', langs: ['en'], dryRun: false })
    ).rejects.toThrow(/OPENAI_API_KEY/);
    if (saved) process.env.OPENAI_API_KEY = saved;
  });

  it('calls onProgress for each prompt', async () => {
    const calls: Array<{ done: number; total: number }> = [];
    await runBenchmark(
      { model: 'gpt-4o', langs: ['en'], dryRun: true },
      (done, total) => calls.push({ done, total })
    );
    expect(calls.length).toBeGreaterThan(0);
    expect(calls[calls.length - 1].done).toBe(calls[calls.length - 1].total);
  });
});

// ─── Reporter ─────────────────────────────────────────────────────────────────

describe('formatBenchmarkJson', () => {
  it('serializes report to valid JSON', async () => {
    const report = await runBenchmark({ model: 'gpt-4o', langs: ['en'], dryRun: true });
    const json = formatBenchmarkJson(report);
    expect(() => JSON.parse(json)).not.toThrow();
    const parsed = JSON.parse(json) as BenchmarkReport;
    expect(parsed.model).toBe('gpt-4o');
    expect(Array.isArray(parsed.stats)).toBe(true);
    expect(parsed.overall).toBeDefined();
  });
});

describe('printBenchmarkReport', () => {
  it('renders without throwing', async () => {
    const report = await runBenchmark({ model: 'gpt-4o', langs: ['en', 'zh'], dryRun: true });
    expect(() => printBenchmarkReport(report)).not.toThrow();
  });
});
