import { OcrWorkerPool } from '../utils/ocr-worker-pool';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Creates a pool with a mock recognize function so tests never call tesseract.
 * The mock is injected by overriding the private runOcr via prototype.
 */
function poolWithMock(
  opts: { concurrency?: number; budgetMs?: number; timeoutMs?: number },
  recognizeFn: (imagePath: string) => Promise<string>
): OcrWorkerPool {
  const pool = new OcrWorkerPool(opts);
  // Override the private method via prototype cast
  (pool as any).runOcr = async (imagePath: string) => {
    const text = await recognizeFn(imagePath);
    return { text, budgetExceeded: false };
  };
  return pool;
}

// ---------------------------------------------------------------------------
// startBudget / isBudgetExceeded
// ---------------------------------------------------------------------------

describe('OcrWorkerPool — budget', () => {
  test('isBudgetExceeded returns false before startBudget', () => {
    const pool = new OcrWorkerPool({ budgetMs: 100 });
    expect(pool.isBudgetExceeded()).toBe(false);
  });

  test('isBudgetExceeded returns false immediately after startBudget', () => {
    const pool = new OcrWorkerPool({ budgetMs: 5000 });
    pool.startBudget();
    expect(pool.isBudgetExceeded()).toBe(false);
  });

  test('isBudgetExceeded returns true after budget expires', async () => {
    const pool = new OcrWorkerPool({ budgetMs: 20 }); // 20 ms budget
    pool.startBudget();
    await new Promise(r => setTimeout(r, 30));
    expect(pool.isBudgetExceeded()).toBe(true);
  });

  test('recognize returns budgetExceeded=true when budget is already expired', async () => {
    const pool = poolWithMock({ budgetMs: 1 }, async () => 'hello');
    pool.startBudget();
    await new Promise(r => setTimeout(r, 10)); // let budget expire
    const result = await pool.recognize('/fake/image.png');
    expect(result.budgetExceeded).toBe(true);
    expect(result.text).toBe('');
  });
});

// ---------------------------------------------------------------------------
// concurrency limiting
// ---------------------------------------------------------------------------

describe('OcrWorkerPool — concurrency', () => {
  test('limits concurrent workers to the specified concurrency', async () => {
    let active = 0;
    let maxActive = 0;
    const concurrency = 2;

    const pool = poolWithMock({ concurrency, budgetMs: 5000, timeoutMs: 5000 }, async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      // Simulate work
      await new Promise(r => setTimeout(r, 20));
      active--;
      return 'text';
    });
    pool.startBudget();

    // Dispatch 6 jobs simultaneously
    await Promise.all(
      Array.from({ length: 6 }, (_, i) => pool.recognize(`/img${i}.png`))
    );

    expect(maxActive).toBeLessThanOrEqual(concurrency);
  });

  test('resolves all jobs when concurrency < job count', async () => {
    const pool = poolWithMock({ concurrency: 2, budgetMs: 5000 }, async (p) => `ok:${p}`);
    pool.startBudget();

    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) => pool.recognize(`/img${i}.png`))
    );

    expect(results).toHaveLength(5);
    for (const r of results) {
      expect(r.budgetExceeded).toBe(false);
      expect(r.text).toMatch(/^ok:/);
    }
  });
});

// ---------------------------------------------------------------------------
// env var config
// ---------------------------------------------------------------------------

describe('OcrWorkerPool — env var config', () => {
  const OLD_ENV = process.env;

  beforeEach(() => {
    process.env = { ...OLD_ENV };
  });

  afterEach(() => {
    process.env = OLD_ENV;
  });

  test('reads SENTORI_OCR_CONCURRENCY from env', () => {
    process.env.SENTORI_OCR_CONCURRENCY = '7';
    const pool = new OcrWorkerPool();
    expect((pool as any).concurrency).toBe(7);
  });

  test('reads SENTORI_OCR_BUDGET_MS from env', () => {
    process.env.SENTORI_OCR_BUDGET_MS = '60000';
    const pool = new OcrWorkerPool();
    expect((pool as any).budgetMs).toBe(60_000);
  });

  test('reads SENTORI_OCR_TIMEOUT_MS from env', () => {
    process.env.SENTORI_OCR_TIMEOUT_MS = '10000';
    const pool = new OcrWorkerPool();
    expect((pool as any).timeoutMs).toBe(10_000);
  });

  test('constructor opts take precedence over env vars', () => {
    process.env.SENTORI_OCR_CONCURRENCY = '99';
    const pool = new OcrWorkerPool({ concurrency: 3 });
    expect((pool as any).concurrency).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Integration — budget exhaustion mid-batch
// ---------------------------------------------------------------------------

describe('OcrWorkerPool — budget exhaustion mid-batch', () => {
  test('stops processing images once budget is consumed', async () => {
    let processed = 0;
    const pool = poolWithMock({ concurrency: 1, budgetMs: 40 }, async () => {
      processed++;
      await new Promise(r => setTimeout(r, 20)); // each image takes 20 ms
      return 'text';
    });
    pool.startBudget();

    // Queue 10 images. Budget of 40 ms should only allow ~2 through.
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => pool.recognize(`/img${i}.png`))
    );

    const skipped = results.filter(r => r.budgetExceeded);
    // At least some should be skipped
    expect(skipped.length).toBeGreaterThan(0);
    // And not all should be processed
    expect(processed).toBeLessThan(10);
  });
});
