/**
 * OcrWorkerPool — bounded concurrency + scan-level time budget for tesseract OCR.
 *
 * Config (env vars):
 *   SENTORI_OCR_CONCURRENCY  — max parallel tesseract workers (default: 4)
 *   SENTORI_OCR_BUDGET_MS    — total OCR time budget for one scan run in ms (default: 120000)
 *   SENTORI_OCR_TIMEOUT_MS   — per-image OCR timeout in ms (default: 30000)
 */

// Dynamic import for tesseract.js (ESM module)
let Tesseract: any = null;

async function getTesseract(): Promise<any> {
  if (!Tesseract) {
    Tesseract = await import('tesseract.js');
  }
  return Tesseract;
}

export interface OcrResult {
  text: string;
  /** true if the image was skipped due to budget exhaustion */
  budgetExceeded: boolean;
}

export class OcrWorkerPool {
  private readonly concurrency: number;
  private readonly budgetMs: number;
  private readonly timeoutMs: number;

  private budgetDeadline: number = 0;
  private active: number = 0;
  private queue: Array<() => void> = [];

  constructor(opts?: { concurrency?: number; budgetMs?: number; timeoutMs?: number }) {
    this.concurrency = opts?.concurrency
      ?? (parseInt(process.env.SENTORI_OCR_CONCURRENCY ?? '', 10) || 4);
    this.budgetMs = opts?.budgetMs
      ?? (parseInt(process.env.SENTORI_OCR_BUDGET_MS ?? '', 10) || 120_000);
    this.timeoutMs = opts?.timeoutMs
      ?? (parseInt(process.env.SENTORI_OCR_TIMEOUT_MS ?? '', 10) || 30_000);
  }

  /** Call once before starting a batch of OCR work. Resets the budget clock. */
  startBudget(): void {
    this.budgetDeadline = Date.now() + this.budgetMs;
  }

  /** True if the scan-level budget has been exhausted. */
  isBudgetExceeded(): boolean {
    return this.budgetDeadline > 0 && Date.now() >= this.budgetDeadline;
  }

  /**
   * Enqueue an OCR job for `imagePath`. Respects concurrency limit and budget.
   * Returns null on budget exhaustion or when tesseract returns no text.
   */
  async recognize(imagePath: string): Promise<OcrResult> {
    if (this.isBudgetExceeded()) {
      return { text: '', budgetExceeded: true };
    }

    await this.acquire();
    try {
      // Re-check after potentially waiting in queue
      if (this.isBudgetExceeded()) {
        return { text: '', budgetExceeded: true };
      }
      return await this.runOcr(imagePath);
    } finally {
      this.release();
    }
  }

  // --- internals ---

  private acquire(): Promise<void> {
    if (this.active < this.concurrency) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  private release(): void {
    const next = this.queue.shift();
    if (next) {
      next(); // pass the slot to the next waiter (active count stays the same)
    } else {
      this.active--;
    }
  }

  private async runOcr(imagePath: string): Promise<OcrResult> {
    const remaining = this.budgetDeadline > 0
      ? Math.max(0, this.budgetDeadline - Date.now())
      : this.timeoutMs;
    const effectiveTimeout = Math.min(this.timeoutMs, remaining);

    // Budget expired between the isBudgetExceeded() check and here — skip the
    // worker entirely instead of creating it only to time it out immediately.
    if (effectiveTimeout <= 0) {
      return { text: '', budgetExceeded: true };
    }

    const tesseract = await getTesseract();
    const worker = await tesseract.createWorker('eng', undefined, {
      logger: () => {},
    });

    const recognizePromise = worker.recognize(imagePath);
    let timeoutHandle!: NodeJS.Timeout;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(() => reject(new Error('OCR timeout')), effectiveTimeout);
    });

    let text = '';
    try {
      const result = await Promise.race([recognizePromise, timeoutPromise]);
      text = (result as any).data.text ?? '';
    } finally {
      clearTimeout(timeoutHandle);
      await worker.terminate();
    }

    return { text, budgetExceeded: false };
  }
}
