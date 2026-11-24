/**
 * Bounded concurrency and backpressure for the scan pipeline.
 *
 * Semaphore: limits parallel analyzeFile() calls so a burst of large PRs
 * does not exhaust Node's heap.  When the queue exceeds its depth limit
 * (backpressure) callers receive an error immediately instead of waiting
 * indefinitely — the job stays in the message queue and is retried later.
 *
 * LanguageBudgetTracker: per-language ms budget within a single scan.
 * When a language exceeds its budget, subsequent files in that language
 * are handed to the pattern layer only (the same path as
 * ScanInput.time_budget_ms, but per-language rather than global).
 * Files dropped this way MUST generate a "time-budget" CoverageGap —
 * performance limits must never cause silent analysis skipping.
 *
 * CancellationToken: AbortController-based signal that lets a worker stop
 * analysis mid-scan when the job is superseded or the queue item is cancelled.
 *
 * streamInBatches: async generator for large-repository streaming.
 * Yields successive file batches and yields to the event loop between them
 * (backpressure point) so the caller can begin emitting results before the
 * whole repository is processed.
 */

// ── Semaphore ─────────────────────────────────────────────────────────────────

export class BackpressureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackpressureError";
  }
}

/**
 * Counting semaphore with optional queue-depth limit for backpressure.
 *
 * Acquire waits until a slot is free.  If the internal wait queue already
 * has `maxQueueDepth` entries, `acquire()` throws `BackpressureError`
 * immediately — the caller should surface this as a 503 / retry-later
 * response rather than growing the queue unboundedly.
 */
export class Semaphore {
  private _available: number;
  private readonly _queue: Array<(value: void) => void> = [];

  constructor(
    private readonly _maxConcurrency: number,
    private readonly _maxQueueDepth: number = Infinity,
  ) {
    if (_maxConcurrency < 1) throw new RangeError("maxConcurrency must be >= 1");
    this._available = _maxConcurrency;
  }

  get available(): number { return this._available; }
  get queueDepth(): number { return this._queue.length; }
  get maxConcurrency(): number { return this._maxConcurrency; }

  async acquire(): Promise<void> {
    if (this._available > 0) {
      this._available--;
      return;
    }
    if (this._queue.length >= this._maxQueueDepth) {
      throw new BackpressureError(
        `Semaphore queue depth limit (${this._maxQueueDepth}) exceeded — dropping request`,
      );
    }
    return new Promise<void>(resolve => this._queue.push(resolve));
  }

  release(): void {
    if (this._queue.length > 0) {
      const resolve = this._queue.shift()!;
      resolve();
    } else {
      this._available = Math.min(this._maxConcurrency, this._available + 1);
    }
  }
}

/** Run `fn` under the semaphore, releasing on completion or error. */
export async function withConcurrencyLimit<T>(
  semaphore: Semaphore,
  fn: () => Promise<T>,
): Promise<T> {
  await semaphore.acquire();
  try {
    return await fn();
  } finally {
    semaphore.release();
  }
}

// ── Per-language execution budget ─────────────────────────────────────────────

/**
 * Tracks per-language time budgets within a single scan invocation.
 *
 * When a language's budget is exhausted, `isOverBudget(lang)` returns true
 * and the caller skips the data-flow engine for subsequent files in that
 * language.  Those files must generate a "time-budget" CoverageGap so the
 * scan health report reflects incomplete coverage.
 */
export class LanguageBudgetTracker {
  private readonly _used = new Map<string, number>();

  constructor(
    private readonly _budgets: Readonly<Partial<Record<string, number>>>,
  ) {}

  /**
   * Record elapsed ms for a language.
   * Returns true when the budget is now exhausted (after adding elapsedMs).
   */
  record(language: string, elapsedMs: number): boolean {
    const budget = this._budgets[language];
    if (budget == null) return false;
    const used = (this._used.get(language) ?? 0) + elapsedMs;
    this._used.set(language, used);
    return used >= budget;
  }

  /** Whether a language's budget was already exhausted before this file. */
  isOverBudget(language: string): boolean {
    const budget = this._budgets[language];
    if (budget == null) return false;
    return (this._used.get(language) ?? 0) >= budget;
  }

  usedMs(language: string): number {
    return this._used.get(language) ?? 0;
  }

  budgetMs(language: string): number | undefined {
    return this._budgets[language];
  }

  /** All languages that have exceeded their budget. */
  exhaustedLanguages(): string[] {
    return [...this._used.entries()]
      .filter(([lang, used]) => {
        const b = this._budgets[lang];
        return b != null && used >= b;
      })
      .map(([lang]) => lang);
  }
}

/** Default per-language budgets for a scan (ms). Generous enough for large PRs. */
export const DEFAULT_LANGUAGE_BUDGETS: Partial<Record<string, number>> = {
  python:     30_000,
  java:       30_000,
  golang:     30_000,
  csharp:     30_000,
  php:        30_000,
  ruby:       20_000,
  kotlin:     20_000,
  rust:       20_000,
  cpp:        20_000,
  javascript: 60_000,
  typescript: 60_000,
};

// ── Worker cancellation ───────────────────────────────────────────────────────

export interface CancellationToken {
  readonly signal: AbortSignal;
  readonly cancelled: boolean;
  cancel(reason?: string): void;
}

/** Create a cancellation token backed by an AbortController. */
export function createCancellationToken(): CancellationToken {
  const controller = new AbortController();
  return {
    get signal()    { return controller.signal; },
    get cancelled() { return controller.signal.aborted; },
    cancel(reason?: string) { controller.abort(reason); },
  };
}

// ── Large-repository streaming ────────────────────────────────────────────────

/**
 * Chunk a large file list into streaming batches so the scan pipeline can
 * start emitting results for the first batch while still processing later
 * ones — prevents a single very large PR from blocking the whole queue.
 *
 * Yields to the event loop between batches (backpressure point) so the
 * runtime can service other requests.  Stops immediately when the token
 * is cancelled so the caller can honour a job-superseded signal cleanly.
 */
export async function* streamInBatches<T>(
  items: readonly T[],
  batchSize: number,
  token: CancellationToken,
): AsyncGenerator<T[], void, unknown> {
  for (let i = 0; i < items.length; i += batchSize) {
    if (token.cancelled) break;
    yield items.slice(i, i + batchSize);
    // Yield to the event loop between batches (the backpressure point).
    await new Promise<void>(resolve => setTimeout(resolve, 0));
  }
}
