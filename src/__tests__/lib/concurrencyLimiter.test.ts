import {
  Semaphore,
  BackpressureError,
  withConcurrencyLimit,
  LanguageBudgetTracker,
  DEFAULT_LANGUAGE_BUDGETS,
  createCancellationToken,
  streamInBatches,
} from "../../lib/concurrencyLimiter";

// ── Semaphore ─────────────────────────────────────────────────────────────────

describe("Semaphore", () => {
  it("rejects maxConcurrency < 1", () => {
    expect(() => new Semaphore(0)).toThrow(RangeError);
  });

  it("acquire resolves immediately when slots available", async () => {
    const sem = new Semaphore(2);
    await expect(sem.acquire()).resolves.toBeUndefined();
    expect(sem.available).toBe(1);
  });

  it("release restores available count", async () => {
    const sem = new Semaphore(1);
    await sem.acquire();
    expect(sem.available).toBe(0);
    sem.release();
    expect(sem.available).toBe(1);
  });

  it("queues a waiter when no slots are available", async () => {
    const sem = new Semaphore(1);
    await sem.acquire(); // occupies the only slot

    let resolved = false;
    const waiter = sem.acquire().then(() => { resolved = true; });

    expect(sem.queueDepth).toBe(1);
    expect(resolved).toBe(false);

    sem.release(); // should wake the waiter
    await waiter;
    expect(resolved).toBe(true);
  });

  it("throws BackpressureError when queue depth limit is exceeded", async () => {
    const sem = new Semaphore(1, 1);
    await sem.acquire();      // occupy slot
    sem.acquire();            // fills queue to depth 1 (will hang, not awaited)

    await expect(sem.acquire()).rejects.toThrow(BackpressureError);
  });

  it("BackpressureError has correct name", async () => {
    const sem = new Semaphore(1, 0);
    await sem.acquire();
    try {
      await sem.acquire();
      fail("expected throw");
    } catch (e) {
      expect((e as BackpressureError).name).toBe("BackpressureError");
    }
  });
});

// ── withConcurrencyLimit ──────────────────────────────────────────────────────

describe("withConcurrencyLimit", () => {
  it("runs the function and returns its value", async () => {
    const sem = new Semaphore(2);
    const result = await withConcurrencyLimit(sem, async () => 42);
    expect(result).toBe(42);
  });

  it("releases the semaphore even if fn throws", async () => {
    const sem = new Semaphore(1);
    await expect(
      withConcurrencyLimit(sem, async () => { throw new Error("boom"); }),
    ).rejects.toThrow("boom");
    expect(sem.available).toBe(1);
  });

  it("enforces max concurrency", async () => {
    const sem = new Semaphore(2);
    let concurrent = 0;
    let maxSeen = 0;
    const task = () => withConcurrencyLimit(sem, async () => {
      concurrent++;
      maxSeen = Math.max(maxSeen, concurrent);
      await new Promise<void>(r => setTimeout(r, 0));
      concurrent--;
    });
    await Promise.all([task(), task(), task(), task()]);
    expect(maxSeen).toBeLessThanOrEqual(2);
  });
});

// ── LanguageBudgetTracker ─────────────────────────────────────────────────────

describe("LanguageBudgetTracker", () => {
  it("returns false for a language with no budget", () => {
    const tracker = new LanguageBudgetTracker({ python: 1000 });
    const exhausted = tracker.record("kotlin", 500);
    expect(exhausted).toBe(false);
    expect(tracker.isOverBudget("kotlin")).toBe(false);
  });

  it("returns false while under budget", () => {
    const tracker = new LanguageBudgetTracker({ python: 1000 });
    expect(tracker.record("python", 400)).toBe(false);
    expect(tracker.isOverBudget("python")).toBe(false);
  });

  it("returns true when budget is exactly met", () => {
    const tracker = new LanguageBudgetTracker({ python: 1000 });
    expect(tracker.record("python", 1000)).toBe(true);
    expect(tracker.isOverBudget("python")).toBe(true);
  });

  it("returns true when budget is exceeded", () => {
    const tracker = new LanguageBudgetTracker({ python: 1000 });
    tracker.record("python", 600);
    expect(tracker.record("python", 500)).toBe(true);
  });

  it("isOverBudget returns false before budget is crossed", () => {
    const tracker = new LanguageBudgetTracker({ java: 500 });
    tracker.record("java", 499);
    expect(tracker.isOverBudget("java")).toBe(false);
  });

  it("exhaustedLanguages lists only languages over budget", () => {
    const tracker = new LanguageBudgetTracker({ python: 100, java: 100 });
    tracker.record("python", 150);
    tracker.record("java", 50);
    expect(tracker.exhaustedLanguages()).toEqual(["python"]);
  });

  it("usedMs accumulates across multiple calls", () => {
    const tracker = new LanguageBudgetTracker({ typescript: 60_000 });
    tracker.record("typescript", 10_000);
    tracker.record("typescript", 5_000);
    expect(tracker.usedMs("typescript")).toBe(15_000);
  });

  it("DEFAULT_LANGUAGE_BUDGETS has expected keys", () => {
    expect(DEFAULT_LANGUAGE_BUDGETS["python"]).toBe(30_000);
    expect(DEFAULT_LANGUAGE_BUDGETS["javascript"]).toBe(60_000);
    expect(DEFAULT_LANGUAGE_BUDGETS["typescript"]).toBe(60_000);
  });
});

// ── CancellationToken ─────────────────────────────────────────────────────────

describe("createCancellationToken", () => {
  it("starts not cancelled", () => {
    const token = createCancellationToken();
    expect(token.cancelled).toBe(false);
    expect(token.signal.aborted).toBe(false);
  });

  it("becomes cancelled after cancel()", () => {
    const token = createCancellationToken();
    token.cancel("test");
    expect(token.cancelled).toBe(true);
    expect(token.signal.aborted).toBe(true);
  });

  it("cancel is idempotent", () => {
    const token = createCancellationToken();
    token.cancel();
    token.cancel();
    expect(token.cancelled).toBe(true);
  });
});

// ── streamInBatches ───────────────────────────────────────────────────────────

describe("streamInBatches", () => {
  async function collectBatches<T>(gen: AsyncGenerator<T[], void, unknown>): Promise<T[][]> {
    const batches: T[][] = [];
    for await (const batch of gen) batches.push(batch);
    return batches;
  }

  it("yields all items in correct batches", async () => {
    const token = createCancellationToken();
    const batches = await collectBatches(streamInBatches([1,2,3,4,5], 2, token));
    expect(batches).toEqual([[1,2],[3,4],[5]]);
  });

  it("yields nothing for empty input", async () => {
    const token = createCancellationToken();
    const batches = await collectBatches(streamInBatches([], 10, token));
    expect(batches).toEqual([]);
  });

  it("stops early when token is cancelled", async () => {
    const token = createCancellationToken();
    const items = Array.from({ length: 100 }, (_, i) => i);
    const batches: number[][] = [];
    for await (const batch of streamInBatches(items, 10, token)) {
      batches.push(batch);
      token.cancel(); // cancel after first batch
    }
    // Only the first batch should have been yielded
    expect(batches.length).toBe(1);
    expect(batches[0]).toEqual([0,1,2,3,4,5,6,7,8,9]);
  });

  it("handles batchSize larger than items length", async () => {
    const token = createCancellationToken();
    const batches = await collectBatches(streamInBatches([1,2,3], 100, token));
    expect(batches).toEqual([[1,2,3]]);
  });
});
