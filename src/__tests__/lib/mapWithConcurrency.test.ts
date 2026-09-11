import { mapWithConcurrency } from "@/lib/github";

describe("mapWithConcurrency", () => {
  it("returns results in the same order as the input, regardless of completion order", async () => {
    const items = [30, 10, 20, 5, 25];
    const results = await mapWithConcurrency(items, 3, async ms => {
      await new Promise(r => setTimeout(r, ms));
      return ms;
    });
    expect(results).toEqual(items);
  });

  it("never runs more than `limit` calls concurrently", async () => {
    let active = 0;
    let maxActive = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);

    await mapWithConcurrency(items, 4, async i => {
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise(r => setTimeout(r, 5));
      active--;
      return i;
    });

    expect(maxActive).toBeLessThanOrEqual(4);
  });

  it("processes every item exactly once", async () => {
    const items = Array.from({ length: 50 }, (_, i) => i);
    const seen: number[] = [];
    await mapWithConcurrency(items, 7, async i => { seen.push(i); return i; });
    expect(seen.sort((a, b) => a - b)).toEqual(items);
  });

  it("handles an empty input without hanging", async () => {
    const results = await mapWithConcurrency<number, number>([], 5, async i => i);
    expect(results).toEqual([]);
  });

  it("handles limit greater than item count", async () => {
    const results = await mapWithConcurrency([1, 2, 3], 100, async i => i * 2);
    expect(results).toEqual([2, 4, 6]);
  });

  it("propagates a thrown error from one worker", async () => {
    await expect(
      mapWithConcurrency([1, 2, 3], 2, async i => {
        if (i === 2) throw new Error("boom");
        return i;
      }),
    ).rejects.toThrow("boom");
  });
});
