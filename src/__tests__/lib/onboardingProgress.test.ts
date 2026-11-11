/**
 * The setup wizard always lists the same five steps; finished steps are remembered so it reopens at the first one still
 * to do, and nothing is remembered once setup is finished.
 */
import { clearDoneSteps, DOABLE_STEPS, firstUnfinishedIndex, loadDoneSteps, markStepDone, WIZARD_STEPS, ONBOARDING_DONE_KEY } from "@/lib/onboardingProgress";

const memoryStorage = (): Storage => {
  const m = new Map<string, string>();
  return {
    get length() { return m.size; },
    key: (i: number) => [...m.keys()][i] ?? null,
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => { m.set(k, String(v)); },
    removeItem: (k: string) => { m.delete(k); },
    clear: () => m.clear(),
  };
};
let store: Storage;
beforeEach(() => { store = memoryStorage(); });

describe("setup wizard progress", () => {
  it("is five steps, four to do and a finish line", () => {
    expect(WIZARD_STEPS).toEqual(["welcome", "github", "team", "policy", "done"]);
    expect(DOABLE_STEPS).toEqual(["welcome", "github", "team", "policy"]);
  });

  it("reopens at the first step still to do, however the steps were finished", () => {
    expect(firstUnfinishedIndex([])).toBe(0);
    expect(firstUnfinishedIndex(["welcome"])).toBe(1);
    expect(firstUnfinishedIndex(["welcome", "github"])).toBe(2);
    // a step skipped over is still the one to do
    expect(firstUnfinishedIndex(["welcome", "team"])).toBe(1);
    // everything done: the finish line
    expect(firstUnfinishedIndex(["welcome", "github", "team", "policy"])).toBe(4);
  });

  it("remembers finished steps, in order and without repeats", () => {
    expect(markStepDone("welcome", store)).toEqual(["welcome"]);
    expect(markStepDone("team", store)).toEqual(["welcome", "team"]);
    expect(markStepDone("welcome", store)).toEqual(["welcome", "team"]);
    expect(loadDoneSteps(store)).toEqual(["welcome", "team"]);
  });

  it("the finish line is never stored as a step to do; junk or unreadable storage is an empty list", () => {
    markStepDone("done", store);
    expect(loadDoneSteps(store)).toEqual([]);
    store.setItem(ONBOARDING_DONE_KEY, "not json");
    expect(loadDoneSteps(store)).toEqual([]);
    store.setItem(ONBOARDING_DONE_KEY, JSON.stringify(["github", "bogus", 7]));
    expect(loadDoneSteps(store)).toEqual(["github"]);
  });

  it("clears once setup is finished", () => {
    markStepDone("welcome", store);
    clearDoneSteps(store);
    expect(loadDoneSteps(store)).toEqual([]);
  });
});
