/**
 * Which setup-wizard steps this person has finished, kept in the browser so the wizard can reopen at the first one
 * still to do. The wizard always lists the same five steps (the last, "Ready", is the finish line) until setup is
 * complete; finished steps show as done and are not asked again.
 *
 * Stored under a "tl_" key, so it is cleared with the rest of an account's browser state when someone else signs in
 * (lib/browserState.ts). Client-only; every access is guarded.
 */
export type WizardStep = "welcome" | "github" | "team" | "policy" | "done";
/** The five steps, in order. */
export const WIZARD_STEPS: readonly WizardStep[] = ["welcome", "github", "team", "policy", "done"];
/** The steps a person actually does; reaching "done" completes setup. */
export const DOABLE_STEPS: readonly WizardStep[] = WIZARD_STEPS.slice(0, -1);
export const ONBOARDING_DONE_KEY = "tl_onboarding_done";

export function loadDoneSteps(store?: Storage): WizardStep[] {
  try {
    const raw = JSON.parse((store ?? localStorage).getItem(ONBOARDING_DONE_KEY) ?? "[]");
    return Array.isArray(raw) ? DOABLE_STEPS.filter(s => raw.includes(s)) : [];
  } catch { return []; }
}

/** Record a step as finished; returns the new list. */
export function markStepDone(step: WizardStep, store?: Storage): WizardStep[] {
  const have = loadDoneSteps(store);
  const done = DOABLE_STEPS.includes(step) ? DOABLE_STEPS.filter(s => s === step || have.includes(s)) : have;
  try { (store ?? localStorage).setItem(ONBOARDING_DONE_KEY, JSON.stringify(done)); } catch { /* storage unavailable */ }
  return done;
}

export function clearDoneSteps(store?: Storage): void {
  try { (store ?? localStorage).removeItem(ONBOARDING_DONE_KEY); } catch { /* storage unavailable */ }
}

/** Index (in WIZARD_STEPS) of the first step still to do; the finish line when every step is done. */
export function firstUnfinishedIndex(done: readonly WizardStep[]): number {
  const i = DOABLE_STEPS.findIndex(s => !done.includes(s));
  return i === -1 ? WIZARD_STEPS.length - 1 : i;
}
