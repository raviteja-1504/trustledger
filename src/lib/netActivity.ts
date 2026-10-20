/**
 * How many data requests are in flight right now, app-wide -- so the top bar can say "Refreshing…" whenever a page
 * is fetching, including background refreshes (polling, focus, after a sign-off) that otherwise change numbers with
 * no sign anything is happening. authedFetch and api.ts's apiFetch report through track(). Client-safe, no imports.
 */

type Listener = (inFlight: number) => void;

let inFlight = 0;
const listeners = new Set<Listener>();
const emit = () => listeners.forEach(l => l(inFlight));

export function getInFlight(): number { return inFlight; }

export function subscribe(l: Listener): () => void {
  listeners.add(l);
  return () => { listeners.delete(l); };
}

/** Count `p` as in flight until it settles; returns it unchanged. */
export function track<T>(p: Promise<T>): Promise<T> {
  inFlight++;
  emit();
  const done = () => { inFlight = Math.max(0, inFlight - 1); emit(); };
  p.then(done, done);
  return p;
}

/** Test hook: back to a clean state. */
export function __resetNetActivity(): void { inFlight = 0; listeners.clear(); }
