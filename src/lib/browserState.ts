/**
 * The state this app keeps in the browser (notifications, the last dashboard snapshot, the setup checklist's progress
 * and dismissal, incident and team caches, ...) is stored under fixed "tl_*" keys. Nothing tied it to a person, so a
 * second account opened in the same browser showed the first one's notifications and a dismissed setup guide.
 *
 * Fix: the browser remembers WHO its state belongs to. When a different user signs in (or nobody is recorded, as in
 * a browser used before this existed) the per-user state is cleared first; signing out clears it too. Device settings
 * -- theme, cookie consent, timezone -- belong to the browser and stay.
 *
 * Client-only; every access is guarded (private windows, blocked storage).
 */

const OWNER_KEY = "tl_owner";
/** Browser preferences that are not about an account. tl_password_recovery is a sign-in flow flag, handled by auth. */
const DEVICE_KEYS = new Set(["tl_theme", "tl_cookie_consent", "tl_user_timezone", "tl_password_recovery"]);

function clearStore(store: Storage): void {
  const doomed: string[] = [];
  for (let i = 0; i < store.length; i++) {
    const k = store.key(i);
    if (k && k.startsWith("tl_") && !DEVICE_KEYS.has(k) && k !== OWNER_KEY) doomed.push(k);
  }
  for (const k of doomed) store.removeItem(k);
}

export interface BrowserStores { local: Storage; session: Storage }
const browserStores = (): BrowserStores => ({ local: localStorage, session: sessionStorage });

/** Forget everything this browser holds for the signed-in account (local and session storage). */
export function clearUserBrowserState(stores?: BrowserStores): void {
  try { const l = stores?.local ?? localStorage; clearStore(l); l.removeItem(OWNER_KEY); } catch { /* storage unavailable */ }
  try { clearStore(stores?.session ?? sessionStorage); } catch { /* storage unavailable */ }
}

/** Call as soon as a user is known, before anything reads the state: clears it unless it already belongs to them. */
export function claimBrowserState(userId: string | null | undefined, stores?: BrowserStores): void {
  if (!userId) return;
  try {
    const st = stores ?? browserStores();
    if (st.local.getItem(OWNER_KEY) === userId) return;
    clearUserBrowserState(st);
    st.local.setItem(OWNER_KEY, userId);
  } catch { /* storage unavailable */ }
}
