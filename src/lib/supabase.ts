import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const url  = process.env.NEXT_PUBLIC_SUPABASE_URL  ?? "";
const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";

const SUPABASE_CONFIGURED = Boolean(url && anon);

// ── Stub client used when Supabase is not configured (demo / skip-auth mode) ──
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function makeStubClient(): SupabaseClient<any> {
  const noop = () => Promise.resolve({ data: null, error: null });

  // Fully chainable query builder — every filter/modifier returns itself,
  // and it is awaitable (thenable) with { data: null, error: null }.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function makeBuilder(): any {
    const empty = Promise.resolve({ data: null, error: null, count: null, status: 200, statusText: "OK" });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const b: any = {
      then:  (res: any, rej: any) => empty.then(res, rej),
      catch: (rej: any)           => empty.catch(rej),
      finally:(fn: any)           => empty.finally(fn),
      single:      () => Promise.resolve({ data: null, error: null }),
      maybeSingle: () => Promise.resolve({ data: null, error: null }),
    };
    // All standard PostgREST filter + modifier methods chain back to the same builder
    for (const m of [
      "eq","neq","gt","gte","lt","lte","in","not","is","like","ilike",
      "likeAllOf","likeAnyOf","ilikeAllOf","ilikeAnyOf",
      "contains","containedBy","rangeGt","rangeGte","rangeLt","rangeLte","rangeAdjacent","overlaps",
      "order","limit","range","select","filter","match","or","and","explain","returns","rollback","csv",
    ]) { b[m] = () => b; }
    return b;
  }

  const stub = {
    auth: {
      getSession:         () => Promise.resolve({ data: { session: null }, error: null }),
      getUser:            () => Promise.resolve({ data: { user: null },    error: null }),
      onAuthStateChange:  () => ({ data: { subscription: { unsubscribe: () => {} } } }),
      signInWithOAuth:    noop,
      signInWithPassword: noop,
      signUp:             noop,
      signOut:            noop,
    },
    from: () => ({
      select: makeBuilder,
      insert: () => makeBuilder(),
      update: () => makeBuilder(),
      delete: () => makeBuilder(),
      upsert: () => makeBuilder(),
    }),
    storage: {
      from: () => ({
        upload:          noop,
        list:            () => Promise.resolve({ data: [], error: null }),
        remove:          noop,
        createSignedUrl: () => Promise.resolve({ data: { signedUrl: "" }, error: null }),
      }),
    },
    channel: () => ({
      on:        function(this: unknown) { return this; },
      subscribe: () => ({}),
    }),
    removeChannel: noop,
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return stub as unknown as SupabaseClient<any>;
}

// Browser client — uses anon key, respects RLS
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const supabase: SupabaseClient<any> = SUPABASE_CONFIGURED
  ? createClient(url, anon, { auth: { persistSession: true, autoRefreshToken: true } })
  : makeStubClient();

// Server-side client — uses service role key, bypasses RLS.
// ONLY import this in API routes / server components — never expose to browser.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function createServiceClient(): SupabaseClient<any> {
  if (!SUPABASE_CONFIGURED) return makeStubClient();
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!serviceKey) {
    // Misconfiguration: falling back to anon key means RLS is NOT bypassed.
    // All service-role operations will silently fail or return empty data.
    console.error("[TrustLedger] SUPABASE_SERVICE_ROLE_KEY is not set. API routes will use the anon key and RLS will NOT be bypassed. Set this env var in production.");
  }
  return createClient(url, serviceKey ?? anon, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

// Re-export type helper — replace with `supabase gen types typescript` output
export type { Database } from "@/types/supabase";
