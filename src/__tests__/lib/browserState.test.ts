/**
 * The browser's saved state (notifications, snapshot, setup guide, ...) belongs to ONE account: a second account in
 * the same browser used to show the first one's notifications and a dismissed setup guide.
 */
import { claimBrowserState as claim, clearUserBrowserState as clear, type BrowserStores } from "@/lib/browserState";

// A complete Storage (key()/length), injected: the shared test setup's localStorage is a minimal fake.
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

let local: Storage, session: Storage, stores: BrowserStores;
beforeEach(() => { local = memoryStorage(); session = memoryStorage(); stores = { local, session }; });

const seed = () => {
  local.setItem("tl_notifications", JSON.stringify([{ id: "n1", title: "Critical finding in acme/api" }]));
  local.setItem("tl_notif_snapshot", "{\"repos\":[]}");
  local.setItem("tl_setup_guide_dismissed", "1");
  local.setItem("tl_onboarding_step", "2");
  session.setItem("tl_notif_session", "1");
  local.setItem("tl_theme", "dark");
  local.setItem("tl_cookie_consent", "accepted");
  local.setItem("tl_user_timezone", "Asia/Kolkata");
  local.setItem("not_ours", "keep");
};

describe("browser state belongs to one account", () => {
  it("a different user signing in starts clean; device settings and other apps' keys stay", () => {
    seed();
    claim("user-a", stores);                       // first claim: the state is from before ownership was recorded
    expect(local.getItem("tl_notifications")).toBeNull();
    local.setItem("tl_notifications", "[\"A's\"]");
    claim("user-b", stores);
    expect(local.getItem("tl_notifications")).toBeNull();
    expect(local.getItem("tl_notif_snapshot")).toBeNull();
    expect(local.getItem("tl_setup_guide_dismissed")).toBeNull();
    expect(local.getItem("tl_onboarding_step")).toBeNull();
    expect(session.getItem("tl_notif_session")).toBeNull();
    expect(local.getItem("tl_theme")).toBe("dark");
    expect(local.getItem("tl_cookie_consent")).toBe("accepted");
    expect(local.getItem("tl_user_timezone")).toBe("Asia/Kolkata");
    expect(local.getItem("not_ours")).toBe("keep");
    expect(local.getItem("tl_owner")).toBe("user-b");
  });

  it("the same user coming back keeps their state", () => {
    claim("user-a", stores);
    seed();
    claim("user-a", stores);
    expect(local.getItem("tl_notifications")).not.toBeNull();
    expect(local.getItem("tl_onboarding_step")).toBe("2");
  });

  it("signing out clears the account's state and the owner; nobody signed in claims nothing", () => {
    claim("user-a", stores);
    seed();
    clear(stores);
    expect(local.getItem("tl_notifications")).toBeNull();
    expect(local.getItem("tl_owner")).toBeNull();
    expect(local.getItem("tl_theme")).toBe("dark");
    claim(null, stores);
    claim(undefined, stores);
    expect(local.getItem("tl_owner")).toBeNull();
  });

  it("a sign-in flow flag survives a claim", () => {
    local.setItem("tl_password_recovery", "1");
    claim("user-a", stores);
    expect(local.getItem("tl_password_recovery")).toBe("1");
  });
});
