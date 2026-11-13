import { normalizeGithubHandle, escapeLike } from "@/lib/githubHandle";

const handle = (raw: string) => { const r = normalizeGithubHandle(raw); return r.ok ? r.handle : `ERR:${r.problem}`; };

describe("normalizeGithubHandle", () => {
  it.each([
    ["acme-corp", "acme-corp"],
    ["  acme-corp  ", "acme-corp"],
    ["@acme-corp", "acme-corp"],
    ["Acme-Corp", "acme-corp"],                                   // GitHub names are case-insensitive: saved lower case
    ["https://github.com/acme-corp", "acme-corp"],
    ["https://github.com/acme-corp/payments-api", "acme-corp"],   // a pasted repository address
    ["github.com/acme-corp/payments-api", "acme-corp"],
    ["www.github.com/acme-corp", "acme-corp"],
    ["acme-corp/payments-api", "acme-corp"],                      // a pasted full repository name
    ["https://github.com/acme-corp?tab=repositories", "acme-corp"],
    ["a", "a"],
    ["cyberminutetech", "cyberminutetech"],
    ["acme_corp_emu", "acme_corp_emu"],
  ])("takes %j as %j", (raw, want) => expect(handle(raw)).toBe(want));

  it.each([
    ["", "empty"], ["   ", "empty"], ["@", "invalid"],
    ["raviteja.t@gmail.com", "email"], ["me@example.com", "email"],
    ["acme corp", "invalid"], ["acme.corp", "invalid"], ["-acme", "invalid"], ["acme!", "invalid"],
    ["a".repeat(40), "invalid"], ["https://example.com/acme", "invalid"],
  ])("refuses %j (%s)", (raw, problem) => expect(handle(raw)).toBe(`ERR:${problem}`));

  it("an email gets a message that says what to type instead", () => {
    const r = normalizeGithubHandle("me@example.com");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.message).toMatch(/email address/i);
  });

  it("says when it had to clean the input up, so the page can show what will be saved", () => {
    expect(normalizeGithubHandle("https://github.com/Acme-Corp/x")).toMatchObject({ ok: true, handle: "acme-corp", changed: true });
    expect(normalizeGithubHandle("acme-corp")).toMatchObject({ ok: true, handle: "acme-corp", changed: false });
  });
});

describe("escapeLike", () => {
  it("makes _ and % literal", () => {
    expect(escapeLike("acme_corp")).toBe("acme\\_corp");
    expect(escapeLike("100%")).toBe("100\\%");
    expect(escapeLike("a\\b")).toBe("a\\\\b");
  });
});
