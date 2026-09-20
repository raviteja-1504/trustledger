jest.mock("@/lib/attestation", () => ({ performAttestation: jest.fn() }));

import { handleAttest, resolveSlackUserEmail } from "@/lib/slackAttest";
import { performAttestation } from "@/lib/attestation";
import type { SupabaseClient } from "@supabase/supabase-js";

const mockPerformAttestation = performAttestation as jest.MockedFunction<typeof performAttestation>;
const fakeDb = {} as SupabaseClient;

describe("slack/commands.handleAttest", () => {
  const originalToken = process.env.SLACK_BOT_TOKEN;
  const originalFetch = global.fetch;

  afterEach(() => {
    process.env.SLACK_BOT_TOKEN = originalToken;
    global.fetch = originalFetch;
    jest.restoreAllMocks();
    mockPerformAttestation.mockReset();
  });

  it("returns a usage error when scan_id is missing", async () => {
    const result = await handleAttest(fakeDb, "org-1", [], "U123") as { text: string };
    expect(result.text).toContain("Usage:");
    expect(mockPerformAttestation).not.toHaveBeenCalled();
  });

  it("returns a usage error when file_path is missing", async () => {
    const result = await handleAttest(fakeDb, "org-1", ["scan-1"], "U123") as { text: string };
    expect(result.text).toContain("Usage:");
    expect(mockPerformAttestation).not.toHaveBeenCalled();
  });

  it("joins multi-word file paths back together", async () => {
    delete process.env.SLACK_BOT_TOKEN;
    process.env.SLACK_BOT_TOKEN = "xoxb-test";
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ ok: true, user: { profile: { email: "dev@acme.com" } } }),
    }) as unknown as typeof fetch;
    mockPerformAttestation.mockResolvedValue({ ok: true, attestation_id: "a1", payload_hash: "h", attested_at: "2026-01-01T00:00:00.000Z" });

    await handleAttest(fakeDb, "org-1", ["scan-1", "src/some", "file.ts"], "U123");

    expect(mockPerformAttestation).toHaveBeenCalledWith(fakeDb, expect.objectContaining({
      scan_id: "scan-1", file_path: "src/some file.ts", reviewer_email: "dev@acme.com",
    }));
  });

  it("fails open with a dashboard-pointer message when SLACK_BOT_TOKEN is not configured", async () => {
    delete process.env.SLACK_BOT_TOKEN;
    const result = await handleAttest(fakeDb, "org-1", ["scan-1", "src/app.ts"], "U123") as { text: string };
    expect(result.text).toContain("dashboard");
    expect(mockPerformAttestation).not.toHaveBeenCalled();
  });

  it("returns a clear error when performAttestation reports scan_not_found", async () => {
    process.env.SLACK_BOT_TOKEN = "xoxb-test";
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ ok: true, user: { profile: { email: "dev@acme.com" } } }),
    }) as unknown as typeof fetch;
    mockPerformAttestation.mockResolvedValue({ ok: false, reason: "scan_not_found" });

    const result = await handleAttest(fakeDb, "org-1", ["bad-scan", "src/app.ts"], "U123") as { text: string };
    expect(result.text).toContain("Scan not found");
  });

  it("returns a success block on a successful attestation", async () => {
    process.env.SLACK_BOT_TOKEN = "xoxb-test";
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ ok: true, user: { profile: { email: "dev@acme.com" } } }),
    }) as unknown as typeof fetch;
    mockPerformAttestation.mockResolvedValue({ ok: true, attestation_id: "a1", payload_hash: "h", attested_at: "2026-01-01T00:00:00.000Z" });

    const result = await handleAttest(fakeDb, "org-1", ["scan-1", "src/app.ts"], "U123") as { blocks: Array<{ text: { text: string } }> };
    expect(result.blocks[0].text.text).toContain("src/app.ts");
    expect(result.blocks[0].text.text).toContain("dev@acme.com");
  });
});

describe("slack/commands.resolveSlackUserEmail", () => {
  const originalToken = process.env.SLACK_BOT_TOKEN;
  const originalFetch = global.fetch;

  afterEach(() => {
    process.env.SLACK_BOT_TOKEN = originalToken;
    global.fetch = originalFetch;
  });

  it("returns null when SLACK_BOT_TOKEN is not configured, without calling fetch", async () => {
    delete process.env.SLACK_BOT_TOKEN;
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await resolveSlackUserEmail("U123");

    expect(result).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns null (fails open) when the Slack API call throws", async () => {
    process.env.SLACK_BOT_TOKEN = "xoxb-test";
    global.fetch = jest.fn().mockRejectedValue(new Error("network down")) as unknown as typeof fetch;

    const result = await resolveSlackUserEmail("U123");

    expect(result).toBeNull();
  });

  it("returns null when Slack reports ok:false (e.g. user not found)", async () => {
    process.env.SLACK_BOT_TOKEN = "xoxb-test";
    global.fetch = jest.fn().mockResolvedValue({ json: async () => ({ ok: false }) }) as unknown as typeof fetch;

    const result = await resolveSlackUserEmail("U123");

    expect(result).toBeNull();
  });

  it("returns the resolved email on success", async () => {
    process.env.SLACK_BOT_TOKEN = "xoxb-test";
    global.fetch = jest.fn().mockResolvedValue({
      json: async () => ({ ok: true, user: { profile: { email: "dev@acme.com" } } }),
    }) as unknown as typeof fetch;

    const result = await resolveSlackUserEmail("U123");

    expect(result).toBe("dev@acme.com");
  });
});
