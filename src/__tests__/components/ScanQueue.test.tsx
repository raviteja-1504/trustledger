/**
 * @jest-environment jsdom
 *
 * The scan queue panel: counts, the reason a scan failed, and a replay that sends the job's id.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));

import ScanQueue from "@/components/settings/ScanQueue";

const job = (over: Record<string, unknown>) => ({ id: "j1", repo_full_name: "acme/app", pr_number: 4, head_sha: "abcdef012", status: "dead", attempts: 4, max_attempts: 4, last_error: "scan_failed: The scan could not be completed.", result: null, updated_at: new Date().toISOString(), ...over });
const overview = (attention: unknown[] = [], counts = { queued: 0, running: 1, succeeded: 12, failed: 0, dead: attention.length }) => ({ set_up: true, counts, attention, recent: [] });

beforeEach(() => authedFetch.mockReset());

it("shows the week's counts and the reason a scan failed", async () => {
  authedFetch.mockResolvedValue(overview([job({})]));
  render(<ScanQueue />);
  expect(await screen.findByText(/scan_failed: The scan could not be completed/)).toBeTruthy();
  expect(screen.getByText(/attempt 4 of 4/)).toBeTruthy();
  expect(screen.getByText("12")).toBeTruthy();
  expect(screen.getByText("abcdef0")).toBeTruthy();
});

it("says so when nothing needs attention", async () => {
  authedFetch.mockResolvedValue(overview([]));
  render(<ScanQueue />);
  expect(await screen.findByText(/Nothing needs attention/)).toBeTruthy();
});

it("replay sends the job's id and refreshes", async () => {
  authedFetch.mockImplementation(async (_u: string, init?: { method?: string }) => (init?.method === "POST" ? { ok: true } : overview([job({})])));
  render(<ScanQueue />);
  fireEvent.click(await screen.findByRole("button", { name: "Replay" }));
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/scan-jobs", expect.objectContaining({ method: "POST", body: JSON.stringify({ id: "j1" }) })));
  expect(await screen.findByText(/Queued acme\/app #4 again/)).toBeTruthy();
});

it("a job that is still waiting or running has no replay button", async () => {
  authedFetch.mockResolvedValue(overview([job({ status: "queued", attempts: 0, last_error: null })], { queued: 1, running: 0, succeeded: 0, failed: 0, dead: 0 }));
  render(<ScanQueue />);
  expect(await screen.findByText(/Waiting · attempt/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Replay" })).toBeNull();
});

it("shows the server's reason when a replay is refused", async () => {
  authedFetch.mockImplementation(async (_u: string, init?: { method?: string }) => { if (init?.method === "POST") throw new Error("Plan limit reached: 3 of 3 scans used this month"); return overview([job({})]); });
  render(<ScanQueue />);
  fireEvent.click(await screen.findByRole("button", { name: "Replay" }));
  expect(await screen.findByText(/Plan limit reached/)).toBeTruthy();
});

it("tells you when the database update is missing", async () => {
  authedFetch.mockResolvedValue({ set_up: false, counts: {}, attention: [], recent: [] });
  render(<ScanQueue />);
  expect(await screen.findByText(/needs a database update/)).toBeTruthy();
});
