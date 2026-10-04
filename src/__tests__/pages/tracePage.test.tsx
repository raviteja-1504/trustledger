/**
 * Trace page: health tiles, timelines, search, and the "migration not run yet" notice.
 */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));
jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));

import TracePage from "@/app/trace/page";

const health = (over = {}) => ({ stuck_scans: [{ trace_id: "s1", repo: "o/api", pr_number: 9, minutes: 40 }], undelivered_webhooks: [], failed_scans_24h: 2, api_errors_24h: 0, completed_scans_24h: 5, events_available: true, ...over });
const trace = {
  trace_id: "0f0e7a5c-1111", status: "failed", repo: "o/api", pr_number: 7, scan_id: null, started_at: new Date().toISOString(), last_at: new Date().toISOString(),
  events: [
    { id: 1, created_at: new Date().toISOString(), trace_id: "0f0e7a5c-1111", kind: "scan.started", level: "info", message: null, scan_id: null, delivery_id: null, repo: "o/api", pr_number: 7, ref_id: null, duration_ms: null, data: {} },
    { id: 2, created_at: new Date().toISOString(), trace_id: "0f0e7a5c-1111", kind: "scan.failed", level: "error", message: "GitHub returned 502", scan_id: null, delivery_id: null, repo: "o/api", pr_number: 7, ref_id: null, duration_ms: 4200, data: { head_sha: "abc" } },
  ],
};

beforeEach(() => { authedFetch.mockReset(); });

it("shows pipeline health and recent traces", async () => {
  authedFetch.mockResolvedValue({ health: health(), traces: [trace] });
  render(<TracePage />);
  expect(await screen.findByText("Stuck scans")).toBeInTheDocument();
  expect(screen.getByText("Failed scans").nextSibling).toHaveTextContent("2");
  expect(screen.getByText("o/api #7")).toBeInTheDocument();
  expect(authedFetch).toHaveBeenCalledWith("/api/ops/trace");
});

it("searching opens the matching trace's timeline", async () => {
  authedFetch.mockResolvedValue({ health: health(), traces: [trace] });
  render(<TracePage />);
  await screen.findByText("o/api #7");
  fireEvent.change(screen.getByLabelText("Search traces"), { target: { value: "o/api#7" } });
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/ops/trace?q=o%2Fapi%237"));
  expect(await screen.findByText("Scan failed")).toBeInTheDocument();
  expect(screen.getByText(/GitHub returned 502/)).toBeInTheDocument();
  expect(screen.getByText("4.2 s")).toBeInTheDocument();
});

it("says when step-by-step events aren't being stored yet", async () => {
  authedFetch.mockResolvedValue({ health: health({ events_available: false, stuck_scans: [] }), traces: [] });
  render(<TracePage />);
  expect(await screen.findByText(/run the/)).toHaveTextContent("20261004_ops_events.sql");
});
