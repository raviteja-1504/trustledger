/**
 * Dashboard New Scan panel: real repositories only, real open PRs, waits for the queued scan and opens it.
 */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

const push = jest.fn();
jest.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: jest.fn() }), usePathname: () => "/dashboard" }));
const authedFetch = jest.fn();
let seed = false;
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a), isSeedMode: () => seed }));
const scan = jest.fn();
jest.mock("@/lib/api", () => ({ api: { scan: (...a: unknown[]) => scan(...a) } }));

import NewScanPanel from "@/components/NewScanPanel";

const pulls = [
  { number: 12, title: "Add refunds", author: "ana", branch: "feat/refunds", head_sha: "abc123def456", draft: false, updated_at: new Date().toISOString() },
  { number: 9, title: "Fix typo", author: "raj", branch: "fix/typo", head_sha: "999", draft: true, updated_at: new Date().toISOString() },
];

function backend(over: Partial<Record<string, (init?: RequestInit) => unknown>> = {}) {
  authedFetch.mockImplementation(async (path: string, init?: RequestInit) => {
    const key = path.split("?")[0] + (init?.method === "POST" ? ":POST" : "");
    if (over[key]) return over[key]!(init);
    if (key === "/api/repos") return { repos: [{ repo_full_name: "namacorp/billing", is_active: true }, { repo_full_name: "namacorp/web", is_active: true }] };
    if (key === "/api/repos/pulls") return { pulls };
    if (key === "/api/scans/pr:POST") return { status: "queued", repo: "namacorp/billing", pr_number: 12, head_sha: "abc123def456" };
    if (key === "/api/scans") return { scans: [] };
    throw new Error("unexpected " + key);
  });
}

beforeEach(() => { jest.clearAllMocks(); jest.useRealTimers(); seed = false; backend(); });

it("offers only the org's connected repositories — no sample repos, no pre-filled PR", async () => {
  render(<NewScanPanel open onClose={() => {}} />);
  const select = await screen.findByLabelText("Repository") as HTMLSelectElement;
  expect([...select.options].map(o => o.value)).toEqual(["namacorp/billing", "namacorp/web"]);
  expect(screen.queryByText(/payments-api/)).not.toBeInTheDocument();
  expect(screen.queryByDisplayValue("50")).not.toBeInTheDocument();
});

it("lists the repository's open pull requests from GitHub and reloads them for another repo", async () => {
  render(<NewScanPanel open onClose={() => {}} />);
  expect(await screen.findByRole("radio", { name: /Add refunds/ })).toBeInTheDocument();
  expect(screen.getByRole("radio", { name: /Fix typo/ })).toBeInTheDocument();
  expect(authedFetch).toHaveBeenCalledWith("/api/repos/pulls?repo=namacorp%2Fbilling");
  fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "namacorp/web" } });
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/repos/pulls?repo=namacorp%2Fweb"));
});

it("scans the chosen PR, waits for its result and opens it", async () => {
  let polls = 0;
  backend({
    "/api/scans": () => ({ scans: ++polls < 2 ? [] : [
      { scan_id: "older", pr_number: 12, commit_sha: "0ld" },
      { scan_id: "scan-new", pr_number: 12, commit_sha: "abc123def456" },
    ] }),
  });
  render(<NewScanPanel open onClose={() => {}} />);
  await screen.findByRole("radio", { name: /Add refunds/ });
  jest.useFakeTimers();
  fireEvent.click(screen.getByRole("button", { name: "Scan PR #12" }));
  await waitFor(() => expect(screen.getByText(/Scanning namacorp\/billing #12/)).toBeInTheDocument());
  expect(authedFetch).toHaveBeenCalledWith("/api/scans/pr", { method: "POST", body: JSON.stringify({ repo: "namacorp/billing", pr_number: 12, force: false }) });
  for (let i = 0; i < 3 && !push.mock.calls.length; i++) { await act(async () => { jest.advanceTimersByTime(3000); }); }
  expect(push).toHaveBeenCalledWith("/pr/scan-new");
});

it("a PR already scanned at its latest commit: open it, or scan it again", async () => {
  backend({ "/api/scans/pr:POST": () => ({ status: "already_scanned", scan_id: "scan-old", repo: "namacorp/billing", pr_number: 12, head_sha: "abc123def456" }) });
  render(<NewScanPanel open onClose={() => {}} />);
  await screen.findByRole("radio", { name: /Add refunds/ });
  fireEvent.click(screen.getByRole("button", { name: "Scan PR #12" }));
  fireEvent.click(await screen.findByRole("button", { name: "Open scan" }));
  expect(push).toHaveBeenCalledWith("/pr/scan-old");

  backend({ "/api/scans/pr:POST": (init) => (JSON.parse(String(init?.body)).force
    ? { status: "queued", repo: "namacorp/billing", pr_number: 12, head_sha: "abc123def456" }
    : { status: "already_scanned", scan_id: "scan-old", repo: "namacorp/billing", pr_number: 12, head_sha: "abc123def456" }) });
  fireEvent.click(screen.getByRole("button", { name: "Scan again" }));
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/scans/pr", expect.objectContaining({ body: JSON.stringify({ repo: "namacorp/billing", pr_number: 12, force: true }) })));
});

it("shows the server's reason when a scan can't start", async () => {
  backend({ "/api/scans/pr:POST": () => { throw new Error("This PR was scanned less than a minute ago. Try again shortly."); } });
  render(<NewScanPanel open onClose={() => {}} />);
  await screen.findByRole("radio", { name: /Add refunds/ });
  fireEvent.click(screen.getByRole("button", { name: "Scan PR #12" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("less than a minute ago");
});

it("with no connected repositories, explains how to connect one instead of offering fake ones", async () => {
  backend({ "/api/repos": () => ({ repos: [] }) });
  render(<NewScanPanel open onClose={() => {}} />);
  expect(await screen.findByText("No repositories connected yet")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Settings → Repositories/ })).toHaveAttribute("href", "/settings?tab=repositories");
  expect(screen.getByRole("button", { name: "Scan PR" })).toBeDisabled();
});

it("pasted code is scanned against a connected repo, with no PR unless one is given", async () => {
  scan.mockResolvedValue({ scan_id: "paste-1" });
  render(<NewScanPanel open onClose={() => {}} />);
  await screen.findByLabelText("Repository");
  fireEvent.click(screen.getByRole("tab", { name: "Paste code" }));
  fireEvent.click(screen.getByText("SQL Injection"));
  fireEvent.click(screen.getByRole("button", { name: "Scan 1 file" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith("/pr/paste-1"));
  const body = scan.mock.calls[0][0];
  expect(body).toMatchObject({ repo: "namacorp/billing", pr_number: 0 });
  expect(body.files[0].path).toBe("src/db/users.ts");
  expect(body.commit_sha).toMatch(/^[0-9a-f]{40}$/);
});

it("demo mode offers paste mode only, on sample repositories", async () => {
  seed = true;
  render(<NewScanPanel open onClose={() => {}} />);
  expect(screen.getByRole("tab", { name: "Pull request" })).toBeDisabled();
  expect(screen.getByRole("tab", { name: "Paste code" })).toHaveAttribute("aria-selected", "true");
  expect(authedFetch).not.toHaveBeenCalled();
});
