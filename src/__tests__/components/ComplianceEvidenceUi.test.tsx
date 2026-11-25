/**
 * UI for Tasks 3/5/11/12: audit checkpoints (Audit Trail page), control owners and gaps (Compliance page),
 * and the attestation signature check (PR page). Each says what the backend found, in plain words, and never claims
 * more than the evidence shows.
 */
import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

type Call = { url: string; method: string; body?: unknown };
const calls: Call[] = [];
let handler: (c: Call) => unknown = () => { throw new Error("no handler"); };
jest.mock("@/lib/useRealData", () => ({
  getAuthHeader: async () => ({ Authorization: "Bearer t" }),
  authedFetch: jest.fn(async (url: string, init?: { method?: string; body?: string }) => {
    const c: Call = { url, method: init?.method ?? "GET", body: init?.body ? JSON.parse(init.body) : undefined };
    calls.push(c);
    return handler(c);
  }),
}));

import AuditCheckpoints from "@/components/AuditCheckpoints";
import ControlGaps from "@/components/ControlGaps";
import AttestationProof from "@/components/AttestationProof";

beforeEach(() => { calls.length = 0; });

// ── Audit checkpoints ─────────────────────────────────────────────────────────────────────────────────────

const cp = (sequence: number, entry_count: number) => ({
  payload: { schema_version: 1, org_id: "o", sequence, entry_count, last_entry_id: entry_count, last_entry_hash: "h", first_entry_hash: "f", prev_checkpoint_hash: null, created_at: "2026-11-20T10:00:00.000Z", key_id: "11111111-2222-3333-4444-555555555555" },
  payload_hash: "abcdef0123456789abcdef", signature: "sig",
});
const verification = (status: string, over: Record<string, unknown> = {}) => ({
  status, checkpoints: 2, latest_sequence: 2, latest_at: "2026-11-20T10:00:00.000Z", unanchored_entries: 0, problems: [],
  chain: { status: "VALID", valid: true, total: 9, verified: 9, legacy: 0, concurrent: 0, first_at: null, last_at: null }, ...over,
});

describe("AuditCheckpoints", () => {
  it("fetches nothing until asked", () => {
    handler = () => { throw new Error("should not be called"); };
    render(<AuditCheckpoints />);
    expect(calls).toEqual([]);
    expect(screen.getByRole("button", { name: "Check against checkpoints" })).toBeInTheDocument();
  });

  it("a clean log reports what it matched, lists the latest checkpoints, and says what checkpoints cannot prove", async () => {
    handler = () => ({ verification: verification("VALID", { unanchored_entries: 3 }), checkpoints: [cp(1, 4), cp(2, 9)] });
    render(<AuditCheckpoints />);
    fireEvent.click(screen.getByRole("button", { name: "Check against checkpoints" }));
    const status = await screen.findByText("Matches every checkpoint.");
    expect(status.closest("[role=status]")).toHaveTextContent("2 signed checkpoints");
    expect(status.closest("[role=status]")).toHaveTextContent("3 newer entries are not covered");
    const rows = screen.getAllByRole("row");
    expect(within(rows[1]).getByText("2")).toBeInTheDocument();          // newest first
    expect(document.body.textContent).toMatch(/can.t prove the database itself wasn.t rewritten/);
    expect(document.body.textContent).toMatch(/verify-audit-bundle\.cjs/);
  });

  it("missing entries are reported as such, with the reason for each problem", async () => {
    handler = () => ({ verification: verification("TRUNCATED", { problems: [{ sequence: 2, code: "truncated", detail: "chain holds 7 entries, checkpoint recorded 10" }] }), checkpoints: [cp(1, 4), cp(2, 10)] });
    render(<AuditCheckpoints />);
    fireEvent.click(screen.getByRole("button", { name: "Check against checkpoints" }));
    expect(await screen.findByText("Entries are missing.")).toBeInTheDocument();
    expect(screen.getByText(/Checkpoint #2: chain holds 7 entries, checkpoint recorded 10/)).toBeInTheDocument();
  });

  it.each([
    ["HISTORY_MODIFIED", "History has changed."],
    ["CHECKPOINT_INVALID", "A checkpoint does not verify."],
    ["KEY_UNTRUSTED", "Signed by an untrusted key."],
    ["NO_CHECKPOINTS", "No checkpoints yet."],
  ])("%s has its own wording", async (status, title) => {
    handler = () => ({ verification: verification(status, { checkpoints: 0, latest_sequence: null }), checkpoints: [] });
    render(<AuditCheckpoints />);
    fireEvent.click(screen.getByRole("button", { name: "Check against checkpoints" }));
    expect(await screen.findByText(title)).toBeInTheDocument();
  });

  it("shows an error, not a verdict, when the check cannot run", async () => {
    handler = () => { throw new Error("boom"); };
    render(<AuditCheckpoints />);
    fireEvent.click(screen.getByRole("button", { name: "Check against checkpoints" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("couldn't run");
    expect(screen.queryByText(/Matches every checkpoint/)).not.toBeInTheDocument();
  });

  it("recording a checkpoint says what was covered and where the copy lives, then re-checks", async () => {
    handler = c => c.method === "POST"
      ? { created: true, checkpoint: cp(3, 12), external: "not_configured" }
      : { verification: verification("VALID"), checkpoints: [cp(3, 12)] };
    render(<AuditCheckpoints />);
    fireEvent.click(screen.getByRole("button", { name: "Record a checkpoint" }));
    expect(await screen.findByText(/Checkpoint #3 recorded, covering 12 entries/)).toBeInTheDocument();
    expect(screen.getByText(/the only copy is in TrustLedger's database/)).toBeInTheDocument();
    await waitFor(() => expect(calls.map(c => c.method)).toEqual(["POST", "GET"]));
  });

  it.each([
    [{ created: false, reason: "unchanged" }, /Nothing new since the last checkpoint/],
    [{ created: false, reason: "no_signing_key" }, /no signing key configured/],
    [{ created: false, reason: "no_entries" }, /no audit entries/],
    [{ created: false, reason: "verification_failed", status: "TRUNCATED" }, /already fails verification \(Entries are missing\).*must not vouch/],
  ])("explains why no checkpoint was recorded: %j", async (resp, text) => {
    handler = c => (c.method === "POST" ? resp : { verification: verification("VALID"), checkpoints: [] });
    render(<AuditCheckpoints />);
    fireEvent.click(screen.getByRole("button", { name: "Record a checkpoint" }));
    expect(await screen.findByText(text)).toBeInTheDocument();
  });

  it("downloads the bundle with the user's credentials", async () => {
    const fetchMock = jest.fn(async () => ({ ok: true, blob: async () => new Blob(["{}"]) }));
    const realFetch = global.fetch; global.fetch = fetchMock as unknown as typeof fetch;
    (URL as unknown as { createObjectURL: () => string }).createObjectURL = () => "blob:x";
    (URL as unknown as { revokeObjectURL: () => void }).revokeObjectURL = () => {};
    const click = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    try {
      render(<AuditCheckpoints />);
      fireEvent.click(screen.getByRole("button", { name: "Download bundle" }));
      await waitFor(() => expect(click).toHaveBeenCalled());
      expect(fetchMock).toHaveBeenCalledWith("/api/audit/checkpoints?bundle=1", { headers: { Authorization: "Bearer t" } });
    } finally { global.fetch = realFetch; click.mockRestore(); }
  });
});

// ── Control owners and gaps ───────────────────────────────────────────────────────────────────────────────

const control = (over: Record<string, unknown> = {}) => ({
  control_id: "CC8.1", control_name: "Changes are reviewed before release", status: "partial", owner: "ana@acme.dev",
  gaps: [{ evidence_type: "pr_approval", kind: "missing" }, { evidence_type: "security_scan", kind: "unverified" }],
  remediations: [{ id: "e1", title: "Collect PR approvals", status: "in-progress", owner_email: "ana@acme.dev", due_date: "2026-01-05", risk_accepted: false, overdue: true }],
  flags: ["remediation_overdue"], ...over,
});
const report = (controls: unknown[]) => ({
  framework_id: "soc2", mapping_version: "1.0", scope_disclaimer: "Technical evidence only; an assessor tests the rest.",
  summary: { controls: controls.length, with_gaps: 1, unowned: 1, untracked_gaps: 1, overdue: 1, resolved_but_gap_remains: 0 }, controls,
});
const gapsPanel = (props: Partial<React.ComponentProps<typeof ControlGaps>> = {}) =>
  render(<ControlGaps framework="soc2" frameworkName="SOC 2" color="#6366f1" members={["ana@acme.dev", "bo@acme.dev"]} canEdit canExport {...props} />);

describe("ControlGaps", () => {
  const twoControls = () => report([control(), control({ control_id: "CC6.1", control_name: "Access is restricted", status: "missing", owner: null, gaps: [{ evidence_type: "access_control_event", kind: "expired" }], remediations: [], flags: ["no_owner", "gap_untracked"] })]);

  it("shows each control's gaps, owner and remediation, and is explicit that this is not a compliance verdict", async () => {
    handler = () => twoControls();
    gapsPanel();
    expect(await screen.findByRole("article", { name: "Control CC8.1" })).toBeInTheDocument();
    expect(calls[0].url).toBe("/api/evidence/gaps?framework=soc2");
    expect(screen.getByRole("note")).toHaveTextContent("This is not a compliance verdict");
    expect(screen.getByRole("note")).toHaveTextContent("Technical evidence only");
    const cc81 = within(screen.getByRole("article", { name: "Control CC8.1" }));
    expect(cc81.getByText("PR approval: missing")).toBeInTheDocument();
    expect(cc81.getByText("Security scan: failed verification")).toBeInTheDocument();
    expect(cc81.getByText("Remediation overdue")).toBeInTheDocument();
    expect(cc81.getByText("Collect PR approvals")).toBeInTheDocument();
    expect(cc81.getByText(/in progress · ana@acme.dev · due 5 Jan 2026/)).toHaveTextContent("overdue");
    const cc61 = within(screen.getByRole("article", { name: "Control CC6.1" }));
    expect(cc61.getByText("Gap nobody is working on")).toBeInTheDocument();
    expect(cc61.getByText("Access control event: expired")).toBeInTheDocument();
    expect(cc61.getByLabelText("Owner")).toHaveValue("");
    expect(screen.getByLabelText("Summary")).toHaveTextContent("Gaps nobody is working on1");
  });

  it("assigns an owner, then reloads", async () => {
    handler = c => (c.method === "PUT" ? { ok: true } : twoControls());
    gapsPanel();
    const owner = await screen.findAllByLabelText("Owner");
    fireEvent.change(owner[1], { target: { value: "bo@acme.dev" } });
    await waitFor(() => expect(calls.find(c => c.method === "PUT")).toMatchObject({ url: "/api/evidence/controls", body: { framework: "soc2", control_id: "CC6.1", owner_email: "bo@acme.dev" } }));
    await waitFor(() => expect(calls.filter(c => c.method === "GET")).toHaveLength(2));
  });

  it("unassigning removes the owner", async () => {
    handler = c => (c.method === "DELETE" ? { ok: true } : twoControls());
    gapsPanel();
    const owner = await screen.findAllByLabelText("Owner");
    fireEvent.change(owner[0], { target: { value: "" } });
    await waitFor(() => expect(calls.find(c => c.method === "DELETE")?.url).toBe("/api/evidence/controls?framework=soc2&control_id=CC8.1"));
  });

  it("shows the server's reason when an owner cannot be saved", async () => {
    handler = c => { if (c.method === "PUT") throw new Error("The owner must be a member of this organisation."); return twoControls(); };
    gapsPanel();
    fireEvent.change((await screen.findAllByLabelText("Owner"))[1], { target: { value: "bo@acme.dev" } });
    expect(await screen.findByRole("alert")).toHaveTextContent("must be a member");
  });

  it("without edit rights, owners are text and the export button is hidden", async () => {
    handler = () => twoControls();
    gapsPanel({ canEdit: false, canExport: false });
    await screen.findByRole("article", { name: "Control CC8.1" });
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.getByText("ana@acme.dev", { selector: "span" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /auditor export/ })).not.toBeInTheDocument();
  });

  it("offers a retry when the report cannot be loaded", async () => {
    let fail = true;
    handler = () => { if (fail) throw new Error("x"); return twoControls(); };
    gapsPanel();
    expect(await screen.findByText(/Couldn't load owners and gaps/)).toBeInTheDocument();
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("article", { name: "Control CC8.1" })).toBeInTheDocument();
  });

  it("reloads for another framework", async () => {
    handler = () => twoControls();
    const { rerender } = gapsPanel();
    await screen.findByRole("article", { name: "Control CC8.1" });
    rerender(<ControlGaps framework="iso27001" frameworkName="ISO 27001" color="#8b5cf6" members={[]} canEdit canExport />);
    await waitFor(() => expect(calls.map(c => c.url)).toContain("/api/evidence/gaps?framework=iso27001"));
  });
});

// ── Attestation signature check ───────────────────────────────────────────────────────────────────────────

describe("AttestationProof", () => {
  const ask = async (resp: Record<string, unknown>) => {
    handler = () => ({ has_signature: true, is_inherited: false, ...resp });
    render(<AttestationProof attestationId="att-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Check signature" }));
    return screen.findByRole("status");
  };

  it("fetches nothing until asked, then asks about that attestation", async () => {
    handler = () => ({ verify_result: "valid", has_signature: true, is_inherited: false });
    render(<AttestationProof attestationId="att 1&x" />);
    expect(calls).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Check signature" }));
    await screen.findByRole("status");
    expect(calls[0].url).toBe("/api/attest/verify?id=att%201%26x");
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();
  });

  it.each([
    ["valid", /Signature valid\./],
    ["key_retired", /key that signed it has since been retired.*signature itself still checks out/],
    ["key_revoked", /revoked key.*Do not rely/],
    ["invalid", /may have been altered/],
    ["payload_db_mismatch", /describes a different attestation/],
    ["no_signature", /before signing was switched on/],
    ["inherited_content_changed", /file's content has changed since/],
    ["inherited_source_not_found", /can no longer be found/],
    ["key_not_found", /key that signed this record can't be found/],
    ["payload_schema_invalid", /malformed/],
  ])("%s is explained", async (result, text) => {
    expect(await ask({ verify_result: result })).toHaveTextContent(text);
  });

  it("a carried-over approval that still verifies says so, rather than claiming a fresh signature", async () => {
    const s = await ask({ verify_result: "valid", is_inherited: true, has_signature: false });
    expect(s).toHaveTextContent("Carried over from an earlier review; original signature valid");
    expect(s).toHaveTextContent("content is unchanged");
  });

  it("an unrecognised result is shown as such, not as success", async () => {
    const s = await ask({ verify_result: "something_new" });
    expect(s).toHaveTextContent("Unrecognised result");
    expect(s).not.toHaveTextContent("Signature valid");
  });

  it("an error is not a verdict", async () => {
    handler = () => { throw new Error("x"); };
    render(<AttestationProof attestationId="att-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Check signature" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("couldn't run");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
