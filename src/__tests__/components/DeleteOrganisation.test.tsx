/**
 * @jest-environment jsdom
 *
 * The settings panel for deleting the organisation walks through the server's steps and never offers the final delete before
 * the waiting period is over.
 */
import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const authedFetch = jest.fn();
jest.mock("@/lib/useRealData", () => ({ authedFetch: (...a: unknown[]) => authedFetch(...a) }));
jest.mock("next/link", () => ({ __esModule: true, default: ({ href, children }: { href: string; children: React.ReactNode }) => <a href={href}>{children}</a> }));

import DeleteOrganisation from "@/components/settings/DeleteOrganisation";

const preview = {
  deleted: [{ key: "members", label: "Members", count: 3 }, { key: "scans", label: "Scans", count: 42 }],
  retained: [{ key: "audit_log", label: "Audit log entries", count: 900 }],
  exports: [{ label: "Audit log (signed export)", href: "/audit" }],
};
const base = { organization: { name: "Acme", slug: "acme" }, preview, delay_hours: 24, step_up: "recent_signin" as const };
const load = (state: Record<string, unknown>) => authedFetch.mockImplementation(async (url: string, init?: { method?: string }) => (init?.method === "POST" ? { ok: true } : { ...base, ...state }));

beforeEach(() => authedFetch.mockReset());

it("shows what is deleted and what is kept, and a link to take a copy first", async () => {
  load({ request: null });
  render(<DeleteOrganisation />);
  expect(await screen.findByText("Scans:")).toBeTruthy();
  expect(screen.getByText("42")).toBeTruthy();
  expect(screen.getByText(/Kept, as evidence/)).toBeTruthy();
  expect(screen.getByText("Audit log (signed export)").getAttribute("href")).toBe("/audit");
});

it("requesting needs the organisation's name typed, and says how long the wait is", async () => {
  load({ request: null });
  render(<DeleteOrganisation />);
  const button = await screen.findByRole("button", { name: "Request deletion" });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText(/24-hour/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "acme" } });
  expect((button as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(button);
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/orgs/delete", expect.objectContaining({ method: "POST", body: JSON.stringify({ action: "request", confirm: "acme" }) })));
});

it("asks for the authenticator code when two-factor is on, and sends it", async () => {
  load({ request: null, step_up: "totp" });
  render(<DeleteOrganisation />);
  fireEvent.change(await screen.findByLabelText(/to confirm/), { target: { value: "acme" } });
  fireEvent.change(screen.getByLabelText(/Authenticator code/), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Request deletion" }));
  await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/orgs/delete", expect.objectContaining({ body: JSON.stringify({ action: "request", confirm: "acme", code: "123456" }) })));
});

it("during the waiting period the final delete is not offered, but cancel is", async () => {
  load({ request: { id: "r", status: "pending", execute_after: new Date(Date.now() + 3600_000).toISOString(), error: null, requested_by_email: "a@acme.io" } });
  render(<DeleteOrganisation />);
  expect(await screen.findByText(/cannot run before/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /Delete the organisation permanently/ })).toBeNull();
  expect(screen.getByRole("button", { name: "Cancel deletion" })).toBeTruthy();
});

it("after the waiting period the final delete appears, still needing the name", async () => {
  load({ request: { id: "r", status: "pending", execute_after: new Date(Date.now() - 1000).toISOString(), error: null, requested_by_email: null } });
  render(<DeleteOrganisation />);
  const del = await screen.findByRole("button", { name: /Delete the organisation permanently/ });
  expect((del as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "acme" } });
  expect((del as HTMLButtonElement).disabled).toBe(false);
});

it("a failed run says nothing was deleted and offers to run again or cancel", async () => {
  load({ request: { id: "r", status: "failed", execute_after: new Date(Date.now() - 1000).toISOString(), error: "org_delete_blocked: scans", requested_by_email: null } });
  render(<DeleteOrganisation />);
  expect(await screen.findByText(/nothing was deleted/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Cancel deletion" })).toBeTruthy();
  expect(screen.getByRole("button", { name: /Delete the organisation permanently/ })).toBeTruthy();
});

it("a running deletion cannot be cancelled", async () => {
  load({ request: { id: "r", status: "executing", execute_after: new Date(Date.now() - 1000).toISOString(), error: null, requested_by_email: null } });
  render(<DeleteOrganisation />);
  expect(await screen.findByText(/Deletion is running/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Cancel deletion" })).toBeNull();
});

it("shows the server's reason when a step is refused", async () => {
  authedFetch.mockImplementation(async (_u: string, init?: { method?: string }) => {
    if (init?.method === "POST") throw new Error("For your security, sign out and sign in again.");
    return { ...base, request: null };
  });
  render(<DeleteOrganisation />);
  fireEvent.change(await screen.findByLabelText(/to confirm/), { target: { value: "acme" } });
  fireEvent.click(screen.getByRole("button", { name: "Request deletion" }));
  expect(await screen.findByText(/sign out and sign in again/)).toBeTruthy();
});
