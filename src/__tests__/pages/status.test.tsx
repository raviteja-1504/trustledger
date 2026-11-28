/**
 * @jest-environment jsdom
 *
 * The public status page shows only real checks (no hard-coded "operational" rows) and the operator's notices.
 */
import React from "react";
import { render, screen } from "@testing-library/react";

import StatusPage from "@/app/status/page";

const realFetch = global.fetch;
const json = (body: unknown, ok = true) => Promise.resolve({ ok, json: async () => body } as Response);
function mockNetwork(opts: { health?: unknown; status?: unknown; statusFails?: boolean }) {
  global.fetch = jest.fn((url: string) => {
    if (url === "/healthz") return json(opts.health ?? { status: "ok", db: "connected" });
    if (url === "/api/status") return opts.statusFails ? Promise.reject(new Error("down")) : json(opts.status ?? { components: [], notices: [] });
    return json({}, true);                                       // api.github.com/zen
  }) as unknown as typeof fetch;
}
afterEach(() => { global.fetch = realFetch; });

it("shows the real component states from /api/status, and nothing it did not check", async () => {
  mockNetwork({ status: { components: [
    { key: "database", name: "Database", state: "operational" }, { key: "scans", name: "Scanning", state: "degraded" },
    { key: "audit_log", name: "Audit log", state: "operational" }, { key: "webhooks", name: "Outbound webhooks", state: "operational" },
  ], notices: [] } });
  render(<StatusPage />);
  expect(await screen.findByText("Scanning")).toBeTruthy();
  expect(screen.getByText("Audit log")).toBeTruthy();
  expect(screen.getByText("Outbound webhooks")).toBeTruthy();
  for (const fake of ["PDF Generator", "Alert Delivery", "SLA Monitor (Cron)", "Webhook Receiver"]) expect(screen.queryByText(fake)).toBeNull();
  expect(await screen.findByText("Some systems degraded")).toBeTruthy();
});

it("shows the operator's open notice above the components, and a resolved one as resolved", async () => {
  mockNetwork({ status: { components: [], notices: [
    { id: "n1", severity: "outage", title: "Scans are delayed", body: "We are investigating.", started_at: "2026-11-29T10:00:00Z", resolved_at: null },
    { id: "n2", severity: "degraded", title: "Slow exports", body: "", started_at: "2026-11-27T10:00:00Z", resolved_at: "2026-11-27T12:00:00Z" },
  ] } });
  render(<StatusPage />);
  expect(await screen.findByText(/Scans are delayed/)).toBeTruthy();
  expect(screen.getByText("We are investigating.")).toBeTruthy();
  expect(screen.getByText("Outage")).toBeTruthy();
  expect(screen.getAllByText("Resolved").length).toBe(1);
  expect(await screen.findByText("Some systems degraded")).toBeTruthy();       // an open outage notice means not "all operational"
});

it("when the platform's own status cannot be read, it says so instead of claiming everything is fine", async () => {
  mockNetwork({ statusFails: true });
  render(<StatusPage />);
  expect(await screen.findByText(/could not be read/)).toBeTruthy();
  expect(await screen.findByText("Some systems degraded")).toBeTruthy();
});
