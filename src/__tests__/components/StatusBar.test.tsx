/**
 * The status bar's API indicator: labels, re-checking soon while offline, and re-checking at once when the
 * browser's connection comes back.
 */
import React from "react";
import { act, render, screen } from "@testing-library/react";

let next: Array<"online" | "offline" | "no-network"> = [];
const probeApi = jest.fn(async () => next.shift() ?? "online");
jest.mock("@/lib/apiHealth", () => ({
  ...jest.requireActual("@/lib/apiHealth"),
  probeApi: () => probeApi(),
}));
jest.mock("@/lib/sidebar", () => ({ useSidebar: () => ({ collapsed: false }) }));
jest.mock("next/navigation", () => ({ usePathname: () => "/reports" }));

import StatusBar from "@/components/StatusBar";
import { RECHECK_OFFLINE_MS } from "@/lib/apiHealth";

beforeEach(() => { jest.useFakeTimers(); probeApi.mockClear(); next = []; });
afterEach(() => jest.useRealTimers());
const flush = () => act(async () => { await Promise.resolve(); await Promise.resolve(); });

describe("StatusBar", () => {
  it("shows the API as online, and the viewer's lost connection as their own", async () => {
    next = ["online"];
    const { unmount } = render(<StatusBar />);
    await flush();
    expect(screen.getByRole("status")).toHaveTextContent("API online");
    unmount();
    next = ["no-network"];
    render(<StatusBar />);
    await flush();
    expect(screen.getByRole("status")).toHaveTextContent("You're offline");
  });

  it("while offline it re-checks in 30 seconds, and turns green when the API answers", async () => {
    next = ["offline", "online"];
    render(<StatusBar />);
    await flush();
    expect(screen.getByRole("status")).toHaveTextContent("API offline");
    await act(async () => { jest.advanceTimersByTime(RECHECK_OFFLINE_MS); });
    await flush();
    expect(probeApi).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("status")).toHaveTextContent("API online");
  });

  it("the connection coming back re-checks at once", async () => {
    next = ["no-network", "online"];
    render(<StatusBar />);
    await flush();
    await act(async () => { window.dispatchEvent(new Event("online")); });
    await flush();
    expect(screen.getByRole("status")).toHaveTextContent("API online");
  });

  it("the report link stays on TrustLedger", async () => {
    render(<StatusBar />);
    await flush();
    expect(screen.getByTitle("Report an issue")).toHaveAttribute("href", "/security");
  });
});
