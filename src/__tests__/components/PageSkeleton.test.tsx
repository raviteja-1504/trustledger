/**
 * Loading states that say they're loading (components/PageSkeleton.tsx, components/Loading.tsx, lib/netActivity.ts):
 * the skeleton stays for as long as data is loading -- not a fixed 80 ms -- and names what's loading; the top bar
 * says "Loading…" / "Refreshing…" while any request is in flight.
 */
import React from "react";
import { act, render, screen } from "@testing-library/react";
import PageSkeleton from "@/components/PageSkeleton";
import { ACTIVITY_DELAY_MS, LoadingBlock, NetworkActivity } from "@/components/Loading";
import { __resetNetActivity, getInFlight, subscribe, track } from "@/lib/netActivity";

describe("PageSkeleton", () => {
  it("while loading: 'Loading {label}…' and no page content, however long it takes", () => {
    jest.useFakeTimers();
    render(<PageSkeleton loading label="violations"><p>Page content</p></PageSkeleton>);
    act(() => { jest.advanceTimersByTime(10_000); });
    expect(screen.getByRole("status", { name: "Loading violations" })).toHaveTextContent("Loading violations…");
    expect(screen.queryByText("Page content")).toBeNull();
    jest.useRealTimers();
  });

  it("once loaded: the page, at once", () => {
    render(<PageSkeleton loading={false} label="violations"><p>Page content</p></PageSkeleton>);
    expect(screen.getByText("Page content")).toBeInTheDocument();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("the skeleton follows the requested shape", () => {
    const { container } = render(<LoadingBlock label="x" rows={3} cards={2} />);
    expect(container.querySelectorAll(".section-card > div")).toHaveLength(3);
    expect(container.querySelectorAll(".grid > div")).toHaveLength(2);
  });
});

describe("netActivity", () => {
  beforeEach(() => __resetNetActivity());

  it("counts requests in flight until they settle, success or failure", async () => {
    const seen: number[] = [];
    subscribe(n => seen.push(n));
    let ok!: (v: number) => void, fail!: (e: Error) => void;
    const a = track(new Promise<number>(r => { ok = r; }));
    const b = track(new Promise<number>((_, r) => { fail = r; }));
    expect(getInFlight()).toBe(2);
    ok(1); await a;
    fail(new Error("x")); await b.catch(() => {});
    expect(getInFlight()).toBe(0);
    expect(seen).toEqual([1, 2, 1, 0]);
  });

  it("track hands back the same promise", async () => {
    await expect(track(Promise.resolve(7))).resolves.toBe(7);
  });
});

describe("NetworkActivity", () => {
  beforeEach(() => { __resetNetActivity(); jest.useFakeTimers(); });
  afterEach(() => jest.useRealTimers());

  it("appears only for requests that take a moment; first 'Loading…', then 'Refreshing…' on the same page", async () => {
    const { rerender } = render(<NetworkActivity page="/scans" />);
    let done!: () => void;
    act(() => { void track(new Promise<void>(r => { done = r; })); });
    act(() => { jest.advanceTimersByTime(ACTIVITY_DELAY_MS - 10); });
    expect(screen.queryByRole("status")).toBeNull();                       // a quick request doesn't flicker
    act(() => { jest.advanceTimersByTime(20); });
    expect(screen.getByRole("status")).toHaveTextContent("Loading…");
    await act(async () => { done(); });
    expect(screen.queryByRole("status")).toBeNull();

    act(() => { void track(new Promise<void>(r => { done = r; })); });
    act(() => { jest.advanceTimersByTime(ACTIVITY_DELAY_MS + 1); });
    expect(screen.getByRole("status")).toHaveTextContent("Refreshing…");     // the page already has its data
    await act(async () => { done(); });

    rerender(<NetworkActivity page="/alerts" />);                          // a new page loads fresh
    act(() => { void track(new Promise<void>(() => {})); });
    act(() => { jest.advanceTimersByTime(ACTIVITY_DELAY_MS + 1); });
    expect(screen.getByRole("status")).toHaveTextContent("Loading…");
  });
});
