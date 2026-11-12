/**
 * The guided tour: shown once to a signed-in person who has not seen it, stepping through the page's data-tour targets,
 * skippable, remembered when finished or skipped, replayable, and tolerant of a target that is not on the page.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import Tour, { TourButton, useTour } from "@/components/tour/Tour";
import { PR_TOUR, SCANS_TOUR, tourSeenOf, withTourSeen, type TourDef } from "@/lib/tour";

const auth = { tourEnabled: true, tourSeen: [] as string[], markTourSeen: jest.fn(async (_id: string) => undefined) };
// a fresh array each render, as the provider gives (tourSeenOf builds a new one), so the effect re-runs on every render
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ ...auth, tourSeen: [...auth.tourSeen] }) }));

beforeEach(() => { auth.tourEnabled = true; auth.tourSeen = []; auth.markTourSeen.mockClear(); });

const TWO: TourDef = {
  id: "scans", finishLabel: "Open it",
  steps: [
    { target: "a", title: "Step A", body: "About A" },
    { target: "missing", title: "Step M", body: "About M" },          // not on the page, no fallback: skipped
    { target: "b", title: "Step B", body: "About B", fallback: "B is not available to you" },
  ],
};

function Page({ def = TWO, ready = true, withB = true, onFinish }: { def?: TourDef; ready?: boolean; withB?: boolean; onFinish?: () => void }) {
  const tour = useTour(def, ready);
  return (
    <div>
      <div data-tour="a">A</div>
      {withB && <div data-tour="b">B</div>}
      {tour.available && <TourButton onClick={tour.start} />}
      {tour.active && <Tour def={def} onClose={tour.close} onFinish={onFinish} />}
    </div>
  );
}

describe("tour helpers", () => {
  it("reads and extends the seen list, ignoring junk", () => {
    expect(tourSeenOf(null)).toEqual([]);
    expect(tourSeenOf({ user_metadata: { tour_seen: "scans" } })).toEqual([]);
    expect(tourSeenOf({ user_metadata: { tour_seen: ["scans", 3, null, "pr"] } })).toEqual(["scans", "pr"]);
    expect(withTourSeen(["scans"], "pr")).toEqual(["scans", "pr"]);
    expect(withTourSeen(["scans"], "scans")).toEqual(["scans"]);
  });
  it("both tours point only at targets and say something at each step", () => {
    for (const t of [SCANS_TOUR, PR_TOUR]) for (const s of t.steps) { expect(s.target).toBeTruthy(); expect(s.title).toBeTruthy(); expect(s.body.length).toBeGreaterThan(20); }
    expect(PR_TOUR.steps.find(s => s.target === "pr-attest")?.fallback).toBeTruthy();
  });
});

describe("<Tour> / useTour", () => {
  it("starts by itself for someone who has not seen it, and walks the steps (a missing target is skipped)", () => {
    render(<Page />);
    expect(screen.getByRole("dialog", { name: "Guided tour" })).toBeInTheDocument();
    expect(screen.getByText("Step A")).toBeInTheDocument();
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Step B")).toBeInTheDocument();
    expect(screen.queryByText("Step M")).not.toBeInTheDocument();
    expect(screen.getByText("2 of 2")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByText("Step A")).toBeInTheDocument();
  });

  it("finishing remembers it and runs onFinish; the last button carries the tour's own label", () => {
    const onFinish = jest.fn();
    render(<Page onFinish={onFinish} />);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    fireEvent.click(screen.getByRole("button", { name: "Open it" }));
    expect(auth.markTourSeen).toHaveBeenCalledWith("scans");
    expect(onFinish).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("skip (button, × or Escape) remembers it without running onFinish", () => {
    const onFinish = jest.fn();
    const { unmount } = render(<Page onFinish={onFinish} />);
    fireEvent.click(screen.getByRole("button", { name: "Skip" }));
    expect(auth.markTourSeen).toHaveBeenCalledWith("scans");
    unmount();
    auth.markTourSeen.mockClear();
    render(<Page onFinish={onFinish} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(auth.markTourSeen).toHaveBeenCalledWith("scans");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onFinish).not.toHaveBeenCalled();
  });

  it("arrow keys move between steps", () => {
    render(<Page />);
    fireEvent.keyDown(window, { key: "ArrowRight" });
    expect(screen.getByText("Step B")).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "ArrowLeft" });
    expect(screen.getByText("Step A")).toBeInTheDocument();
  });

  it("does not start when already seen, when the page is not ready, or when tours are off (demo / signed out)", () => {
    auth.tourSeen = ["scans"];
    const a = render(<Page />); expect(screen.queryByRole("dialog")).not.toBeInTheDocument(); a.unmount();
    auth.tourSeen = [];
    const b = render(<Page ready={false} />); expect(screen.queryByRole("dialog")).not.toBeInTheDocument(); b.unmount();
    auth.tourEnabled = false;
    render(<Page />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /take the tour/i })).not.toBeInTheDocument();
  });

  it("starts when the page becomes ready, and only once", () => {
    const { rerender } = render(<Page ready={false} />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    rerender(<Page ready />);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Skip" }));
    rerender(<Page ready />);          // still not seen in this mock (the save is async), but it must not pop up again
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("a step whose target is absent shows its fallback text instead, centred", () => {
    render(<Page withB={false} />);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getByText("Step B")).toBeInTheDocument();
    expect(screen.getByText("B is not available to you")).toBeInTheDocument();
    expect(screen.queryByText("About B")).not.toBeInTheDocument();
  });

  it("'Take the tour' replays it after it was finished", () => {
    auth.tourSeen = ["scans"];
    render(<Page />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /take the tour/i }));
    expect(screen.getByText("Step A")).toBeInTheDocument();
  });

  it("renders nothing when none of its steps can be shown", () => {
    const def: TourDef = { id: "pr", steps: [{ target: "nope", title: "T", body: "B" }] };
    render(<Page def={def} />);
    expect(screen.queryByText("T")).not.toBeInTheDocument();
  });
});

describe("<Tour> layout (the PR page scrolled sideways while the tour was open)", () => {
  afterEach(() => jest.restoreAllMocks());

  it("is rendered into <body>, outside the page: a `contain: layout` ancestor would turn `fixed` into 'relative to the page'", () => {
    const { container } = render(<div style={{ contain: "layout" }}><Page /></div>);
    const dialog = screen.getByRole("dialog", { name: "Guided tour" });
    expect(container.contains(dialog)).toBe(false);
    expect(dialog.parentElement).toBe(document.body);
  });

  it("brings the target into view by scrolling the page's scroller vertically only, never with scrollIntoView (which shifts every ancestor sideways too)", () => {
    const rect = (top: number, height: number) => ({ top, height, left: 10, right: 60, width: 50, bottom: top + height, x: 10, y: top, toJSON: () => ({}) });
    jest.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
      return (this.dataset.tour === "a" ? rect(900, 40) : this.tagName === "MAIN" ? rect(50, 500) : rect(0, 0)) as DOMRect;
    });
    jest.spyOn(HTMLElement.prototype, "clientHeight", "get").mockImplementation(function (this: HTMLElement) { return this.tagName === "MAIN" ? 500 : 0; });
    jest.spyOn(HTMLElement.prototype, "scrollHeight", "get").mockImplementation(function (this: HTMLElement) { return this.tagName === "MAIN" ? 3000 : 0; });
    const scrollIntoView = jest.fn();
    HTMLElement.prototype.scrollIntoView = scrollIntoView;
    function InMain() {
      const tour = useTour(TWO, true);
      return <main data-testid="main" style={{ overflowY: "auto" }}><div data-tour="a">A</div>{tour.active && <Tour def={TWO} onClose={tour.close} />}</main>;
    }
    render(<InMain />);
    const main = screen.getByTestId("main");
    expect(main.scrollTop).toBe(900 - 50 - (500 - 40) / 2);   // centred in the scroller
    expect(main.scrollLeft).toBe(0);
    expect(scrollIntoView).not.toHaveBeenCalled();
    delete (HTMLElement.prototype as { scrollIntoView?: unknown }).scrollIntoView;
  });

  it("a target beyond the window's right edge (a far-right table column) is not pointed at: the step still reads, in the middle", () => {
    jest.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
      return (this.dataset.tour === "a" ? { top: 100, height: 30, left: 5000, right: 5100, width: 100, bottom: 130, x: 5000, y: 100, toJSON: () => ({}) } : { top: 0, height: 0, left: 0, right: 0, width: 0, bottom: 0, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect;
    });
    render(<Page />);
    expect(screen.getByText("About A")).toBeInTheDocument();
  });
});
