import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import Tip from "@/components/Tip";

const rect = (o: Partial<DOMRect>): DOMRect => ({ x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, toJSON: () => ({}), ...o } as DOMRect);

describe("Tip", () => {
  it("shows its text on hover and hides it when the pointer leaves", () => {
    render(<Tip tip="Scans the PR again"><button>Rescan</button></Tip>);
    expect(screen.queryByRole("tooltip")).toBeNull();
    fireEvent.mouseEnter(screen.getByRole("button", { name: "Rescan" }).parentElement!);
    expect(screen.getByRole("tooltip")).toHaveTextContent("Scans the PR again");
    fireEvent.mouseLeave(screen.getByRole("button", { name: "Rescan" }).parentElement!);
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("shows on keyboard focus and hides on blur, so it isn't mouse-only", () => {
    render(<Tip tip="Scans the PR again"><button>Rescan</button></Tip>);
    fireEvent.focus(screen.getByRole("button", { name: "Rescan" }));
    expect(screen.getByRole("tooltip")).toBeInTheDocument();
    fireEvent.blur(screen.getByRole("button", { name: "Rescan" }));
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("Escape dismisses it while it is open", () => {
    render(<Tip tip="Scans the PR again"><button>Rescan</button></Tip>);
    fireEvent.focus(screen.getByRole("button", { name: "Rescan" }));
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("describes the element with it while open (and not otherwise), keeping an existing description", () => {
    render(<Tip tip="Scans the PR again"><button aria-describedby="other">Rescan</button></Tip>);
    const btn = screen.getByRole("button", { name: "Rescan" });
    expect(btn.getAttribute("aria-describedby")).toBe("other");
    fireEvent.focus(btn);
    const id = screen.getByRole("tooltip").id;
    expect(btn.getAttribute("aria-describedby")).toBe(`other ${id}`);
    expect(btn).toHaveAccessibleDescription(/Scans the PR again/);
  });

  it("renders a title above the text when given", () => {
    render(<Tip title="Rescan" tip="Scans the PR again"><button>Rescan</button></Tip>);
    fireEvent.focus(screen.getByRole("button"));
    expect(screen.getByRole("tooltip")).toHaveTextContent(/RescanScans the PR again|Rescan.*Scans the PR again/);
  });

  it("with no tip it renders the child untouched: no wrapper, no listeners", () => {
    const { container } = render(<Tip><button>Plain</button></Tip>);
    expect(container.firstElementChild!.tagName).toBe("BUTTON");
    fireEvent.focus(screen.getByRole("button"));
    expect(screen.queryByRole("tooltip")).toBeNull();
  });

  it("opens above the element when there is room", () => {
    render(<Tip tip="x"><button>b</button></Tip>);
    const wrap = screen.getByRole("button").parentElement!;
    wrap.getBoundingClientRect = () => rect({ top: 400, bottom: 420, left: 300, right: 360, width: 60, height: 20 });
    fireEvent.mouseEnter(wrap);
    expect(screen.getByRole("tooltip").style.transform).toBe("translateY(-100%)");
  });

  it("opens below when it would run off the top of the screen", () => {
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => 80 });
    try {
      render(<Tip tip="x"><button>b</button></Tip>);
      const wrap = screen.getByRole("button").parentElement!;
      wrap.getBoundingClientRect = () => rect({ top: 10, bottom: 30, left: 300, right: 360, width: 60, height: 20 });
      fireEvent.mouseEnter(wrap);
      const bubble = screen.getByRole("tooltip");
      expect(bubble.style.transform).toBe("none");
      expect(bubble.style.top).toBe("38px");                          // element bottom + gap
    } finally { delete (HTMLElement.prototype as unknown as Record<string, unknown>).offsetHeight; }
  });

  it("stays on screen horizontally", () => {
    render(<Tip tip="x" width={260}><button>b</button></Tip>);
    const wrap = screen.getByRole("button").parentElement!;
    wrap.getBoundingClientRect = () => rect({ top: 400, bottom: 420, left: 2, right: 20, width: 18, height: 20 });
    fireEvent.mouseEnter(wrap);
    expect(parseFloat(screen.getByRole("tooltip").style.left)).toBeGreaterThanOrEqual(8);
    fireEvent.mouseLeave(wrap);
    wrap.getBoundingClientRect = () => rect({ top: 400, bottom: 420, left: window.innerWidth - 10, right: window.innerWidth, width: 10, height: 20 });
    fireEvent.mouseEnter(wrap);
    expect(parseFloat(screen.getByRole("tooltip").style.left)).toBeLessThanOrEqual(window.innerWidth - 260 - 8);
  });

  it("works around a disabled button too", () => {
    render(<Tip tip="Not available yet"><button disabled>Go</button></Tip>);
    fireEvent.mouseEnter(screen.getByRole("button").parentElement!);
    expect(screen.getByRole("tooltip")).toHaveTextContent("Not available yet");
  });
});
