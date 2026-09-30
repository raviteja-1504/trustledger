/**
 * Brand logo: the components, the generated assets they (and the page metadata) point at, and the places
 * the logo must appear.
 */
import fs from "fs";
import path from "path";
import { render, screen } from "@testing-library/react";
import { BrandLogo, BrandMark, BrandWordmark } from "@/components/BrandLogo";
import { WORDMARK_PNG_DATA_URI, WORDMARK_ASPECT } from "@/lib/brandAssets";

const sidebarState = { collapsed: false, toggle: jest.fn() };
jest.mock("@/lib/sidebar", () => ({ useSidebar: () => sidebarState }));
jest.mock("@/lib/roles", () => ({
  useRole: () => ({ role: "admin", setRole: jest.fn(), isDemo: false, permissions: { canManageSettings: true, canAttest: true } }),
  ROLE_LABELS: { admin: "Admin" }, ROLE_COLORS: { admin: "#fff" },
}));
const authState: { user: unknown; profile: unknown; loading: boolean } = { user: null, profile: null, loading: false };
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ ...authState, signOut: jest.fn(), signInWithGitHub: jest.fn() }) }));
jest.mock("@/lib/useRealData", () => ({ isSeedMode: () => true, authedFetch: jest.fn() }));
jest.mock("@/lib/api", () => ({ api: {} }));

const PUBLIC = path.join(__dirname, "../../../public");

/** Width/height from a PNG's IHDR chunk, and whether it carries an alpha channel (colour type 6). */
function pngInfo(file: string) {
  const b = fs.readFileSync(path.join(PUBLIC, file));
  expect(b.subarray(1, 4).toString("latin1")).toBe("PNG");
  return { width: b.readUInt32BE(16), height: b.readUInt32BE(20), rgba: b[25] === 6 };
}

describe("brand components", () => {
  it("render the right artwork, alt text and aspect-correct size", () => {
    render(<><BrandMark size={40} /><BrandWordmark height={30} /><BrandLogo height={60} /></>);
    const [mark, wordmark, logo] = screen.getAllByRole("img") as HTMLImageElement[];
    expect(mark).toHaveAttribute("src", "/brand/trustledger-mark.png");
    expect(mark).toHaveAttribute("width", "40");
    expect(mark).toHaveAttribute("height", "40");
    expect(wordmark).toHaveAttribute("src", "/brand/trustledger-wordmark.png");
    const wm = pngInfo("brand/trustledger-wordmark.png");
    expect(Number(wordmark.getAttribute("width"))).toBe(Math.round(30 * wm.width / wm.height));
    expect(logo).toHaveAttribute("src", "/brand/trustledger-logo.png");
    const lg = pngInfo("brand/trustledger-logo.png");
    expect(Number(logo.getAttribute("width"))).toBe(Math.round(60 * lg.width / lg.height));
    for (const img of [mark, wordmark, logo]) expect(img.getAttribute("alt")).toMatch(/^TrustLedger/);
  });
});

describe("brand assets", () => {
  it("are transparent PNGs; the mark is square", () => {
    for (const f of ["brand/trustledger-mark.png", "brand/trustledger-wordmark.png", "brand/trustledger-logo.png", "favicon-16x16.png", "favicon-32x32.png"]) {
      expect(pngInfo(f).rgba).toBe(true);
    }
    const mark = pngInfo("brand/trustledger-mark.png");
    expect(mark.width).toBe(mark.height);
  });

  it("every icon the page metadata and web manifest reference exists at its declared size", () => {
    const layout = fs.readFileSync(path.join(__dirname, "../../app/layout.tsx"), "utf8");
    const referenced = Array.from(layout.matchAll(/["`](?:\$\{APP_URL\})?(\/[\w-]+\.(?:png|ico))["`]/g), m => m[1]);
    expect(referenced).toEqual(expect.arrayContaining(["/favicon-16x16.png", "/favicon-32x32.png", "/apple-touch-icon.png", "/favicon.ico", "/og-image.png"]));
    for (const r of referenced) expect(fs.existsSync(path.join(PUBLIC, r))).toBe(true);

    const manifest = JSON.parse(fs.readFileSync(path.join(PUBLIC, "manifest.json"), "utf8")) as { icons: { src: string; sizes: string }[] };
    for (const icon of manifest.icons) {
      const { width, height } = pngInfo(icon.src.slice(1));
      expect(`${width}x${height}`).toBe(icon.sizes);
    }
    expect(pngInfo("og-image.png")).toMatchObject({ width: 1200, height: 630 });
  });

  it("the PDF's embedded wordmark is a PNG whose aspect matches its declared ratio", () => {
    const b = Buffer.from(WORDMARK_PNG_DATA_URI.replace(/^data:image\/png;base64,/, ""), "base64");
    expect(b.subarray(1, 4).toString("latin1")).toBe("PNG");
    expect(b.readUInt32BE(16) / b.readUInt32BE(20)).toBeCloseTo(WORDMARK_ASPECT, 5);
  });
});

describe("where the logo appears", () => {
  it("sidebar: wordmark when expanded, mark alone when collapsed", async () => {
    const { default: Sidebar } = await import("@/components/Sidebar");
    sidebarState.collapsed = false;
    const { unmount } = render(<Sidebar />);
    expect(screen.getAllByRole("img").map(i => i.getAttribute("src"))).toContain("/brand/trustledger-wordmark.png");
    unmount();
    sidebarState.collapsed = true;
    render(<Sidebar />);
    const srcs = screen.getAllByRole("img").map(i => i.getAttribute("src"));
    expect(srcs).toContain("/brand/trustledger-mark.png");
    expect(srcs).not.toContain("/brand/trustledger-wordmark.png");
  });

  it("the signed-out screen shows the full logo", async () => {
    const { default: AuthGuard } = await import("@/components/AuthGuard");
    render(<AuthGuard><p>secret</p></AuthGuard>);
    expect(screen.queryByText("secret")).not.toBeInTheDocument();
    expect(screen.getByRole("img", { name: /TrustLedger — code security with proof/ })).toHaveAttribute("src", "/brand/trustledger-logo.png");
  });
});
