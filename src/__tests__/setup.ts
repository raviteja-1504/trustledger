import "@testing-library/jest-dom";

// Node 20+ globals the app relies on (package.json "engines": ">=20"), filled in only when the Node running the
// tests is older (Node 18: no global File, no global WebCrypto). Production never takes these branches.
if (typeof globalThis.File === "undefined") {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  Object.defineProperty(globalThis, "File", { value: require("buffer").File, configurable: true, writable: true });
}
if (!globalThis.crypto?.subtle) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  Object.defineProperty(globalThis, "crypto", { value: require("crypto").webcrypto, configurable: true, writable: true });
}

// Mock Next.js navigation
jest.mock("next/navigation", () => ({
  useRouter:      () => ({ push: jest.fn(), replace: jest.fn(), back: jest.fn() }),
  usePathname:    () => "/dashboard",
  useParams:      () => ({}),
  useSearchParams:() => ({ get: () => null }),
}));

// Mock next/link globally
jest.mock("next/link", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const React = require("react");
  const MockLink = ({ children, href, ...rest }: { children: React.ReactNode; href: string; [k: string]: unknown }) =>
    React.createElement("a", { href, ...rest }, children);
  return { __esModule: true, default: MockLink };
});

// Mock localStorage — only relevant under jsdom (component tests). API/lib
// tests run under `@jest-environment node` (no DOM), where `window` doesn't exist.
if (typeof window !== "undefined") {
  const localStorageMock = (() => {
    let store: Record<string, string> = {};
    return {
      getItem:    (k: string) => store[k] ?? null,
      setItem:    (k: string, v: string) => { store[k] = v; },
      removeItem: (k: string) => { delete store[k]; },
      clear:      () => { store = {}; },
    };
  })();
  Object.defineProperty(window, "localStorage", { value: localStorageMock });
}

// Suppress console.error noise from React in tests
const originalError = console.error;
beforeAll(() => {
  console.error = (...args: unknown[]) => {
    const msg = String(args[0] ?? "");
    if (msg.includes("ReactDOM.render") || msg.includes("act(")) return;
    originalError(...args);
  };
});
afterAll(() => { console.error = originalError; });
