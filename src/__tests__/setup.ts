import "@testing-library/jest-dom";

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

// Mock localStorage
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
