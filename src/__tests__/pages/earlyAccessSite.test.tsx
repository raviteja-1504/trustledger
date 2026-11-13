import { render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("next/navigation", () => ({ useRouter: () => ({ push: jest.fn() }), usePathname: () => "/", useSearchParams: () => new URLSearchParams() }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ user: null, profile: null, loading: false }) }));

import LandingClient, { type LandingEvidence } from "@/app/LandingClient";
import ContactPage from "@/app/contact/page";
import { DOCS_CONTENT } from "@/app/docs/content";
import { PLAN_LIMITS } from "@/lib/limits";
import { PRIMARY_CONTACT } from "@/lib/contacts";

const evidence: LandingEvidence = {
  engineCommit: "abc1234", measuredAt: "2026-11-03", pooledTpr: 0.568, pooledFpr: 0.012, labelledCases: 5000,
  corpora: [{ name: "Corpus A", languages: ["Go"], score: 70 }], juiceDetected: 10, juiceTotal: 20, ruleCount: 100, cweCount: 50,
};

beforeAll(() => {
  window.matchMedia = window.matchMedia || ((q: string) => ({ matches: false, media: q, addEventListener: () => {}, removeEventListener: () => {}, addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => false }) as unknown as MediaQueryList);
  (window as unknown as { IntersectionObserver: unknown }).IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
});

describe("homepage", () => {
  it("leads with the new headline and its supporting line", () => {
    render(<LandingClient evidence={evidence} />);
    const h1 = screen.getByRole("heading", { level: 1 });
    expect(h1).toHaveTextContent("Secure Every Pull Request.");
    expect(h1).toHaveTextContent("Establish Trust in Every Release.");
    expect(screen.getByText("Discover vulnerabilities, trace real attack paths across files, detect exposed secrets and govern AI-generated code.")).toBeInTheDocument();
    expect(screen.getByText("One platform for application security, code provenance and AI governance")).toBeInTheDocument();
  });

  it("the two hero buttons: free sign-up first, the product demo second", () => {
    render(<LandingClient evidence={evidence} />);
    expect(screen.getAllByRole("link", { name: /Try TrustLedger Free/ })[0]).toHaveAttribute("href", "/login?mode=signup");
    expect(screen.getAllByRole("link", { name: /Watch Product Demo/ })[0]).toHaveAttribute("href", "/demo");
  });

  it("shows the Founding Users Program right after the hero: what you receive, how to start, and the real allowance", () => {
    render(<LandingClient evidence={evidence} />);
    const section = document.getElementById("early-access")!;
    expect(section).not.toBeNull();
    const s = within(section);
    expect(s.getByRole("heading", { name: /Join the Founding Users Program: free early access/ })).toBeInTheDocument();
    expect(s.getByText("What you receive")).toBeInTheDocument();
    expect(s.getByText("How to start")).toBeInTheDocument();
    // the numbers come from the plan itself
    const f = PLAN_LIMITS.free;
    expect(section.textContent).toContain(`${f.scans} pull-request scans a month`);
    expect(section.textContent).toContain(`${f.members} team members`);
    expect(s.getByRole("link", { name: /Join the Founding Users Program/ })).toHaveAttribute("href", "/login?mode=signup");
    expect(s.getByRole("link", { name: "Ask about the program" }).getAttribute("href")).toContain(`mailto:${PRIMARY_CONTACT}?subject=Founding%20Users%20Program`);
    // it sits directly after the hero section
    const hero = document.querySelector("section");
    expect(hero?.nextElementSibling?.nextElementSibling).toBe(section);
  });

  it("promises nothing the product does not do: no credit card is the only commercial claim", () => {
    render(<LandingClient evidence={evidence} />);
    const text = document.getElementById("early-access")!.textContent ?? "";
    expect(text).not.toMatch(/lifetime|discount|limited spots|unlimited scans|guarantee/i);
  });
});

describe("early-access banner", () => {
  it("sits at the top of the homepage, above the navigation, and states the offer from the plan itself", () => {
    render(<LandingClient evidence={evidence} />);
    const banner = screen.getByRole("region", { name: "Free early access" });
    const f = PLAN_LIMITS.free;
    expect(banner).toHaveTextContent("No credit card");
    expect(banner).toHaveTextContent(`${f.repos} repository`);
    expect(banner).toHaveTextContent(`${f.scans} scans a month`);
    expect(within(banner).getByRole("link", { name: /Start free/ })).toHaveAttribute("href", "/login?mode=signup");
    // the first thing in the fixed top bar, before the site header
    const bar = banner.parentElement!;
    expect(bar.firstElementChild).toBe(banner);
    expect(banner.nextElementSibling?.tagName).toBe("HEADER");
  });

  it("is only on the homepage: other site pages keep the plain navigation", () => {
    render(<ContactPage />);
    expect(screen.queryByRole("region", { name: "Free early access" })).toBeNull();
  });
});

describe("contact and feedback page", () => {
  it("offers each kind of message as a prefilled email to the one address", () => {
    render(<ContactPage />);
    for (const [name, subject] of [["Request a demo", "TrustLedger%20demo%20%2F%20pricing"], ["Report a false positive", "False%20positive"], ["Report a miss", "Missed%20vulnerability"],
      ["Request a feature", "Feature%20request"], ["Report a problem", "Problem%20report"]] as const) {
      const href = screen.getByRole("link", { name: new RegExp(name) }).getAttribute("href")!;
      expect(href.startsWith(`mailto:${PRIMARY_CONTACT}?subject=${subject}&body=`)).toBe(true);
    }
  });

  it("points security reports to the security page and shows the plain address as a fallback", () => {
    render(<ContactPage />);
    expect(screen.getByRole("link", { name: "security page" })).toHaveAttribute("href", "/security");
    expect(screen.getAllByText(PRIMARY_CONTACT).length).toBeGreaterThan(0);
  });
});

describe("getting started guide", () => {
  it("is the five steps in order, with the GitHub name explained", () => {
    render(<>{DOCS_CONTENT["getting-started"]()}</>);
    const steps = screen.getAllByRole("heading", { level: 2 }).map(h => h.textContent);
    expect(steps.slice(0, 5)).toEqual(["1. Create your account", "2. Connect GitHub", "3. Select your repository", "4. Run your first scan", "5. Review the findings"]);
    expect(screen.getByRole("heading", { name: "Your GitHub name" })).toBeInTheDocument();
    expect(screen.getByText(/If it does not match, the pull request is not scanned/)).toBeInTheDocument();
  });

  it("states the plan allowance from the plan itself", () => {
    render(<>{DOCS_CONTENT["getting-started"]()}</>);
    const f = PLAN_LIMITS.free;
    expect(document.body.textContent).toContain(`${f.scans} pull-request scans a month, ${f.repos} repository and ${f.members} team members`);
  });
});

describe("troubleshooting", () => {
  it("covers the failures people actually hit, and the known limitations", () => {
    render(<>{DOCS_CONTENT.troubleshooting()}</>);
    const heads = screen.getAllByRole("heading", { level: 2 }).map(h => h.textContent);
    expect(heads).toEqual(expect.arrayContaining([
      "A pull request was not scanned", "The check says “Plan limit reached”", "Setup shows the wrong account or organisation",
      "I was signed out on one device after signing in on another", "The numbers on the pull request page do not match", "Known limitations",
    ]));
    expect(screen.getByText(/Detection is not equal in every language/)).toBeInTheDocument();
    expect(document.body.textContent).toContain(PRIMARY_CONTACT);
  });
});
