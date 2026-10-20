/**
 * @jest-environment node
 *
 * The production report failure: Next's bundled React (19) tags elements Symbol.for("react.transitional.element");
 * @react-pdf/renderer runs on node_modules' React 18, which rejects them ("Objects are not valid as a React child").
 * toRendererElements rebuilds the tree with the renderer's React. (@react-pdf/renderer is ESM-only and can't load in
 * jest; it's mocked to its host element names, and the real render was checked against Next's React 19 by hand.)
 */
import React from "react";

jest.mock("@react-pdf/renderer", () => ({
  Document: "DOCUMENT", Page: "PAGE", Text: "TEXT", View: "VIEW", Image: "IMAGE",
  StyleSheet: { create: <T,>(s: T) => s },
}));

import { loadRendererReact, toRendererElements } from "@/lib/pdfElements";
import { buildReportDocument } from "@/lib/reportPDF";

const T19 = Symbol.for("react.transitional.element");

/** What Next's React 19 hands over: the same tree, every element tagged the React 19 way, components not yet called. */
function asReact19(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(asReact19);
  if (!React.isValidElement(node)) return node;
  const el = node as React.ReactElement<Record<string, unknown>>;
  const props = { ...el.props };
  if ("children" in props) props.children = asReact19(props.children);
  return { $$typeof: T19, type: el.type, key: el.key, ref: null, props };
}

const reportData = {
  report_id: "ABC-123", org: { name: "Acme", slug: "acme", github_org: "acme" },
  framework: "SOC2", period_start: "2026-09-01", period_end: "2026-10-01",
  generated_at: "2026-10-01T00:00:00Z", generated_by: "auditor@example.test", framework_id: "SOC2",
  evidence_scope: { name: "SOC 2", standard: "AICPA TSC", scope: "Change management", status_counts: { pass: 1, partial: 0, fail: 1, no_data: 0 } },
  metrics: { total_scans: 3, total_files: 12, total_attestations: 2, critical_findings: 1, high_risk_files: 3, high_risk_reviewed: 2,
    independent_reviews: 2, self_approvals: 0, secrets_detected: 0, avg_ai_percentage: 0.4 },
  risk_breakdown: { critical: 1, high: 2, medium: 3, low: 6 },
  gaps: [{ repo: "acme/api", pr_number: 7, file_path: "src/pay.ts", risk_score: "CRITICAL", ai_percentage: 0.8 }],
  compliance: [
    { control_id: "CC8.1", control_name: "Change management", status: "pass", score: 100, checks: [{ label: "Reviewed", status: "pass", summary: "All reviewed", gaps: [] }] },
    { control_id: "CC7.1", control_name: "Monitoring", status: "fail", score: 20, checks: [{ label: "Secrets", status: "fail", summary: "1 open", gaps: ["src/pay.ts"] }] },
  ],
  scans: [], attestations: [], secrets: [],
};

describe("PDF elements", () => {
  it("the whole SOC 2 report, handed over React 19-style, comes out as renderer-React host elements only", () => {
    const tree = asReact19(React.createElement(buildReportDocument, { data: reportData as never, signature: "f".repeat(64) }));
    const out = toRendererElements(tree, loadRendererReact());
    const types = new Set<unknown>();
    let text = "";
    const walk = (n: unknown) => {
      if (Array.isArray(n)) return n.forEach(walk);
      if (typeof n === "string" || typeof n === "number") { text += `${n} `; return; }
      if (!n || typeof n !== "object") return;
      const el = n as { $$typeof: symbol; type: unknown; props: { children?: unknown } };
      expect(el.$$typeof).toBe(Symbol.for("react.element"));   // what React 18's reconciler accepts
      types.add(el.type);
      walk(el.props.children);
    };
    walk(out);
    expect(React.isValidElement(out)).toBe(true);
    expect([...types].every(t => typeof t === "string" || typeof t === "symbol")).toBe(true);
    expect(types).toEqual(expect.objectContaining(new Set(["DOCUMENT", "PAGE", "VIEW", "TEXT"])));
    expect(text).toContain("ABC-123");
    expect(text).toContain("CC7.1");
  });

  it("keeps keys, props, fragments and primitives; calls function components", () => {
    const calls: unknown[] = [];
    const R = { Fragment: "FRAG", createElement: (type: unknown, props: unknown, ...children: unknown[]) => ({ type, props, children }) };
    const Comp = (p: { n: number }) => { calls.push(p); return { $$typeof: T19, type: "TEXT", key: null, ref: null, props: { children: `n=${p.n}` } }; };
    const tree = { $$typeof: T19, type: "VIEW", key: "k1", ref: null, props: { style: { a: 1 }, fixed: true, children: [
      "plain", 3, null, false,
      { $$typeof: Symbol.for("react.fragment"), type: Symbol.for("react.fragment"), key: null, ref: null, props: { children: "in fragment" } },
      { $$typeof: T19, type: Comp, key: null, ref: null, props: { n: 2 } },
      { $$typeof: T19, type: "TEXT", key: null, ref: null, props: {} },
    ] } };
    // The fragment element above is tagged with the fragment symbol, not an element tag: it passes through untouched.
    const out = toRendererElements(tree, R) as { type: string; props: Record<string, unknown>; children: unknown[] };
    expect(out.type).toBe("VIEW");
    expect(out.props).toEqual({ style: { a: 1 }, fixed: true, key: "k1" });
    expect(out.children.slice(0, 4)).toEqual(["plain", 3, null, false]);
    expect(out.children[5]).toEqual({ type: "TEXT", props: {}, children: ["n=2"] });
    expect(out.children[6]).toStrictEqual({ type: "TEXT", props: {}, children: [] });   // no stray undefined child
    expect(calls).toEqual([{ n: 2 }]);
  });

  it("a Fragment element becomes the renderer's Fragment; a single child isn't wrapped in an array", () => {
    const R = { Fragment: "FRAG", createElement: (type: unknown, props: unknown, ...children: unknown[]) => ({ type, props, children }) };
    const frag = { $$typeof: T19, type: Symbol.for("react.fragment"), key: null, ref: null, props: { children: { $$typeof: T19, type: "TEXT", key: null, ref: null, props: { children: "x" } } } };
    expect(toRendererElements(frag, R)).toEqual({ type: "FRAG", props: {}, children: [{ type: "TEXT", props: {}, children: ["x"] }] });
  });

  it("refuses class components and absurdly deep trees instead of mis-rendering", () => {
    class K extends React.Component { render() { return null; } }
    const R = { Fragment: "F", createElement: () => ({}) };
    expect(() => toRendererElements({ $$typeof: T19, type: K, key: null, ref: null, props: {} }, R)).toThrow(/Class components/);
    let deep: unknown = "leaf";
    for (let i = 0; i < 300; i++) deep = { $$typeof: T19, type: "VIEW", key: null, ref: null, props: { children: deep } };
    expect(() => toRendererElements(deep, R)).toThrow(/too deep/);
  });
});
