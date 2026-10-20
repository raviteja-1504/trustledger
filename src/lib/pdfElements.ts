/**
 * Hands a React element tree to @react-pdf/renderer in the shape *its* React understands.
 *
 * @react-pdf/renderer is a server-external package (next.config.mjs), so at runtime it require()s the project's
 * React from node_modules (18.x). Code bundled by Next -- this route's createElement and the JSX in reportPDF.tsx --
 * gets Next's own vendored React (19.x), whose elements are tagged Symbol.for("react.transitional.element"). React
 * 18's reconciler only knows Symbol.for("react.element"), so it rejected every report with "Objects are not valid
 * as a React child (found: object with keys {$$typeof, type, key, ref, props})" and no PDF was ever produced.
 *
 * toRendererElements rebuilds the tree with the renderer's own createElement. Function components are called
 * directly while rebuilding (the report's are plain functions of their props -- no hooks, no state), so only host
 * elements (react-pdf's "VIEW", "TEXT", ...) and fragments reach the renderer.
 */

type CreateElement = (type: unknown, props: Record<string, unknown> | null, ...children: unknown[]) => unknown;
export interface RendererReact { createElement: CreateElement; Fragment: unknown }

interface AnyElement { $$typeof: symbol; type: unknown; key: string | null; props: Record<string, unknown> }

const ELEMENT_TAGS = new Set([Symbol.for("react.element"), Symbol.for("react.transitional.element")]);
const FRAGMENT = Symbol.for("react.fragment");

const isElement = (n: unknown): n is AnyElement =>
  typeof n === "object" && n !== null && ELEMENT_TAGS.has((n as { $$typeof?: symbol }).$$typeof as symbol);

const MAX_DEPTH = 200;

export function toRendererElements(node: unknown, R: RendererReact, depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new Error("PDF element tree too deep");
  if (Array.isArray(node)) return node.map(n => toRendererElements(n, R, depth + 1));
  if (!isElement(node)) return node;           // strings, numbers, null, booleans, render-prop functions
  const { type, key, props } = node;
  if (typeof type === "function") {
    // A class component would need its own instance; the report has none, so fail loudly rather than mis-render.
    if ((type as { prototype?: { isReactComponent?: unknown } }).prototype?.isReactComponent) throw new Error("Class components aren't supported in PDF documents");
    return toRendererElements((type as (p: unknown) => unknown)(props), R, depth + 1);
  }
  const { children, ...rest } = props ?? {};
  const outType = type === FRAGMENT ? R.Fragment : type;
  const outProps = key != null ? { ...rest, key } : rest;
  if (children === undefined) return R.createElement(outType, outProps);
  const kids = toRendererElements(children, R, depth + 1);
  return Array.isArray(kids) ? R.createElement(outType, outProps, ...kids) : R.createElement(outType, outProps, kids);
}

declare const __non_webpack_require__: NodeRequire | undefined;

/** The React that @react-pdf/renderer itself loads: node_modules' react, required at runtime (not Next's bundled
 *  copy). Outside webpack (tests, scripts) the ordinary require is that same module. */
export function loadRendererReact(): RendererReact {
  const req: NodeRequire = typeof __non_webpack_require__ === "function" ? __non_webpack_require__ : require;
  return req("react") as RendererReact;
}
