/**
 * Universal Taint Model -- the shared vocabulary every language engine's models are written in
 * (docs/taint/utm-gap-report.md §6.2): rules, sanitizers, sources, sinks and propagators, with a validator
 * (registry.ts). The engines read sources (JVM), sinks (SSRF) and propagators (all) from it; moved one family at
 * a time, each kept identical by the golden snapshot.
 */
import type { SinkClass } from "../taintCore";

export type ModelLang = "js" | "py" | "java" | "kt" | "go" | "cs" | "php" | "rb" | "rs" | "cpp";
export type SinkClassName = keyof typeof SinkClass;

/** A vulnerability rule over the shared vocabulary. */
export interface RuleModel {
  id: string;
  cwe: string | null;
  /** The sink class a taint flow must keep to report this rule; null for a specialised (non-taint) analysis
   * (weak crypto, races, memory safety, authorization) that sits beside taint, as the spec requires. */
  sinkClass: SinkClassName | null;
  /** Languages whose data-flow engine can report it (ruleLanguages.ts). */
  languages: string[];
}

/** A call that neutralises some sink classes for the value passing through it (taint/sanitizers.ts). */
export interface SanitizerModel {
  id: string;
  lang: ModelLang;
  /** `exact`: the whole callee text (`html.EscapeString`); `tail`: the method name on any receiver (`forHtml`). */
  match: { kind: "exact" | "tail"; name: string };
  /** The classes it clears, or a judgement made from its arguments (`filter_var` by its filter constant). */
  clears: SinkClassName[] | "depends-on-arguments";
}

export interface ModelRegistry {
  rules: RuleModel[];
  sanitizers: SanitizerModel[];
  sources: SourceModel[];
  sinks: SinkModel[];
  propagators: PropagatorModel[];
}

import type { SourceModel } from "./sources";
import type { SinkModel } from "./sinks";
import type { PropagatorModel } from "./propagators";
