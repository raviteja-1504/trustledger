/**
 * The model registry (Universal Taint Model, step 1): the shared taxonomy and the sanitizer models, built from the
 * tables the engines use today -- not a parallel copy that could drift -- and a validator for registry contents.
 */
import { RULE_SINK_CLASSES, SinkClass } from "../taintCore";
import { sanitizerEntries, type SanitizerLang } from "../sanitizers";
import { INDICATOR_CWE_MAP } from "../../cweMap";
import { DATA_FLOW_LANGUAGES } from "../../ruleLanguages";
import type { ModelLang, ModelRegistry, RuleModel, SanitizerModel, SinkClassName } from "./types";
import { SOURCE_MODELS, type SourceKind, type SourceMatchKind } from "./sources";
import { SINK_MODELS } from "./sinks";
import { PROPAGATOR_MODELS, type PropagatorKind } from "./propagators";

const CLASS_NAMES = Object.keys(SinkClass) as SinkClassName[];
const LANGS: readonly ModelLang[] = ["js", "py", "java", "kt", "go", "cs", "php", "rb", "rs", "cpp"];

/** The class names in a mask (a single rule class, or a sanitizer's cleared set). */
export function classNames(mask: number): SinkClassName[] {
  return CLASS_NAMES.filter(n => (mask & SinkClass[n]) !== 0);
}

function buildRules(): RuleModel[] {
  const languagesOf = new Map<string, string[]>();
  for (const { language, ids } of DATA_FLOW_LANGUAGES) for (const id of ids) languagesOf.set(id, [...(languagesOf.get(id) ?? []), language]);
  const ids = new Set([...languagesOf.keys(), ...Object.keys(RULE_SINK_CLASSES)]);
  return [...ids].sort().map(id => {
    const mask = RULE_SINK_CLASSES[id];
    return { id, cwe: INDICATOR_CWE_MAP[id]?.id ?? null, sinkClass: mask === undefined ? null : classNames(mask)[0] ?? null, languages: languagesOf.get(id) ?? [] };
  });
}

const SANITIZER_LANG: Record<SanitizerLang, ModelLang> = { js: "js", py: "py", go: "go", java: "java", cs: "cs", php: "php", rb: "rb", kt: "kt", rs: "rs", cpp: "cpp" };

function buildSanitizers(): SanitizerModel[] {
  return sanitizerEntries().map(e => ({
    id: `${e.lang}:${e.match}:${e.name}`, lang: SANITIZER_LANG[e.lang], match: { kind: e.match, name: e.name },
    clears: e.clears === "depends-on-arguments" ? e.clears : classNames(e.clears),
  }));
}

let built: ModelRegistry | null = null;
export function modelRegistry(): ModelRegistry {
  return built ??= { rules: buildRules(), sanitizers: buildSanitizers(), sources: [...SOURCE_MODELS], sinks: [...SINK_MODELS], propagators: [...PROPAGATOR_MODELS] };
}
const PROPAGATOR_KINDS: readonly PropagatorKind[] = ["call-args", "constructor-args", "method-args", "mutator", "decoder"];

const SOURCE_KINDS: readonly SourceKind[] = ["http.query", "http.path", "http.header", "http.cookie", "http.body", "file.upload",
  "identity", "env", "cli", "stdin", "network", "queue", "db.read", "session", "deserialized"];
const SOURCE_MATCH_KINDS: readonly SourceMatchKind[] = ["request-call", "request-property", "param-annotation"];

/**
 * Problems in a registry, empty when it is consistent: unique ids, known languages and class names, every taint
 * rule mapped to a CWE, every rule an engine reports present in the taxonomy.
 */
export function validateRegistry(r: ModelRegistry): string[] {
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const s of r.sanitizers) {
    if (seen.has(s.id)) errors.push(`sanitizer ${s.id}: duplicate id`);
    seen.add(s.id);
    if (!LANGS.includes(s.lang)) errors.push(`sanitizer ${s.id}: unknown language "${s.lang}"`);
    if (!s.match.name.trim()) errors.push(`sanitizer ${s.id}: empty match`);
    if (Array.isArray(s.clears)) for (const c of s.clears) if (!CLASS_NAMES.includes(c)) errors.push(`sanitizer ${s.id}: unknown class "${c}"`);
  }
  const sourceIds = new Set<string>();
  for (const s of r.sources) {
    if (sourceIds.has(s.id)) errors.push(`source ${s.id}: duplicate id`);
    sourceIds.add(s.id);
    if (s.langs.length === 0 || s.langs.some(l => !LANGS.includes(l))) errors.push(`source ${s.id}: unknown or missing language`);
    if (!SOURCE_KINDS.includes(s.kind)) errors.push(`source ${s.id}: unknown kind "${s.kind}"`);
    if (!SOURCE_MATCH_KINDS.includes(s.match.kind)) errors.push(`source ${s.id}: unknown match kind "${s.match.kind}"`);
    if (!s.match.name.trim()) errors.push(`source ${s.id}: empty match`);
    if (s.trust !== "untrusted" && s.trust !== "semi-trusted") errors.push(`source ${s.id}: unknown trust "${s.trust}"`);
  }
  const knownRules = new Set(r.rules.map(x => x.id));
  const sinkIds = new Set<string>();
  for (const s of r.sinks) {
    if (sinkIds.has(s.id)) errors.push(`sink ${s.id}: duplicate id`);
    sinkIds.add(s.id);
    if (s.langs.length === 0 || s.langs.some(l => !LANGS.includes(l))) errors.push(`sink ${s.id}: unknown or missing language`);
    if (!knownRules.has(s.rule)) errors.push(`sink ${s.id}: unknown rule "${s.rule}"`);
    const positions = [...s.args.positions, ...Object.values(s.args.byMethod ?? {}).flat()];
    if (s.args.positions.length === 0 || positions.some(p => !Number.isInteger(p) || p < 0)) errors.push(`sink ${s.id}: bad argument positions`);
    const names = s.match.kind === "callee" ? s.match.names : s.match.kind === "prefix" ? [s.match.prefix].filter(Boolean)
      : s.match.kind === "constructor" ? s.match.classes : s.match.kind === "pattern" ? [s.match.pattern].filter(Boolean) : s.match.methods;
    if (names.length === 0 && !(s.match.kind === "module" && s.match.bare)) errors.push(`sink ${s.id}: empty match`);
    const pattern = s.match.kind === "receiver" ? s.match.receiver : s.match.kind === "pattern" ? s.match.pattern : null;
    if (pattern !== null) { try { new RegExp(pattern); } catch { errors.push(`sink ${s.id}: ${s.match.kind === "receiver" ? "receiver pattern" : "pattern"} doesn't compile`); } }
    for (const [, k] of (s.label ?? "").matchAll(/\{(\w*)\}/g)) {
      if (!["callee", "method", "receiver", "receiverRoot"].includes(k)) errors.push(`sink ${s.id}: unknown label field "{${k}}"`);
    }
    const when = s.args.whenArg;
    if (when) {
      if (!Number.isInteger(when.index) || when.index < 0) errors.push(`sink ${s.id}: bad argument positions`);
      try { new RegExp(when.pattern); } catch { errors.push(`sink ${s.id}: whenArg pattern doesn't compile`); }
    }
    if (s.target !== undefined && s.target !== "host") errors.push(`sink ${s.id}: unknown target "${s.target}"`);
  }
  const propagatorIds = new Set<string>();
  for (const p of r.propagators) {
    if (propagatorIds.has(p.id)) errors.push(`propagator ${p.id}: duplicate id`);
    propagatorIds.add(p.id);
    if (!LANGS.includes(p.lang)) errors.push(`propagator ${p.id}: unknown language "${p.lang}"`);
    if (!PROPAGATOR_KINDS.includes(p.kind)) errors.push(`propagator ${p.id}: unknown kind "${p.kind}"`);
    if (p.names.length === 0 || p.names.some(n => !n.trim())) errors.push(`propagator ${p.id}: empty name`);
  }
  const ruleIds = new Set<string>();
  for (const rule of r.rules) {
    if (ruleIds.has(rule.id)) errors.push(`rule ${rule.id}: duplicate id`);
    ruleIds.add(rule.id);
    if (rule.sinkClass && !CLASS_NAMES.includes(rule.sinkClass)) errors.push(`rule ${rule.id}: unknown class "${rule.sinkClass}"`);
    if (rule.cwe !== null && !/^CWE-\d+$/.test(rule.cwe)) errors.push(`rule ${rule.id}: malformed CWE "${rule.cwe}"`);
    if (rule.languages.length > 0 && rule.cwe === null) errors.push(`rule ${rule.id}: reported by ${rule.languages.join(", ")} but has no CWE`);
  }
  return errors;
}
