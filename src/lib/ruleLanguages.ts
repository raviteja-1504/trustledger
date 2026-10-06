/**
 * Which data-flow engines can report each rule -- the "supported languages" of the rule catalog (/rules).
 *
 * Each list is checked by the compiler against that engine's own rule-id type in BOTH directions: an id the
 * engine can't emit fails `satisfies`, and an id the engine can emit but this list forgot fails the
 * `Exhaustive` check below. So the catalog can't drift from what the engines actually do.
 */
import type { AstTaintId } from "./astTaint";
import type { AstTaintPyId } from "./astTaintPython";
import type { AstTaintJavaId } from "./astTaintJava";
import type { AstTaintGoId } from "./astTaintGo";
import type { AstTaintCSharpId } from "./astTaintCSharp";
import type { AstTaintPHPId } from "./astTaintPHP";
import type { AstTaintRubyId } from "./astTaintRuby";
import type { AstTaintKotlinId } from "./astTaintKotlin";

const JS = ["sql-injection", "command-injection", "xss", "ssrf", "path-traversal", "open-redirect", "eval-exec", "header-injection", "nosql-injection", "mass-assignment", "redos", "timing-attack", "prototype-pollution", "jwt-none-alg", "bola-missing-ownership-check", "argument-injection"] as const satisfies readonly AstTaintId[];
const PY = ["sql-injection", "command-injection", "ssrf", "path-traversal", "open-redirect", "ssti", "xss", "header-injection", "nosql-injection", "ldap-injection", "xpath-injection", "redos", "eval-exec", "insecure-deserialization", "mass-assignment", "timing-attack", "jwt-none-alg", "bola-missing-ownership-check", "argument-injection", "xxe"] as const satisfies readonly AstTaintPyId[];
const JAVA = ["sql-injection", "command-injection", "xss", "ssrf", "path-traversal", "open-redirect", "insecure-deserialization", "ldap-injection", "xpath-injection", "bola-missing-ownership-check", "header-injection", "redos", "ssti", "mass-assignment", "timing-attack", "jwt-none-alg", "argument-injection", "weak-crypto", "eval-exec", "nosql-injection"] as const satisfies readonly AstTaintJavaId[];
const GO = ["sql-injection", "command-injection", "ssrf", "path-traversal", "open-redirect", "insecure-deserialization", "idor", "xss", "header-injection", "redos", "ssti", "eval-exec", "mass-assignment", "nosql-injection", "ldap-injection", "xpath-injection", "timing-attack", "jwt-none-alg", "weak-crypto", "argument-injection"] as const satisfies readonly AstTaintGoId[];
const CS = ["sql-injection", "command-injection", "xss", "ssrf", "path-traversal", "open-redirect", "insecure-deserialization", "ldap-injection", "xpath-injection", "header-injection", "nosql-injection", "mass-assignment", "redos", "timing-attack", "jwt-none-alg", "eval-exec", "ssti", "argument-injection", "bola-missing-ownership-check"] as const satisfies readonly AstTaintCSharpId[];
const PHP = ["sql-injection", "command-injection", "xss", "ssrf", "path-traversal", "open-redirect", "insecure-deserialization", "file-inclusion", "bola-missing-ownership-check", "header-injection", "ldap-injection", "nosql-injection", "xpath-injection", "eval-exec", "ssti", "mass-assignment", "redos", "timing-attack", "jwt-none-alg"] as const satisfies readonly AstTaintPHPId[];
const RUBY = ["sql-injection", "command-injection", "xss", "ssrf", "path-traversal", "open-redirect", "insecure-deserialization", "eval-exec", "ssti", "mass-assignment", "header-injection", "redos", "bola-missing-ownership-check", "timing-attack", "jwt-none-alg"] as const satisfies readonly AstTaintRubyId[];
// Kotlin reports the same JVM vocabulary as Java.
const KOTLIN = JAVA satisfies readonly AstTaintKotlinId[];

// Compile-time completeness: each resolves to `true` only when the list covers the engine's whole id type.
type Exhaustive<All, Listed> = [Exclude<All, Listed>] extends [never] ? true : { missing: Exclude<All, Listed> };
const _complete: [
  Exhaustive<AstTaintId, typeof JS[number]>, Exhaustive<AstTaintPyId, typeof PY[number]>, Exhaustive<AstTaintJavaId, typeof JAVA[number]>,
  Exhaustive<AstTaintGoId, typeof GO[number]>, Exhaustive<AstTaintCSharpId, typeof CS[number]>, Exhaustive<AstTaintPHPId, typeof PHP[number]>,
  Exhaustive<AstTaintRubyId, typeof RUBY[number]>, Exhaustive<AstTaintKotlinId, typeof KOTLIN[number]>,
] = [true, true, true, true, true, true, true, true];
void _complete;

export const DATA_FLOW_LANGUAGES: ReadonlyArray<{ language: string; ids: readonly string[] }> = [
  { language: "JavaScript/TypeScript", ids: JS }, { language: "Python", ids: PY }, { language: "Java", ids: JAVA },
  { language: "Go", ids: GO }, { language: "C#", ids: CS }, { language: "PHP", ids: PHP },
  { language: "Ruby", ids: RUBY }, { language: "Kotlin", ids: KOTLIN },
];

/** Languages whose data-flow engine can report `id` (empty for rules that aren't data-flow rules). */
export function dataFlowLanguages(id: string): string[] {
  return DATA_FLOW_LANGUAGES.filter(l => l.ids.includes(id)).map(l => l.language);
}
