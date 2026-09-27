// ── Authorization state: WHAT kind of check protects an object lookup ────────────────────────────────────────
//
// Broken Object Level Authorization is "the caller can name an object id, and nothing establishes that THIS
// caller may touch THAT object". The old detector asked one question -- is the id compared to the principal
// before the lookup? -- so the ways real code actually enforces ownership all looked like "no check":
//
//     Doc.findOne({ _id: id, owner: req.user.id })            ownership is IN the query (the most common secure form)
//     const d = await Doc.findById(id);
//     if (String(d.ownerId) !== req.user.id) return 403       ownership is checked on the LOADED record
//
// and a role gate (`if (req.user.role !== "admin") return 403`) looked identical to no gate, although it is a real
// -- if different -- control: it limits WHO reaches the lookup but says nothing about WHICH objects they may read.
//
// So evidence is classified, engine-independently, into what it actually establishes:
//   ownership : this principal owns/is-scoped-to this object            -> the lookup is protected
//   role      : the principal holds some role/permission                 -> a real control, but not object-level
// and the verdict is proven / role-only / unchecked. Engines gather the evidence from their own ASTs (a query
// argument, a dominating branch, a route middleware); this module owns the vocabulary and the verdict so the
// JS/TS and Python engines cannot drift apart on what counts.

export type AuthzKind = "ownership" | "role";
export type AuthzVerdict = "proven" | "role-only" | "unchecked";

/** Field names that denote "whose object is this" (a record's owner column, or a query's scoping key). */
const OWNER_FIELD_RE = /^(?:owner|owner_?id|user|user_?id|uid|created_?by|author|author_?id|account_?id|tenant_?id|org(?:ani[sz]ation)?_?id|customer_?id|member_?id|profile_?id)$/i;
export function isOwnerField(name: string): boolean {
  return OWNER_FIELD_RE.test(name);
}

// Guard names are judged by their WORDS (camelCase / snake_case / dotted), not substrings: a substring test calls
// `scanner` a `can`-guard and `oracle` an `acl`-guard.
const wordsOf = (name: string): string[] =>
  name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
/** Words that assert the caller owns the object. Checked BEFORE the role words because `selfOrAdmin` and
 * `requireOwner` contain words from both. */
const OWNERSHIP_WORDS = new Set(["owner", "owners", "ownership", "owns", "own", "mine", "self", "belongs"]);
/** Words that assert a role or permission, not an object relationship. */
const ROLE_WORDS = new Set([
  "admin", "admins", "role", "roles", "staff", "superuser", "permission", "permissions", "authorize", "authorise",
  "authorization", "policy", "policies", "ability", "scope", "scopes", "acl", "guard", "guards", "can", "cannot", "has", "allow",
  "allowed", "allows", "deny", "denies", "denied",
]);

/** Classify a middleware / decorator / guard-function NAME. null = not an authorization guard we recognize
 * (`authenticate` / `requireAuth` establish WHO the caller is, not what they may touch). */
export function classifyGuardName(name: string): AuthzKind | null {
  const words = wordsOf(name);
  if (words.some(w => OWNERSHIP_WORDS.has(w)) || words.join("").includes("sameuser")) return "ownership";
  if (words.some(w => ROLE_WORDS.has(w))) return "role";
  return null;
}

/** Does a condition's text read a role/permission feature of the principal (`user.role`, `isAdmin`, `hasPermission`)? */
const ROLE_FEATURE_RE = /\b(?:roles?|is_?admin|is_?staff|is_?superuser|permissions?|scopes?|has_?role|has_?perms?|has_?permission|has_?authority|groups?)\b/i;
export function mentionsRoleFeature(conditionText: string): boolean {
  return ROLE_FEATURE_RE.test(conditionText);
}

/** Lookups that mutate as they fetch: a check AFTER them arrives too late, only one BEFORE (or in the query) protects. */
const MUTATING_WORDS = new Set(["update", "delete", "remove", "destroy", "upsert", "save", "insert", "create", "set", "increment", "decrement", "patch"]);
export function isMutatingLookup(methodName: string): boolean {
  return wordsOf(methodName).some(w => MUTATING_WORDS.has(w));
}

/** Ownership anywhere protects the lookup; only a role/permission leaves it exposed at reduced severity. */
export function authzVerdict(evidence: ReadonlySet<AuthzKind>): AuthzVerdict {
  if (evidence.has("ownership")) return "proven";
  if (evidence.has("role")) return "role-only";
  return "unchecked";
}

/** Decorator / middleware names that establish WHO the caller is (and typically inject the principal as a parameter). */
const AUTHENTICATION_WORDS = new Set(["auth", "authenticated", "authentication", "login", "jwt", "token", "session"]);
export function isAuthenticationGuardName(name: string): boolean {
  return wordsOf(name).some(w => AUTHENTICATION_WORDS.has(w));
}

/** Parameter names that, under an authentication decorator, hold the authenticated principal. */
const PRINCIPAL_PARAM_NAMES = new Set(["user", "current_user", "currentuser", "principal", "auth_user"]);
export function isPrincipalParamName(name: string): boolean {
  return PRINCIPAL_PARAM_NAMES.has(name.toLowerCase());
}
