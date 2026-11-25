/**
 * Fix suggestions and CWE lookup for scanner findings, split out of scanner.ts (Task 9, scanner modularization).
 * scanner.ts re-exports getFixSuggestions so existing importers are unchanged.
 */
import { APPSEC_FIXES } from "./appsecRules";
import { cweFor as cweEntryFor } from "./cweMap";
import type { FixSuggestion } from "./scanner";

// ── Security fix suggestions ──────────────────────────────────────────────────

export const FIX_MAP: Record<string, Omit<FixSuggestion, "vuln_id">> = {
  ...APPSEC_FIXES,
  "sql-injection": {
    title: "Use parameterised queries",
    description: "Replace string-interpolated SQL with parameterised statements to prevent injection.",
    code_before: "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
    code_after:  "db.query('SELECT * FROM users WHERE id = $1', [userId])",
    cwe: "CWE-89", effort: "low",
  },
  "xss": {
    title: "Sanitise HTML output",
    description: "Use a trusted sanitiser (DOMPurify, sanitize-html) before inserting user content into the DOM.",
    code_before: "element.innerHTML = userInput",
    code_after:  "element.innerHTML = DOMPurify.sanitize(userInput)",
    cwe: "CWE-79", effort: "low",
  },
  "hardcoded-secret": {
    title: "Move secret to environment variable",
    description: "Remove hardcoded credential and load it from process.env or a secrets manager.",
    code_before: 'const apiKey = "sk_live_abc123"',
    code_after:  "const apiKey = process.env.API_KEY",
    cwe: "CWE-798", effort: "low",
  },
  "command-injection": {
    title: "Use execFile instead of exec",
    description: "Pass arguments as an array to execFile/spawn to avoid shell interpolation.",
    code_before: "exec(`ls ${userPath}`)",
    code_after:  "execFile('ls', [userPath])",
    cwe: "CWE-78", effort: "low",
  },
  "path-traversal": {
    title: "Resolve and validate the canonical path",
    description: "Call path.resolve() then verify the result starts with the expected base directory.",
    code_before: "fs.readFile(req.params.file)",
    code_after:  "const safe = path.resolve(BASE, req.params.file);\nif (!safe.startsWith(BASE)) throw new Error('Forbidden');",
    cwe: "CWE-22", effort: "low",
  },
  "eval-exec": {
    title: "Eliminate eval / Function constructor",
    description: "Refactor to avoid dynamic code execution; use a data-driven approach instead.",
    cwe: "CWE-95", effort: "medium",
  },
  "weak-crypto": {
    title: "Upgrade to SHA-256 or stronger",
    description: "Replace MD5/SHA-1 with crypto.createHash('sha256') for integrity hashing.",
    code_before: "crypto.createHash('md5')",
    code_after:  "crypto.createHash('sha256')",
    cwe: "CWE-327", effort: "low",
  },
  "ssrf": {
    title: "Validate and allowlist outbound URLs",
    description: "Parse the URL and verify the hostname is in an explicit allowlist before fetching.",
    cwe: "CWE-918", effort: "medium",
  },
  "insecure-deserialization": {
    title: "Replace unsafe deserialise with JSON.parse",
    description: "Avoid node-serialize / unserialize; use JSON.parse with schema validation.",
    cwe: "CWE-502", effort: "medium",
  },
  "prototype-pollution": {
    title: "Validate merge keys before deep-merge",
    description: "Check that no key equals '__proto__', 'constructor', or 'prototype' before merging.",
    cwe: "CWE-1321", effort: "low",
  },
  "open-redirect": {
    title: "Validate redirect target against allowlist",
    description: "Compare parsed hostname against an explicit allowlist; reject or strip unknown hosts.",
    cwe: "CWE-601", effort: "low",
  },
  "weak-cors": {
    title: "Restrict CORS origin to known domains",
    description: "Replace wildcard Access-Control-Allow-Origin with an explicit allowlist.",
    code_before: 'res.setHeader("Access-Control-Allow-Origin", "*")',
    code_after:  'res.setHeader("Access-Control-Allow-Origin", "https://app.example.com")',
    cwe: "CWE-942", effort: "low",
  },
  "backdoor-detection": {
    title: "Remove suspicious conditional / exfiltration code",
    description: "Logic bomb or covert data exfiltration pattern detected. Review and remove immediately.",
    cwe: "CWE-506", effort: "high",
  },
  "watermark-detection": {
    title: "Strip invisible Unicode watermark characters",
    description: "Remove zero-width / soft-hyphen / word-joiner characters embedded as AI watermarks.",
    effort: "low",
  },
  "xxe": {
    title: "Disable external entity resolution",
    description: "Call setFeature(...) to disable DOCTYPE/external-entity processing before parsing untrusted XML.",
    code_before: "DocumentBuilderFactory.newInstance()",
    code_after:  'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\ndbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
    cwe: "CWE-611", effort: "low",
  },
  "trust-boundary": {
    title: "Validate before storing request data in the session",
    description: "Keep session keys fixed and validate (or allowlist) any request value before saving it as server-side state; code reading the session treats it as trusted.",
    code_before: "session[request.args['key']] = request.args['value']",
    code_after:  "if role not in ALLOWED_ROLES: abort(400)\nsession['role'] = role",
    cwe: "CWE-501", effort: "low",
  },
  "insecure-file-upload": {
    title: "Validate uploaded file type and size",
    description: "Check file extension and content-type against an allowlist, enforce a size limit, and store outside the web root with a generated filename.",
    cwe: "CWE-434", effort: "low",
  },
  "log-injection": {
    title: "Strip line breaks before logging request input",
    description: "Replace CR/LF in user-supplied values before they reach the log, or log structured JSON so each value stays one field of one entry.",
    code_before: 'console.log("login failed for", userName)',
    code_after:  'console.log("login failed for", userName.replace(/[\\r\\n]/g, "_"))',
    cwe: "CWE-117", effort: "low",
  },
  "unsafe-reflection": {
    title: "Map input to an allow-list instead of calling it by name",
    description: "Never pass request input to send / public_send / const_get / constantize / Class.forName; look the action up in a fixed hash of allowed names.",
    code_before: "obj.send(params[:action])",
    code_after:  "ACTIONS = { 'archive' => :archive }.freeze\nobj.public_send(ACTIONS.fetch(params[:action]))",
    cwe: "CWE-470", effort: "low",
  },
  "file-inclusion": {
    title: "Load code only from a fixed list",
    description: "Don't build an include / require / load path from input; map the requested name to a known file.",
    code_before: "load(\"plugins/#{params[:plugin]}.rb\")",
    code_after:  "PLUGINS = { 'csv' => 'plugins/csv.rb' }.freeze\nload(PLUGINS.fetch(params[:plugin]))",
    cwe: "CWE-98", effort: "low",
  },
  "variable-overwrite": {
    title: "Read expected keys explicitly instead of extract() / $$",
    description: "Don't turn request keys into variables; read each expected key ($in['lang'] ?? 'en'), or use EXTR_SKIP / an EXTR_PREFIX_* flag.",
    code_before: "extract($_POST);",
    code_after:  "$lang = $_POST['lang'] ?? 'en';",
    cwe: "CWE-621", effort: "low",
  },
  "type-juggling": {
    title: "Compare strictly",
    description: "Use === / !== for input, hash_equals() for hashes and tokens, and validate numbers with filter_var(FILTER_VALIDATE_INT) first.",
    code_before: "if ($token == $expected) { ... }",
    code_after:  "if (hash_equals($expected, (string) $token)) { ... }",
    cwe: "CWE-1024", effort: "low",
  },
  "race-condition": {
    title: "Synchronise writes to shared state",
    description: "Guard a variable shared between goroutines / threads with a mutex, or use sync.Map / atomic / a channel owned by one goroutine.",
    code_before: "go func() { counts[key]++ }()",
    code_after:  "go func() { mu.Lock(); counts[key]++; mu.Unlock() }()",
    cwe: "CWE-362", effort: "low",
  },
  "type-confusion": {
    title: "Check the type of a request parameter before using it as a string",
    description: "Express's query/body parsers return an array or object for `?x[]=…`; a `typeof x === \"string\"` check (or schema validation) first makes the blocklist or string method mean what it says.",
    code_before: "if (BAD.some(b => name.includes(b))) return res.sendStatus(400);",
    code_after:  "if (typeof name !== \"string\" || BAD.some(b => name.includes(b))) return res.sendStatus(400);",
    cwe: "CWE-1287", effort: "low",
  },
  "input-validation": {
    title: "Check an index against the bounds first",
    description: "Reject an attacker-chosen index outside 0 <= i < len(items) before using it.",
    code_before: "v := items[i]",
    code_after:  "if i < 0 || i >= len(items) { return errBadIndex }\nv := items[i]",
    cwe: "CWE-129", effort: "low",
  },
  "csrf": {
    title: "Require a CSRF token on state-changing requests",
    description: "Verify a per-session CSRF token (gorilla/csrf, nosurf, framework middleware), check the Origin header, or set the session cookie SameSite=Strict.",
    code_before: "http.HandleFunc(\"/email\", updateEmail)",
    code_after:  "http.Handle(\"/email\", csrf.Protect(key)(http.HandlerFunc(updateEmail)))",
    cwe: "CWE-352", effort: "medium",
  },
  "directory-listing": {
    title: "Serve named files, not a browsable index",
    description: "Remove the directory-index middleware (serve-index, UseDirectoryBrowser, show_indexes) and serve only the files that are meant to be public.",
    code_before: "app.use('/ftp', serveIndex('ftp'))",
    code_after:  "app.use('/ftp/:file', serveAllowedFile)",
    cwe: "CWE-548", effort: "low",
  },
  "webview-insecure-settings": {
    title: "Keep WebView file access off",
    description: "Leave allowFileAccessFromFileURLs and allowUniversalAccessFromFileURLs false (the default since API 16) and load local content through WebViewAssetLoader.",
    code_before: "settings.allowUniversalAccessFromFileURLs = true",
    code_after:  "settings.allowUniversalAccessFromFileURLs = false",
    cwe: "CWE-749", effort: "low",
  },
  "format-string": {
    title: "Pass untrusted text as an argument, never as the format",
    description: "Use a constant format string and pass the value through %s, so %n / %x in the input are printed, not interpreted.",
    code_before: "printf(data);",
    code_after:  'printf("%s", data);',
    cwe: "CWE-134", effort: "low",
  },
  "buffer-overflow": {
    title: "Bound every copy by the destination's size",
    description: "Replace gets/strcpy/strcat/sprintf and unbounded %s with fgets, snprintf or strlcpy, and check any length against sizeof(destination) before memcpy.",
    code_before: "strcpy(dest, input);",
    code_after:  'snprintf(dest, sizeof(dest), "%s", input);',
    cwe: "CWE-120", effort: "low",
  },
  "integer-overflow": {
    title: "Check sizes against an upper bound before allocating",
    description: "Reject sizes above a sane limit (and multiplications that would wrap) before passing them to malloc, new[] or memcpy.",
    code_before: "char *p = malloc(n);",
    code_after:  "if (n == 0 || n > MAX_LEN) return -1;\nchar *p = malloc(n);",
    cwe: "CWE-789", effort: "low",
  },
  "cleartext-sensitive-storage": {
    title: "Don't store secrets in plain files or preferences",
    description: "Keep credentials out of storage entirely (use a token from the server), or use EncryptedSharedPreferences / EncryptedFile backed by the Android Keystore; never write them to external storage.",
    code_before: "FileWriter(file).write(\"password is \" + password.text)",
    code_after:  "EncryptedSharedPreferences.create(ctx, \"auth\", masterKey, AES256_SIV, AES256_GCM).edit().putString(\"token\", token).apply()",
    cwe: "CWE-312", effort: "medium",
  },
  "sensitive-clipboard": {
    title: "Keep secrets off the clipboard",
    description: "Don't copy OTPs, card numbers or passwords; if you must, mark the clip sensitive (EXTRA_IS_SENSITIVE) and clear it after a short time.",
    code_before: "clipboard.setPrimaryClip(ClipData.newPlainText(\"OTP\", otp))",
    code_after:  "val clip = ClipData.newPlainText(\"OTP\", otp)\nclip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }",
    cwe: "CWE-200", effort: "low",
  },
  "session-fixation": {
    title: "Regenerate the session id at login",
    description: "Mark the session as authenticated only inside req.session.regenerate(), so the pre-login id is discarded.",
    code_before: "req.session.userId = user._id;",
    code_after:  "req.session.regenerate(err => {\n  if (err) return next(err);\n  req.session.userId = user._id;\n});",
    cwe: "CWE-384", effort: "low",
  },
  "missing-function-level-authz": {
    title: "Register the guarded route only",
    description: "Remove the unguarded registration (Express serves the first match) so the role check runs on every request.",
    code_before: "app.get('/benefits', isLoggedIn, h);\napp.get('/benefits', isLoggedIn, isAdmin, h);",
    code_after:  "app.get('/benefits', isLoggedIn, isAdmin, h);",
    cwe: "CWE-285", effort: "low",
  },
  "rate-limit-bypass": {
    title: "Key the rate limiter on the proxy-verified client address",
    description: "Set Express's 'trust proxy' to the number of proxies in front of the app and let the limiter use req.ip; never read X-Forwarded-For yourself.",
    code_before: "keyGenerator: (req) => req.headers['x-forwarded-for'] ?? req.ip",
    code_after:  "app.set('trust proxy', 1)\n// default keyGenerator uses req.ip",
    cwe: "CWE-348", effort: "low",
  },
  "unauthenticated-diagnostics": {
    title: "Protect or move diagnostics endpoints",
    description: "Put metrics / actuator / debug routes behind authentication, or serve them on an internal-only port the load balancer doesn't expose.",
    code_before: "app.get('/metrics', serveMetrics())",
    code_after:  "app.get('/metrics', requireMetricsToken, serveMetrics())",
    cwe: "CWE-497", effort: "low",
  },
  "arithmetic-overflow": {
    title: "Use checked arithmetic on request-chosen integers",
    description: "Use checked_mul / checked_add / checked_shl / checked_pow and reject the None case, or bound the value first; convert between integer types with try_from instead of `as`.",
    code_before: "let total = qty * price;",
    code_after:  "let total = qty.checked_mul(price).ok_or(Error::Overflow)?;",
    cwe: "CWE-190", effort: "low",
  },
  "use-after-free": {
    title: "Don't touch memory after freeing it",
    description: "Set the pointer to NULL right after free and restructure so no path reads it afterwards; in C++ prefer std::unique_ptr.",
    code_before: "free(p);\nuse(p);",
    code_after:  "use(p);\nfree(p);\np = NULL;",
    cwe: "CWE-416", effort: "medium",
  },
  "double-free": {
    title: "Free each allocation exactly once",
    description: "Null the pointer after free (free(NULL) is a no-op) or give the allocation a single owner.",
    code_before: "free(p);\n...\nfree(p);",
    code_after:  "free(p);\np = NULL;",
    cwe: "CWE-415", effort: "low",
  },
  "null-dereference": {
    title: "Check allocator results for NULL",
    description: "malloc/calloc/realloc return NULL on failure; test the result before using it.",
    code_before: "int *p = malloc(sizeof *p);\n*p = 5;",
    code_after:  "int *p = malloc(sizeof *p);\nif (p == NULL) return -1;\n*p = 5;",
    cwe: "CWE-690", effort: "low",
  },
  "mismatched-deallocation": {
    title: "Release memory with the matching routine",
    description: "malloc pairs with free, new with delete, new[] with delete[]; in C++ prefer std::vector / smart pointers.",
    code_before: "int *a = new int[10];\ndelete a;",
    code_after:  "int *a = new int[10];\ndelete[] a;",
    cwe: "CWE-762", effort: "low",
  },
  "insecure-temp-file": {
    title: "Create temporary files atomically",
    description: "Use mkstemp (or tmpfile) which creates and opens the file in one step, instead of generating a name with tmpnam/mktemp.",
    code_before: "char *name = tmpnam(NULL);\nFILE *f = fopen(name, \"w\");",
    code_after:  "char name[] = \"/tmp/appXXXXXX\";\nint fd = mkstemp(name);",
    cwe: "CWE-377", effort: "low",
  },
  "ldap-injection": {
    title: "Escape LDAP special characters or use parameterised filters",
    description: "Never concatenate user input into an LDAP filter string — escape special characters (*, (, ), \\, NUL) first.",
    cwe: "CWE-90", effort: "low",
  },
  "idor": {
    title: "Verify the caller owns the requested resource",
    description: "Check the authenticated user's ID against the resource's owner field before returning or modifying it.",
    code_before: "repo.findById(id)",
    code_after:  "repo.findById(id).filter(r -> r.getOwnerId().equals(currentUser.getId()))",
    cwe: "CWE-639", effort: "medium",
  },
  "php-missing-session-guard": {
    title: "Add a session/auth guard before this sensitive action",
    description: "Check for an authenticated session before performing a database write, unserialize(), or file write.",
    code_before: "mysqli_query($conn, \"DELETE FROM users WHERE id=$id\");",
    code_after:  "if (!isset($_SESSION['user_id'])) { header('Location: /login'); exit; }\nmysqli_query($conn, \"DELETE FROM users WHERE id=$id\");",
    cwe: "CWE-306", effort: "low",
  },
  "bola-missing-ownership-check": {
    title: "Verify the caller owns the requested resource before this Spring endpoint reads/writes it",
    description: "A @PathVariable/@RequestParam-sourced identifier reaches a repository/map lookup with no @PreAuthorize/@Secured/@RolesAllowed annotation and no .equals()/==/!= comparison against the authenticated principal anywhere in the method body.",
    code_before: "users.get(userId)",
    code_after:  "if (!userId.equals(authentication.getName())) return ResponseEntity.status(403).build();\nusers.get(userId)",
    cwe: "CWE-639", effort: "medium",
  },
  "nosql-injection": {
    title: "Validate query shape with a schema before passing to the driver",
    description: "Never pass a raw request body/params object as a MongoDB query — validate it against an expected schema first.",
    cwe: "CWE-943", effort: "medium",
  },
  "ssti": {
    title: "Use static templates, never user input as a template string",
    description: "Pass user data as template variables, not as the template source itself.",
    cwe: "CWE-1336", effort: "medium",
  },
  "xpath-injection": {
    title: "Use XPath variable binding instead of string concatenation",
    description: "Pass user input through an XPathVariableResolver rather than concatenating it into the expression string.",
    cwe: "CWE-643", effort: "medium",
  },
  "csrf-protection-disabled": {
    title: "Re-enable framework CSRF protection",
    description: "Remove the explicit disable and add per-request CSRF tokens for state-changing endpoints, exempting only true API-key-authenticated routes.",
    cwe: "CWE-352", effort: "medium",
  },
  // ── IaC security (Terraform + Kubernetes) ──────────────────────────────────
  "iac-s3-public-acl": {
    title: "Remove the public-read ACL",
    description: "Use a bucket policy with least privilege instead of a bucket-wide public ACL.",
    code_before: 'resource "aws_s3_bucket_acl" "x" {\n  acl = "public-read"\n}',
    code_after:  'resource "aws_s3_bucket_acl" "x" {\n  acl = "private"\n}',
    cwe: "CWE-284", effort: "low",
  },
  "iac-open-ingress": {
    title: "Restrict the ingress CIDR block",
    description: "Scope cidr_blocks to the specific IP ranges that need access instead of 0.0.0.0/0, or put the resource behind a load balancer/VPN.",
    code_before: 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}',
    code_after:  'ingress {\n  cidr_blocks = ["10.0.0.0/16"]\n}',
    cwe: "CWE-284", effort: "medium",
  },
  "iac-unencrypted-storage": {
    title: "Enable server-side encryption",
    description: "Add an aws_s3_bucket_server_side_encryption_configuration resource, or set storage_encrypted = true for a database instance.",
    code_before: 'resource "aws_db_instance" "x" {\n  # storage_encrypted not set\n}',
    code_after:  'resource "aws_db_instance" "x" {\n  storage_encrypted = true\n}',
    cwe: "CWE-311", effort: "low",
  },
  "iac-iam-wildcard": {
    title: "Scope the IAM policy to specific actions/resources",
    description: "Replace the wildcard Action/Resource with the exact set your workload needs (least privilege).",
    code_before: '{ "Effect": "Allow", "Action": "*", "Resource": "*" }',
    code_after:  '{ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::my-bucket/*" }',
    cwe: "CWE-732", effort: "medium",
  },
  "iac-public-db": {
    title: "Disable public accessibility on the database instance",
    description: "Set publicly_accessible = false and reach the database through a VPN/bastion/private subnet instead.",
    code_before: "publicly_accessible = true",
    code_after:  "publicly_accessible = false",
    cwe: "CWE-284", effort: "low",
  },
  "iac-privileged-container": {
    title: "Remove privileged mode",
    description: "Grant only the specific Linux capabilities the container actually needs instead of full privileged access.",
    code_before: "securityContext:\n  privileged: true",
    code_after:  "securityContext:\n  privileged: false\n  capabilities:\n    add: [\"NET_BIND_SERVICE\"]",
    cwe: "CWE-250", effort: "medium",
  },
  "iac-container-run-as-root": {
    title: "Run the container as a non-root user",
    description: "Set runAsNonRoot: true and a non-zero runAsUser in the pod/container security context.",
    code_before: "securityContext:\n  runAsUser: 0",
    code_after:  "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
    cwe: "CWE-250", effort: "low",
  },
  "iac-host-namespace-access": {
    title: "Remove host namespace sharing",
    description: "Set hostNetwork/hostPID/hostIPC to false (or omit them) unless the workload has a specific, reviewed need for host-level access.",
    code_before: "hostNetwork: true",
    code_after:  "hostNetwork: false",
    cwe: "CWE-668", effort: "medium",
  },
  "iac-dangerous-capability": {
    title: "Drop the dangerous capability",
    description: "Remove ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_MODULE from the container's added capabilities unless specifically required and reviewed.",
    code_before: "capabilities:\n  add: [\"SYS_ADMIN\"]",
    code_after:  "capabilities:\n  drop: [\"ALL\"]",
    cwe: "CWE-250", effort: "medium",
  },
  "iac-unpinned-image-tag": {
    title: "Pin the image to a specific version or digest",
    description: "Replace the mutable :latest tag (or missing tag) with a specific version tag or, better, a content digest.",
    code_before: "image: nginx:latest",
    code_after:  "image: nginx:1.25.3@sha256:2ab30d...",
    cwe: "CWE-1104", effort: "low",
  },

  // ── Container security (Dockerfile + docker-compose.yml) ──────────────────
  "container-runs-as-root": {
    title: "Add a non-root USER instruction",
    description: "Set a USER instruction before the final CMD/ENTRYPOINT so the container doesn't run as root (UID 0) by default.",
    code_before: "FROM node:20-alpine\n# no USER instruction",
    code_after:  "FROM node:20-alpine\nRUN addgroup -S app && adduser -S app -G app\nUSER app",
    cwe: "CWE-250", effort: "low",
  },
  "container-unpinned-base-image": {
    title: "Pin the base image to a specific version or digest",
    description: "Replace the mutable :latest tag (or missing tag) with a specific version tag or, better, a content digest.",
    code_before: "FROM node:latest",
    code_after:  "FROM node:20.11.1-alpine@sha256:2ab30d...",
    cwe: "CWE-1104", effort: "low",
  },
  "container-add-remote-url": {
    title: "Replace ADD-from-URL with a verified download",
    description: "Use COPY with a locally-verified file, or fetch and checksum-verify the file in a RUN step, instead of ADD pulling directly from a remote URL with no integrity check.",
    code_before: "ADD https://example.com/install.sh /install.sh",
    code_after:  "RUN curl -fsSL https://example.com/install.sh -o /install.sh \\\n  && echo \"<expected-sha256>  /install.sh\" | sha256sum -c -",
    cwe: "CWE-494", effort: "low",
  },
  "container-piped-shell-exec": {
    title: "Verify remote scripts before executing them",
    description: "Download the script to a file, verify its checksum or signature, then execute it — don't pipe curl/wget output directly into a shell.",
    code_before: "RUN curl -fsSL https://example.com/install.sh | sh",
    code_after:  "RUN curl -fsSL https://example.com/install.sh -o install.sh \\\n  && echo \"<expected-sha256>  install.sh\" | sha256sum -c - \\\n  && sh install.sh",
    cwe: "CWE-494", effort: "medium",
  },
  "container-hardcoded-secret": {
    title: "Move the secret out of the Dockerfile",
    description: "Pass secrets via BuildKit's --secret mount (build time) or a runtime environment variable/orchestrator secret (run time) — never bake a credential into an ENV/ARG value, which persists in the image/build history.",
    code_before: "ENV API_KEY=sk_live_abc123",
    code_after:  "# docker build --secret id=api_key,src=./api_key.txt\nRUN --mount=type=secret,id=api_key cat /run/secrets/api_key",
    cwe: "CWE-798", effort: "medium",
  },
  "container-sensitive-file-copy": {
    title: "Don't copy credential/key files into the image",
    description: "Add the file to .dockerignore and pass its contents at runtime (an orchestrator secret, a mounted volume, or an environment variable) instead of baking it into a layer.",
    code_before: "COPY .env /app/.env",
    code_after:  "# .env added to .dockerignore; passed at runtime via --env-file or a secret",
    cwe: "CWE-538", effort: "low",
  },
  "container-exposed-sensitive-port": {
    title: "Remove the sensitive EXPOSE if unintentional",
    description: "Confirm this management port is meant to be reachable from outside the container before shipping it; if not, drop the EXPOSE instruction.",
    code_before: "EXPOSE 22",
    code_after:  "# SSH not exposed from the container",
    cwe: "CWE-668", effort: "low",
  },
  "container-compose-privileged": {
    title: "Remove privileged mode",
    description: "Grant only the specific Linux capabilities the service actually needs instead of full privileged access.",
    code_before: "services:\n  app:\n    privileged: true",
    code_after:  "services:\n  app:\n    cap_add: [\"NET_BIND_SERVICE\"]",
    cwe: "CWE-250", effort: "medium",
  },
  "container-compose-docker-socket-mount": {
    title: "Remove the Docker socket mount",
    description: "Avoid mounting /var/run/docker.sock into a container — it grants root-equivalent host control. If a service genuinely needs to manage containers, use a scoped Docker API proxy instead.",
    code_before: "volumes:\n  - /var/run/docker.sock:/var/run/docker.sock",
    code_after:  "# docker.sock not mounted; use a scoped Docker API proxy if container management is required",
    cwe: "CWE-269", effort: "high",
  },
  "container-compose-host-namespace": {
    title: "Remove host namespace sharing",
    description: "Set network_mode/pid/ipc to a non-host value (or omit them) unless the service has a specific, reviewed need for host-level access.",
    code_before: "network_mode: host",
    code_after:  "# default (bridge) network mode",
    cwe: "CWE-668", effort: "medium",
  },
  "container-compose-dangerous-capability": {
    title: "Drop the dangerous capability",
    description: "Remove ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_MODULE from the service's added capabilities unless specifically required and reviewed.",
    code_before: "cap_add:\n  - SYS_ADMIN",
    code_after:  "cap_drop:\n  - ALL",
    cwe: "CWE-250", effort: "medium",
  },
  "container-compose-hardcoded-secret": {
    title: "Move the secret out of the compose file",
    description: "Use env_file, Docker Compose secrets, or an external secret manager instead of a literal credential value under environment:.",
    code_before: "environment:\n  - DB_PASSWORD=hunter2",
    code_after:  "environment:\n  - DB_PASSWORD_FILE=/run/secrets/db_password\nsecrets:\n  - db_password",
    cwe: "CWE-798", effort: "low",
  },
  "container-compose-unpinned-image": {
    title: "Pin the image to a specific version or digest",
    description: "Replace the mutable :latest tag (or missing tag) with a specific version tag or, better, a content digest.",
    code_before: "image: postgres:latest",
    code_after:  "image: postgres:16.2@sha256:2ab30d...",
    cwe: "CWE-1104", effort: "low",
  },
};

export function getFixSuggestions(indicators: readonly { id: string }[]): FixSuggestion[] {
  const seen = new Set<string>();
  const out: FixSuggestion[] = [];
  for (const ind of indicators) {
    if (seen.has(ind.id)) continue;
    const fix = FIX_MAP[ind.id];
    if (fix) { out.push({ vuln_id: ind.id, ...fix }); seen.add(ind.id); }
  }
  return out;
}

// CWE reference for vulnerability ids that don't already carry one via
// FIX_MAP (checked first, so the mapping isn't maintained in two places).
// Ids not in FIX_MAP fall back to the shared client-safe map (./cweMap)
// that the Risk Register page also reads from directly, so a finding's
// CWE classification is the same wherever it's shown.
export function cweFor(id: string): string | undefined {
  return FIX_MAP[id]?.cwe ?? cweEntryFor(id)?.id;
}
