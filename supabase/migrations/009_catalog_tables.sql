-- ================================================================
-- Migration 009: dynamic catalog tables
-- Adds 5 catalog tables seeded with defaults from src/lib/*.
-- API routes read from these tables; lib files are the fallback.
-- ================================================================

-- ─── vuln_catalog ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vuln_catalog (
  id             text PRIMARY KEY,
  cve            text NOT NULL,
  cvss           numeric(4,1) NOT NULL,
  cvss_vector    text,
  epss_score     numeric(5,1),
  severity       text NOT NULL,
  category       text NOT NULL,
  cwe_id         text NOT NULL,
  cwe_label      text NOT NULL,
  title          text NOT NULL,
  description    text NOT NULL,
  pattern_desc   text,
  remediation    text NOT NULL,
  refs           text[] NOT NULL DEFAULT '{}',
  secure_rewrite jsonb,
  updated_at     timestamptz DEFAULT now()
);

ALTER TABLE vuln_catalog ENABLE ROW LEVEL SECURITY;
CREATE POLICY "vuln_catalog_select" ON vuln_catalog FOR SELECT USING (true);

-- ─── threat_catalog ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_catalog (
  id                 text    PRIMARY KEY,
  cve                text,
  title              text    NOT NULL,
  description        text    NOT NULL,
  severity           text    NOT NULL,
  category           text    NOT NULL,
  status             text    NOT NULL,
  cvss               numeric(4,1),
  epss_score         numeric(5,1),
  mitre_tactic       text,
  mitre_technique    text,
  sla_hours          int,
  published          date    NOT NULL,
  last_updated       date    NOT NULL,
  affected_pattern   text    NOT NULL,
  affected_languages text[]  NOT NULL DEFAULT '{}',
  in_your_codebase   boolean NOT NULL DEFAULT false,
  exploit_available  boolean NOT NULL DEFAULT false,
  exploit_in_wild    boolean NOT NULL DEFAULT false,
  refs               text[]  NOT NULL DEFAULT '{}',
  mitigation         text    NOT NULL,
  ai_specific        boolean NOT NULL DEFAULT true,
  relevance_score    int     NOT NULL DEFAULT 0,
  updated_at         timestamptz DEFAULT now()
);

ALTER TABLE threat_catalog ENABLE ROW LEVEL SECURITY;
CREATE POLICY "threat_catalog_select" ON threat_catalog FOR SELECT USING (true);

-- ─── compliance_frameworks ───────────────────────────────────────
-- controls JSONB uses {{ORG}} as a placeholder replaced at query time.

CREATE TABLE IF NOT EXISTS compliance_frameworks (
  id          text  PRIMARY KEY,
  short_name  text  NOT NULL,
  full_name   text  NOT NULL,
  standard    text  NOT NULL,
  color       text  NOT NULL,
  gradient    text  NOT NULL,
  header_bg   text  NOT NULL,
  cert_body   text  NOT NULL,
  next_audit  text  NOT NULL,
  cert_expiry text,
  controls    jsonb NOT NULL DEFAULT '[]',
  sort_order  int   NOT NULL DEFAULT 0,
  updated_at  timestamptz DEFAULT now()
);

ALTER TABLE compliance_frameworks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "compliance_frameworks_select" ON compliance_frameworks FOR SELECT USING (true);

-- ─── compliance_cross_themes ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS compliance_cross_themes (
  id          serial PRIMARY KEY,
  theme       text  NOT NULL,
  description text  NOT NULL,
  controls    jsonb NOT NULL,
  sort_order  int   NOT NULL DEFAULT 0
);

ALTER TABLE compliance_cross_themes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "cross_themes_select" ON compliance_cross_themes FOR SELECT USING (true);

-- ─── audit_event_config ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_event_config (
  event_type    text    PRIMARY KEY,
  label         text    NOT NULL,
  icon          text    NOT NULL,
  bg            text    NOT NULL,
  text_color    text    NOT NULL,
  border_color  text    NOT NULL,
  dot_color     text    NOT NULL,
  soc2_controls text[]  NOT NULL DEFAULT '{}',
  updated_at    timestamptz DEFAULT now()
);

ALTER TABLE audit_event_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY "audit_event_config_select" ON audit_event_config FOR SELECT USING (true);

-- ================================================================
-- Seed: vulnerability catalog
-- ================================================================

INSERT INTO vuln_catalog (id,cve,cvss,cvss_vector,epss_score,severity,category,cwe_id,cwe_label,title,description,pattern_desc,remediation,refs,secure_rewrite)
VALUES (
  'sql-injection','CVE-2023-20052',9.8,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',95.1,
  'CRITICAL','injection','CWE-89','SQL Injection',
  'SQL Injection via AI-generated dynamic query construction',
  'AI assistants frequently generate SQL queries using f-string interpolation or string concatenation with user-supplied input, bypassing parameterization entirely.',
  'Pattern: f"SELECT ... WHERE id = {user_input}" or query + user_var',
  'Replace all dynamic SQL with parameterized queries or ORM methods. Use SQLAlchemy, Prisma, or similar. Never interpolate user input into SQL strings.',
  ARRAY['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20052','https://owasp.org/www-community/attacks/SQL_Injection','https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
  $${"lang":"python","before":"# AI-generated — vulnerable\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)","after":"# Secure rewrite — parameterised\ncursor.execute(\n  \"SELECT * FROM users WHERE id = %s\",\n  (user_id,)\n)"}$$::jsonb
) ON CONFLICT (id) DO NOTHING;

INSERT INTO vuln_catalog (id,cve,cvss,cvss_vector,epss_score,severity,category,cwe_id,cwe_label,title,description,pattern_desc,remediation,refs,secure_rewrite)
VALUES (
  'jwt-none-alg','CVE-2022-21449',9.1,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',91.8,
  'CRITICAL','auth','CWE-347','Improper Verification of Cryptographic Signature',
  'JWT ''none'' algorithm bypass in AI-generated token verification',
  'AI models commonly generate JWT verification code that accepts the ''none'' algorithm or disables signature verification, allowing attackers to forge arbitrary tokens.',
  'Pattern: algorithms=["HS256", "none"] or verify_signature: False',
  'Explicitly whitelist only the expected algorithm (HS256 or RS256). Never include ''none''. Upgrade to PyJWT >= 2.8.0 or jsonwebtoken >= 9.0.0.',
  ARRAY['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449','https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/','https://nvd.nist.gov/vuln/detail/CVE-2022-21449'],
  $${"lang":"python","before":"# AI-generated — accepts 'none' algorithm\npayload = jwt.decode(\n  token, JWT_SECRET,\n  options={\"verify_signature\": False},\n  algorithms=[\"HS256\", \"none\"],\n)","after":"# Secure rewrite — strict algorithm\npayload = jwt.decode(\n  token, JWT_SECRET,\n  algorithms=[\"HS256\"],\n)"}$$::jsonb
) ON CONFLICT (id) DO NOTHING;

INSERT INTO vuln_catalog (id,cve,cvss,cvss_vector,epss_score,severity,category,cwe_id,cwe_label,title,description,pattern_desc,remediation,refs,secure_rewrite)
VALUES (
  'eval-exec','CVE-2021-44228',10.0,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',99.7,
  'CRITICAL','exec','CWE-95','Improper Neutralization of Directives in Dynamic Code',
  'Arbitrary code execution via AI-generated eval()/exec() usage',
  'AI assistants routinely generate code using eval() or exec() on user-controlled input. This enables remote code execution — one of the most severe vulnerability classes.',
  'Pattern: eval(user_input) / exec(formula) / new Function(code)()',
  'Replace eval/exec with safe alternatives: ast.literal_eval() for Python data, mathjs sandbox for expressions, or explicit parsing. Add bandit/eslint rule to flag eval/exec usage in CI.',
  ARRAY['https://owasp.org/www-community/attacks/Code_Injection','https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html','https://semgrep.dev/r?q=eval'],
  $${"lang":"python","before":"# AI-generated — arbitrary code execution\ndef calculate(expression: str) -> float:\n    return eval(expression)  # CRITICAL","after":"# Secure rewrite — safe expression parser\nimport ast\ndef calculate(expression: str) -> float:\n    tree = ast.parse(expression, mode=\"eval\")\n    return eval(compile(tree, \"\", \"eval\"),\n               {\"__builtins__\": {}}, {})"}$$::jsonb
) ON CONFLICT (id) DO NOTHING;

INSERT INTO vuln_catalog (id,cve,cvss,cvss_vector,epss_score,severity,category,cwe_id,cwe_label,title,description,pattern_desc,remediation,refs)
VALUES
  ('hardcoded-secret','CVE-2021-42013',9.8,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',88.4,
   'CRITICAL','secrets','CWE-798','Use of Hard-coded Credentials',
   'Hardcoded production credentials in AI-generated code',
   'AI models frequently embed production API keys, passwords, and tokens directly in source code — often trained on leaked credential patterns from public repositories.',
   'Pattern: API_KEY = "sk_live_..." / DB_PASSWORD = "prod_..." / JWT_SECRET = "..._2024"',
   'Rotate all exposed credentials immediately. Move secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler).',
   ARRAY['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42013','https://docs.gitguardian.com/secrets-detection','https://trufflesecurity.com/trufflehog']),
  ('structural-uniformity','CVE-2023-45133',8.1,'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N',28.3,
   'HIGH','supply-chain','CWE-1104','Use of Unmaintained Third-Party Components',
   'AI structural uniformity indicating copy-paste without security review',
   'Code blocks with unusually uniform structure and indentation indicate AI-generated output pasted without human modification.',
   'Pattern: identical block structure, predictable variable names, no human variation signatures',
   'Each AI-generated block must be individually reviewed by a qualified engineer.',
   ARRAY['https://owasp.org/www-project-top-ten/','https://cwe.mitre.org/data/definitions/1104.html']),
  ('ai-comment-pattern','CVE-2023-25136',7.5,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',42.1,
   'HIGH','access-control','CWE-862','Missing Authorization',
   'AI comment pattern indicating low-quality security implementation',
   'Over-commented, instructional-style code is a strong AI generation signature. AI models tend to over-explain logic while missing authorization checks and input validation.',
   'Pattern: excessive inline comments, TODO-style explanations, boilerplate security comments without implementation',
   'Review all AI-generated code for missing authorization middleware, unchecked return values, and missing input validation.',
   ARRAY['https://owasp.org/www-project-top-ten/','https://cwe.mitre.org/data/definitions/862.html']),
  ('comment-density','CVE-2022-36067',7.6,'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N',35.6,
   'MEDIUM','access-control','CWE-116','Improper Encoding or Escaping of Output',
   'High comment density — potential XSS via unescaped AI-generated output',
   'AI-generated template code with high comment density often renders user data directly into HTML without proper escaping, enabling cross-site scripting attacks.',
   'Pattern: template rendering without explicit escape, innerHTML assignment, unescaped string interpolation',
   'Use template engines that auto-escape output (Jinja2 with autoescape, React JSX). Never use innerHTML with user data. Implement a Content Security Policy (CSP).',
   ARRAY['https://owasp.org/www-community/attacks/xss/','https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html']),
  ('identifier-entropy','CVE-2023-44487',6.5,'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',22.9,
   'MEDIUM','crypto','CWE-327','Use of Broken Cryptographic Algorithm',
   'Low identifier entropy — AI suggests weak crypto or predictable tokens',
   'AI models trained on older code frequently suggest MD5 or SHA-1 for security-sensitive operations, and generate predictable token values using low-entropy sources like timestamps.',
   'Pattern: hashlib.md5(), crypto.createHash(''sha1''), Math.random() for security tokens',
   'Use SHA-256 or stronger for general hashing. Use bcrypt/scrypt/Argon2 for passwords. Use crypto.randomBytes() or secrets.token_urlsafe() for tokens.',
   ARRAY['https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html','https://nvd.nist.gov/vuln/detail/CVE-2023-44487'])
ON CONFLICT (id) DO NOTHING;

-- ================================================================
-- Seed: threat catalog
-- ================================================================

INSERT INTO threat_catalog (id,cve,title,description,severity,category,status,cvss,epss_score,mitre_tactic,mitre_technique,sla_hours,published,last_updated,affected_pattern,affected_languages,in_your_codebase,exploit_available,exploit_in_wild,refs,mitigation,ai_specific,relevance_score)
VALUES
  ('TI-001','CVE-2024-23897',
   'Jenkins CLI arbitrary file read via AI-generated argument parsing',
   'AI code assistants frequently generate Jenkins CLI argument parsers using unsanitized file paths. CVE-2024-23897 exploits this pattern to read arbitrary files on the Jenkins server including credentials.',
   'CRITICAL','ai-generated','active',9.8,97.4,'Initial Access','T1190',24,
   '2024-01-24','2026-05-20',
   'CLI argument parsing with direct file path construction',
   ARRAY['java','python'],true,true,true,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-23897','https://www.jenkins.io/security/advisory/2024-01-24/'],
   'Replace direct file path construction with validated Path objects. Update Jenkins to 2.442+. Scan all AI-generated CLI argument handlers.',
   true,94),
  ('TI-002','CVE-2024-21626',
   'runc container escape via AI-generated Dockerfile patterns',
   'AI code generators produce Dockerfile patterns that expose /proc/self/fd/ allowing container breakout. The Leaky Vessels vulnerability affects runc < 1.1.12 and is actively exploited.',
   'CRITICAL','zero-day','active',8.6,81.2,'Privilege Escalation','T1611',24,
   '2024-02-01','2026-05-25',
   'Dockerfile WORKDIR with /proc path access',
   ARRAY['dockerfile'],false,true,true,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-21626'],
   'Upgrade runc to 1.1.12+. Audit all AI-generated Dockerfiles for /proc/self/fd references. Add Dockerfile scanning to CI.',
   true,71),
  ('TI-003','CVE-2024-3094',
   'XZ Utils backdoor — AI package recommendation threat pattern',
   'AI tools recommend xz-utils as a standard compression library. The XZ supply chain attack (CVSS 10.0) demonstrates the risk of AI recommending packages without verifying maintainer integrity.',
   'CRITICAL','supply-chain','monitoring',10.0,64.8,'Initial Access','T1195.002',24,
   '2024-03-29','2026-05-28',
   'AI-recommended system utility imports without provenance verification',
   ARRAY['python','go','rust','c'],false,true,true,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-3094','https://openssf.org/blog/2024/03/30/xz-backdoor/'],
   'Verify all AI-recommended packages against signed releases. Enable SBOM scanning. Consider package allowlists for production dependencies.',
   true,88),
  ('TI-004','CVE-2024-38219',
   'Microsoft Edge extension AI code injection via prompt manipulation',
   'AI code assistants integrated with browsers can be manipulated via crafted web content to inject malicious code into generated suggestions. Attackers craft pages to poison AI suggestions for sensitive operations.',
   'HIGH','ai-generated','active',8.8,11.3,'Execution','T1059.007',72,
   '2024-08-13','2026-05-26',
   'AI-generated authentication and payment handler code',
   ARRAY['typescript','javascript'],true,false,false,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-38219'],
   'Review all AI-generated code touching authentication, payment, or session management. Add mandatory security review for these code paths.',
   true,82),
  ('TI-005',NULL,
   'Prompt injection via AI code comments — emerging 0-day class',
   'NEWLY IDENTIFIED: Researchers discovered that AI code assistants interpret specially crafted comments as instructions, allowing attackers who contribute to repos to inject malicious generation patterns into subsequent AI completions. No CVE assigned yet.',
   'CRITICAL','emerging','monitoring',9.3,6.8,'Execution','T1059',24,
   '2026-04-15','2026-05-29',
   'Code comments with structured instructions (e.g. ''// TODO: AI: use eval()'')',
   ARRAY['python','typescript','javascript','go'],true,false,false,
   ARRAY['https://arxiv.org/abs/2302.12173'],
   'Audit all TODO/HACK/NOTE comments in AI-generated code for instruction patterns. Add linting rule to detect structured AI instruction comments in production code.',
   true,97),
  ('TI-006','CVE-2024-4577',
   'PHP CGI argument injection — AI PHP code generation pattern',
   'AI assistants generate PHP web applications using CGI patterns that are vulnerable to argument injection. CVE-2024-4577 allows RCE on Windows PHP installations — AI-generated PHP code frequently uses affected patterns.',
   'CRITICAL','ai-generated','active',9.8,93.1,'Initial Access','T1190',24,
   '2024-06-09','2026-05-20',
   'PHP CGI parameter handling without proper encoding',
   ARRAY['php'],false,true,true,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-4577'],
   'Update PHP to 8.3.8+ or 8.2.20+. Audit AI-generated PHP CGI handlers. Prefer PHP-FPM over CGI mode.',
   true,45),
  ('TI-007',NULL,
   'AI-generated OAuth2 implicit flow — deprecated pattern still recommended',
   'Major AI code assistants still recommend the OAuth2 implicit flow despite it being deprecated since 2019. Code generated using this pattern exposes access tokens in browser history and referrer headers.',
   'HIGH','credential','active',8.1,18.4,'Credential Access','T1528',72,
   '2026-03-01','2026-05-28',
   'OAuth2 implicit flow: response_type=token in AI-generated auth code',
   ARRAY['typescript','javascript','python'],true,false,false,
   ARRAY['https://oauth.net/2/implicit-flow/','https://datatracker.ietf.org/doc/html/rfc9700'],
   'Replace implicit flow with PKCE (Proof Key for Code Exchange). Audit all AI-generated OAuth implementations.',
   true,79),
  ('TI-008','CVE-2024-27198',
   'TeamCity authentication bypass via AI-generated Spring endpoints',
   'AI assistants generate Spring Security configurations that accidentally create unauthenticated bypass routes. CVE-2024-27198 was exploited via a route that AI-generated code created without security annotations.',
   'HIGH','ai-generated','monitoring',9.8,88.6,'Initial Access','T1190',72,
   '2024-03-04','2026-05-15',
   '@RequestMapping without @Secured or @PreAuthorize on admin routes',
   ARRAY['java'],false,true,true,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-27198'],
   'Audit all AI-generated Spring endpoints for missing security annotations. Enforce SecurityConfig that denies by default.',
   true,38),
  ('TI-009',NULL,
   'AI training data poisoning via public repository code commits',
   'Researchers confirmed that attackers are deliberately committing vulnerable code patterns to public GitHub repositories to poison AI training datasets. This causes models to generate the vulnerable patterns in future code suggestions.',
   'MEDIUM','emerging','monitoring',6.5,3.2,'Resource Development','T1195.001',168,
   '2026-05-01','2026-05-30',
   'Subtle variations of known-vulnerable patterns in public repos',
   ARRAY['python','javascript','go','rust'],false,false,true,
   ARRAY['https://arxiv.org/abs/2305.14082'],
   'Subscribe to AI model security bulletins. Cross-reference generated code against NIST NVD. Mandate TrustLedger scanning on every PR regardless of AI% detected.',
   true,91),
  ('TI-010','CVE-2024-10224',
   'Perl cpanel-json-xs RCE — AI dependency suggestion vulnerability',
   'AI tools frequently recommend cpanel-json-xs as a high-performance JSON library. Version < 4.0.2 contains an RCE via crafted JSON input. The issue is patched but AI models still suggest the vulnerable version.',
   'HIGH','supply-chain','patched',7.8,38.7,'Execution','T1203',72,
   '2024-11-21','2026-04-01',
   'AI-recommended cpanel-json-xs without version pinning',
   ARRAY['perl','python'],false,true,false,
   ARRAY['https://nvd.nist.gov/vuln/detail/CVE-2024-10224'],
   'Pin cpanel-json-xs >= 4.0.2 in all Perl/Python projects. Add dep-version scanning to CI.',
   false,22)
ON CONFLICT (id) DO NOTHING;

-- ================================================================
-- Seed: compliance frameworks ({{ORG}} replaced by API at query time)
-- ================================================================

INSERT INTO compliance_frameworks (id,short_name,full_name,standard,color,gradient,header_bg,cert_body,next_audit,controls,sort_order)
VALUES (
  'soc2','SOC 2','SOC 2 Type II','AICPA Trust Services Criteria 2017',
  '#6366f1','linear-gradient(135deg,#6366f1,#7c3aed)',
  'linear-gradient(135deg,#0f172a 0%,#1e1b4b 60%,#0f172a 100%)',
  'AICPA-accredited CPA firm','2026-08-20',
  $soc2$[
    {"id":"CC6.1","label":"Logical Access Controls","description":"AI-authored changes reviewed only by authorised personnel via role-based access and attestation workflow.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-01","next_test":"2026-08-01","test_frequency":"quarterly","evidence_items":[{"type":"attestation","description":"Signed reviewer attestation records (PGP)","auto":true},{"type":"policy","description":"Access control policy v1.2","auto":false},{"type":"screenshot","description":"GitHub App merge gate configuration","auto":false}],"cross_map":[{"framework":"pcidss","control_id":"6.4.2"},{"framework":"euai","control_id":"Art.14"}]},
    {"id":"CC6.2","label":"Authentication","description":"Reviewer identity verified via GitHub OAuth — no anonymous attestations permitted.","weight":20,"owner":"alice@{{ORG}}.io","last_tested":"2026-04-15","next_test":"2026-07-15","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"OAuth token log per attestation call","auto":true},{"type":"config","description":"GitHub App OAuth scope configuration","auto":false}],"cross_map":[{"framework":"pcidss","control_id":"6.4.2"}]},
    {"id":"CC7.2","label":"System Monitoring","description":"Continuous AI content scanning on every pull request — zero manual triggers required.","weight":20,"owner":"bob@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"Automated scan logs per PR","auto":true},{"type":"report","description":"SOC 2 compliance report PDF","auto":false}],"cross_map":[{"framework":"euai","control_id":"Art.17"},{"framework":"pcidss","control_id":"6.2.4"}]},
    {"id":"CC8.1","label":"Change Management","description":"All changes formally attested before deployment — policy gate enforces this automatically.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-15","next_test":"2026-08-15","test_frequency":"quarterly","evidence_items":[{"type":"attestation","description":"Attestation coverage across audit period","auto":true},{"type":"audit-trail","description":"Tamper-evident change management log","auto":true},{"type":"screenshot","description":"Blocked deploy evidence","auto":false}],"cross_map":[{"framework":"pcidss","control_id":"6.4.2"},{"framework":"euai","control_id":"Art.9"}]},
    {"id":"A1.2","label":"Availability","description":"Audit trail retained and accessible for >= 12 months. All scan and attestation records preserved.","weight":10,"owner":"carol@{{ORG}}.io","last_tested":"2026-05-01","next_test":"2026-11-01","test_frequency":"annually","evidence_items":[{"type":"audit-trail","description":"12-month event record retention","auto":true}],"cross_map":[]}
  ]$soc2$::jsonb,
  1
) ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_frameworks (id,short_name,full_name,standard,color,gradient,header_bg,cert_body,next_audit,controls,sort_order)
VALUES (
  'euai','EU AI Act','EU Artificial Intelligence Act','Regulation (EU) 2024/1689 — Annex I High-Risk',
  '#3b82f6','linear-gradient(135deg,#3b82f6,#0891b2)',
  'linear-gradient(135deg,#0f172a 0%,#0c2340 60%,#0f172a 100%)',
  'EU Notified Body / Self-assessment','2026-07-15',
  $euai$[
    {"id":"Art.9","label":"Risk Management System","description":"Continuous identification, analysis and mitigation of AI system risks — documented and reviewable.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-10","next_test":"2026-08-10","test_frequency":"quarterly","evidence_items":[{"type":"report","description":"Risk register with likelihood × impact scoring","auto":false},{"type":"scan-log","description":"Risk classification per scanned file","auto":true}],"cross_map":[{"framework":"soc2","control_id":"CC8.1"}]},
    {"id":"Art.10","label":"Data Governance","description":"Training data provenance documented per file — AI% and source metadata captured at scan time.","weight":20,"owner":"bob@{{ORG}}.io","last_tested":"2026-05-01","next_test":"2026-08-01","test_frequency":"quarterly","evidence_items":[{"type":"audit-trail","description":"AI provenance records per file","auto":true}],"cross_map":[]},
    {"id":"Art.13","label":"Transparency","description":"AI-generated code percentage disclosed per PR — automatically added to status checks.","weight":20,"owner":"bob@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"AI% disclosure per PR scan result","auto":true}],"cross_map":[]},
    {"id":"Art.14","label":"Human Oversight","description":"Named human reviewer required for CRITICAL AI files — policy gate enforces sign-off before merge.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-15","next_test":"2026-08-15","test_frequency":"quarterly","evidence_items":[{"type":"attestation","description":"Named reviewer sign-offs per CRITICAL file","auto":true},{"type":"policy","description":"Human oversight policy v1.2","auto":false}],"cross_map":[{"framework":"soc2","control_id":"CC6.1"},{"framework":"pcidss","control_id":"6.4.2"}]},
    {"id":"Art.17","label":"Quality Management","description":"Post-deployment monitoring via continuous automated scanning — every PR on every monitored repo.","weight":10,"owner":"carol@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"Automated quality assessments per PR","auto":true}],"cross_map":[{"framework":"soc2","control_id":"CC7.2"}]}
  ]$euai$::jsonb,
  2
) ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_frameworks (id,short_name,full_name,standard,color,gradient,header_bg,cert_body,next_audit,cert_expiry,controls,sort_order)
VALUES (
  'pcidss','PCI-DSS','PCI DSS v4.0','PCI Security Standards Council — Req 6 (Software Security)',
  '#10b981','linear-gradient(135deg,#10b981,#0d9488)',
  'linear-gradient(135deg,#0f172a 0%,#042f2e 60%,#0f172a 100%)',
  'QSA — SecurityMetrics','2026-08-22','2026-08-22',
  $pcidss$[
    {"id":"6.2.4","label":"Prevention of Software Attacks","description":"AI code screened for injection, eval/exec, JWT bypass, and hardcoded credential patterns.","weight":30,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"Vulnerability signal detection log per PR","auto":true},{"type":"report","description":"PCI-DSS compliance report — Req 6.4","auto":false}],"cross_map":[{"framework":"soc2","control_id":"CC7.2"},{"framework":"euai","control_id":"Art.9"}]},
    {"id":"6.3.2","label":"Software Inventory","description":"AI-authored code logged per file and pull request — full AIBOM maintained.","weight":25,"owner":"bob@{{ORG}}.io","last_tested":"2026-05-01","next_test":"2026-08-01","test_frequency":"quarterly","evidence_items":[{"type":"audit-trail","description":"AI Bill of Materials (AIBOM) — all files","auto":true}],"cross_map":[]},
    {"id":"6.4.1","label":"Security Vulnerabilities","description":"CRITICAL-risk AI files blocked automatically from merge — zero manual override.","weight":20,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-15","next_test":"2026-08-15","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"Blocked merge evidence per blocked file","auto":true}],"cross_map":[]},
    {"id":"6.4.2","label":"Change Control Process","description":"Dual-reviewer attestation required for payment-system changes — SOD enforced via policy.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"attestation","description":"Dual reviewer records for payment code","auto":true},{"type":"screenshot","description":"Blocked merge evidence for payment PRs","auto":false}],"cross_map":[{"framework":"soc2","control_id":"CC6.1"},{"framework":"soc2","control_id":"CC8.1"},{"framework":"euai","control_id":"Art.14"}]},
    {"id":"6.4.3","label":"Payment Page Security","description":"AI content in payment paths flagged for mandatory review — high-risk repos monitored continuously.","weight":0,"owner":"carol@{{ORG}}.io","last_tested":"2026-05-10","next_test":"2026-08-10","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"Payment-path AI content monitoring logs","auto":true}],"cross_map":[]}
  ]$pcidss$::jsonb,
  3
) ON CONFLICT (id) DO NOTHING;

INSERT INTO compliance_frameworks (id,short_name,full_name,standard,color,gradient,header_bg,cert_body,next_audit,controls,sort_order)
VALUES (
  'iso27001','ISO 27001','ISO/IEC 27001:2022','ISO/IEC 27001:2022 Annex A — Software Development & AI Security Controls',
  '#0ea5e9','linear-gradient(135deg,#0ea5e9,#0284c7)',
  'linear-gradient(135deg,#0f172a 0%,#082f49 60%,#0f172a 100%)',
  'BSI / TÜV SÜD','2027-01-15',
  $iso27001$[
    {"id":"A.8.25","label":"Secure Development Lifecycle","description":"TrustLedger scans every pull request — continuous security testing embedded in the SDLC, not bolted on after delivery.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"scan-log","description":"Automated security scan per PR (SDLC gate)","auto":true},{"type":"policy","description":"Secure development policy v2.0","auto":false}],"cross_map":[{"framework":"soc2","control_id":"CC7.2"},{"framework":"euai","control_id":"Art.17"},{"framework":"pcidss","control_id":"6.2.4"}]},
    {"id":"A.8.26","label":"Application Security Requirements","description":"Policy gates codify AI content thresholds and attestation mandates — security requirements enforced automatically at merge time.","weight":20,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-15","next_test":"2026-08-15","test_frequency":"quarterly","evidence_items":[{"type":"policy","description":"AI code security requirements policy v1.3","auto":false},{"type":"scan-log","description":"Policy enforcement log per PR","auto":true}],"cross_map":[{"framework":"soc2","control_id":"CC8.1"},{"framework":"euai","control_id":"Art.9"}]},
    {"id":"A.8.28","label":"Secure Coding","description":"Every AI-generated file must be attested by a named reviewer before merge — mandatory secure coding verification for all AI output.","weight":25,"owner":"alice@{{ORG}}.io","last_tested":"2026-05-20","next_test":"2026-08-20","test_frequency":"quarterly","evidence_items":[{"type":"attestation","description":"Named reviewer attestation records per file","auto":true},{"type":"audit-trail","description":"Code review evidence chain (tamper-evident)","auto":true}],"cross_map":[{"framework":"soc2","control_id":"CC6.1"},{"framework":"euai","control_id":"Art.14"},{"framework":"pcidss","control_id":"6.4.2"}]},
    {"id":"A.8.30","label":"Outsourced Development","description":"AI coding tools governed as outsourced development suppliers — AI origin tracked per file via AIBOM with full tool provenance.","weight":20,"owner":"bob@{{ORG}}.io","last_tested":"2026-05-01","next_test":"2026-08-01","test_frequency":"quarterly","evidence_items":[{"type":"audit-trail","description":"AI Bill of Materials — tool origin per file","auto":true},{"type":"policy","description":"Third-party AI tool approval register","auto":false}],"cross_map":[{"framework":"euai","control_id":"Art.10"},{"framework":"pcidss","control_id":"6.3.2"}]},
    {"id":"A.5.33","label":"Protection of Records","description":"Immutable cryptographically-chained audit log satisfies records integrity requirements — tamper detection built in to every event.","weight":10,"owner":"carol@{{ORG}}.io","last_tested":"2026-05-01","next_test":"2026-11-01","test_frequency":"annually","evidence_items":[{"type":"audit-trail","description":"Cryptographic chain — 12-month retention","auto":true}],"cross_map":[{"framework":"soc2","control_id":"A1.2"}]}
  ]$iso27001$::jsonb,
  4
) ON CONFLICT (id) DO NOTHING;

-- ================================================================
-- Seed: cross-framework themes
-- ================================================================

INSERT INTO compliance_cross_themes (theme,description,controls,sort_order) VALUES
  ('Human Oversight',       'Require a named human reviewer before merging AI-generated code',       '{"soc2":"CC6.1","euai":"Art.14","pcidss":"6.4.2","iso27001":"A.8.28"}'::jsonb, 1),
  ('Change Management',     'Track and attest every AI code change before deployment',               '{"soc2":"CC8.1","euai":"Art.9","pcidss":"6.4.2","iso27001":"A.8.26"}'::jsonb, 2),
  ('Continuous Monitoring', 'Run automated scans on every pull request',                            '{"soc2":"CC7.2","euai":"Art.17","pcidss":"6.2.4","iso27001":"A.8.25"}'::jsonb, 3),
  ('AI Transparency',       'Disclose AI content percentage per file and per PR',                   '{"soc2":"CC7.2","euai":"Art.13","pcidss":"6.3.2","iso27001":"A.8.30"}'::jsonb, 4),
  ('Risk Management',       'Identify, score and mitigate AI code risks systematically',             '{"soc2":"CC8.1","euai":"Art.9","pcidss":"6.2.4","iso27001":"A.8.26"}'::jsonb, 5),
  ('Access Control',        'Restrict attestation to authorised named reviewers only',              '{"soc2":"CC6.2","euai":"Art.14","pcidss":"6.4.2","iso27001":"A.8.28"}'::jsonb, 6);

-- ================================================================
-- Seed: audit event config
-- ================================================================

INSERT INTO audit_event_config (event_type,label,icon,bg,text_color,border_color,dot_color,soc2_controls) VALUES
  ('scan_complete',         'Scan',        'scan',   '#eef2ff','#4338ca','#c7d2fe','#6366f1', ARRAY['CC7.2']),
  ('attestation',           'Attestation', 'check',  '#f0fdf4','#15803d','#bbf7d0','#22c55e', ARRAY['CC6.1','CC8.1']),
  ('merge_blocked',         'Blocked',     'block',  '#fff1f2','#be123c','#fecdd3','#ef4444', ARRAY['CC8.1','CC6.1']),
  ('policy_violation',      'Violation',   'warn',   '#fffbeb','#b45309','#fde68a','#f59e0b', ARRAY['CC7.2','CC8.1']),
  ('sla_breach',            'SLA Breach',  'clock',  '#fff1f2','#be123c','#fecdd3','#f97316', ARRAY['CC7.2','A1.2']),
  ('policy_change',         'Policy',      'gear',   '#f8fafc','#475569','#e2e8f0','#94a3b8', ARRAY['CC8.1']),
  ('secret_detected',       'Secret',      'secret', '#ede9fe','#6d28d9','#ddd6fe','#7c3aed', ARRAY['CC7.2','CC6.2']),
  ('integration_connected', 'Integration', 'plug',   '#f0fdf4','#15803d','#bbf7d0','#10b981', ARRAY['CC6.2']),
  ('user_added',            'User',        'user',   '#eff6ff','#1d4ed8','#bfdbfe','#3b82f6', ARRAY['CC6.2'])
ON CONFLICT (event_type) DO NOTHING;
