export type VulnSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type VulnCategory =
  | "injection" | "auth" | "crypto" | "exec"
  | "secrets"   | "supply-chain" | "access-control";

export interface CatalogEntry {
  cve:           string;
  cvss:          number;
  cvss_vector?:  string;
  epss_score?:   number;
  severity:      VulnSeverity;
  category:      VulnCategory;
  cweId:         string;
  cweLabel:      string;
  title:         string;
  description:   string;
  patternDesc:   string;
  remediation:   string;
  references:    string[];
  secureRewrite?: { before: string; after: string; lang: string };
}

export const VULN_CATALOG: Record<string, CatalogEntry> = {
  "sql-injection": {
    cve:"CVE-2023-20052", cvss:9.8, epss_score:95.1, severity:"CRITICAL", category:"injection",
    cweId:"CWE-89", cweLabel:"SQL Injection",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    title:"SQL Injection via AI-generated dynamic query construction",
    description:"AI assistants frequently generate SQL queries using f-string interpolation or string concatenation with user-supplied input, bypassing parameterization entirely. This is one of the most common AI code vulnerabilities.",
    patternDesc:'Pattern: f"SELECT ... WHERE id = {user_input}" or query + user_var',
    remediation:"Replace all dynamic SQL with parameterized queries or ORM methods. Use SQLAlchemy, Prisma, or similar. Never interpolate user input into SQL strings. Add a pre-commit hook that scans for f-strings in SQL context.",
    references:["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-20052","https://owasp.org/www-community/attacks/SQL_Injection","https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    secureRewrite:{
      lang:"python",
      before:"# ❌ AI-generated — vulnerable\nquery = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)",
      after:"# ✅ Secure rewrite — parameterised\ncursor.execute(\n  \"SELECT * FROM users WHERE id = %s\",\n  (user_id,)\n)",
    },
  },
  "jwt-none-alg": {
    cve:"CVE-2022-21449", cvss:9.1, epss_score:91.8, severity:"CRITICAL", category:"auth",
    cweId:"CWE-347", cweLabel:"Improper Verification of Cryptographic Signature",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    title:"JWT 'none' algorithm bypass in AI-generated token verification",
    description:"AI models commonly generate JWT verification code that accepts the 'none' algorithm or disables signature verification, allowing attackers to forge arbitrary tokens and bypass authentication entirely.",
    patternDesc:'Pattern: algorithms=["HS256", "none"] or verify_signature: False',
    remediation:"Explicitly whitelist only the expected algorithm (HS256 or RS256). Never include 'none'. Upgrade to PyJWT >= 2.8.0 or jsonwebtoken >= 9.0.0. Add CI lint rule to ban 'none' in JWT config.",
    references:["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21449","https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/","https://nvd.nist.gov/vuln/detail/CVE-2022-21449"],
    secureRewrite:{
      lang:"python",
      before:"# ❌ AI-generated — accepts 'none' algorithm\npayload = jwt.decode(\n  token, JWT_SECRET,\n  options={\"verify_signature\": False},\n  algorithms=[\"HS256\", \"none\"],\n)",
      after:"# ✅ Secure rewrite — strict algorithm\npayload = jwt.decode(\n  token, JWT_SECRET,\n  algorithms=[\"HS256\"],  # explicit allowlist only\n)",
    },
  },
  "eval-exec": {
    cve:"CVE-2021-44228", cvss:10.0, epss_score:99.7, severity:"CRITICAL", category:"exec",
    cweId:"CWE-95", cweLabel:"Improper Neutralization of Directives in Dynamic Code",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    title:"Arbitrary code execution via AI-generated eval()/exec() usage",
    description:"AI assistants routinely generate code using eval() or exec() on user-controlled input. This enables remote code execution — one of the most severe vulnerability classes, enabling full server compromise.",
    patternDesc:"Pattern: eval(user_input) / exec(formula) / new Function(code)()",
    remediation:"Replace eval/exec with safe alternatives: ast.literal_eval() for Python data, mathjs sandbox for expressions, or explicit parsing. Add bandit/eslint rule to flag eval/exec usage in CI.",
    references:["https://owasp.org/www-community/attacks/Code_Injection","https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html","https://semgrep.dev/r?q=eval"],
    secureRewrite:{
      lang:"python",
      before:"# ❌ AI-generated — arbitrary code execution\ndef calculate(expression: str) -> float:\n    return eval(expression)  # CRITICAL",
      after:"# ✅ Secure rewrite — safe expression parser\nimport ast\ndef calculate(expression: str) -> float:\n    tree = ast.parse(expression, mode=\"eval\")\n    return eval(compile(tree, \"\", \"eval\"),\n               {\"__builtins__\": {}}, {})",
    },
  },
  "hardcoded-secret": {
    cve:"CVE-2021-42013", cvss:9.8, epss_score:88.4, severity:"CRITICAL", category:"secrets",
    cweId:"CWE-798", cweLabel:"Use of Hard-coded Credentials",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    title:"Hardcoded production credentials in AI-generated code",
    description:"AI models frequently embed production API keys, passwords, and tokens directly in source code — often trained on leaked credential patterns from public repositories. Any committed secret must be treated as compromised.",
    patternDesc:'Pattern: API_KEY = "sk_live_..." / DB_PASSWORD = "prod_..." / JWT_SECRET = "..._2024"',
    remediation:"Rotate all exposed credentials immediately. Move secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler). Add gitleaks or trufflehog as a pre-commit hook and in CI.",
    references:["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42013","https://docs.gitguardian.com/secrets-detection","https://trufflesecurity.com/trufflehog"],
  },
  "structural-uniformity": {
    cve:"CVE-2023-45133", cvss:8.1, epss_score:28.3, severity:"HIGH", category:"supply-chain",
    cweId:"CWE-1104", cweLabel:"Use of Unmaintained Third-Party Components",
    cvss_vector:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
    title:"AI structural uniformity indicating copy-paste without security review",
    description:"Code blocks with unusually uniform structure and indentation indicate AI-generated output pasted without human modification. This pattern correlates strongly with missed security reviews and introduced vulnerable patterns.",
    patternDesc:"Pattern: identical block structure, predictable variable names, no human variation signatures",
    remediation:"Each AI-generated block must be individually reviewed by a qualified engineer. Establish a checklist for AI code review: check imports, validate logic, test edge cases, verify no secrets.",
    references:["https://owasp.org/www-project-top-ten/","https://cwe.mitre.org/data/definitions/1104.html"],
  },
  "ai-comment-pattern": {
    cve:"CVE-2023-25136", cvss:7.5, epss_score:42.1, severity:"HIGH", category:"access-control",
    cweId:"CWE-862", cweLabel:"Missing Authorization",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    title:"AI comment pattern indicating low-quality security implementation",
    description:"Over-commented, instructional-style code is a strong AI generation signature. AI models tend to over-explain logic while missing authorization checks, input validation, and error handling that experienced engineers add naturally.",
    patternDesc:"Pattern: excessive inline comments, TODO-style explanations, boilerplate security comments without implementation",
    remediation:"Review all AI-generated code for missing authorization middleware, unchecked return values, and missing input validation. Do not treat AI-generated comments as security evidence.",
    references:["https://owasp.org/www-project-top-ten/","https://cwe.mitre.org/data/definitions/862.html"],
  },
  "comment-density": {
    cve:"CVE-2022-36067", cvss:7.6, epss_score:35.6, severity:"MEDIUM", category:"access-control",
    cweId:"CWE-116", cweLabel:"Improper Encoding or Escaping of Output",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    title:"High comment density — potential XSS via unescaped AI-generated output",
    description:"AI-generated template code with high comment density often renders user data directly into HTML without proper escaping, enabling cross-site scripting attacks.",
    patternDesc:"Pattern: template rendering without explicit escape, innerHTML assignment, unescaped string interpolation",
    remediation:"Use template engines that auto-escape output (Jinja2 with autoescape, React JSX). Never use innerHTML with user data. Implement a Content Security Policy (CSP).",
    references:["https://owasp.org/www-community/attacks/xss/","https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
  },
  "identifier-entropy": {
    cve:"CVE-2023-44487", cvss:6.5, epss_score:22.9, severity:"MEDIUM", category:"crypto",
    cweId:"CWE-327", cweLabel:"Use of Broken Cryptographic Algorithm",
    cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    title:"Low identifier entropy — AI suggests weak crypto or predictable tokens",
    description:"AI models trained on older code frequently suggest MD5 or SHA-1 for security-sensitive operations, and generate predictable token values using low-entropy sources like timestamps.",
    patternDesc:"Pattern: hashlib.md5(), crypto.createHash('sha1'), Math.random() for security tokens",
    remediation:"Use SHA-256 or stronger for general hashing. Use bcrypt/scrypt/Argon2 for passwords. Use crypto.randomBytes() or secrets.token_urlsafe() for tokens. Never use MD5/SHA-1 for security.",
    references:["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html","https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
  },
};
