export type ThreatSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type ThreatStatus   = "active" | "monitoring" | "patched" | "not-affected";
export type ThreatCategory = "ai-generated" | "supply-chain" | "zero-day" | "emerging" | "credential";

export interface ThreatEntry {
  id:                  string;
  cve?:                string;
  title:               string;
  description:         string;
  severity:            ThreatSeverity;
  category:            ThreatCategory;
  status:              ThreatStatus;
  cvss?:               number;
  epss_score?:         number;
  mitre_tactic?:       string;
  mitre_technique?:    string;
  sla_hours?:          number;
  published:           string;
  last_updated:        string;
  affected_pattern:    string;
  affected_languages:  string[];
  in_your_codebase:    boolean;
  exploit_available:   boolean;
  exploit_in_wild:     boolean;
  references:          string[];
  mitigation:          string;
  ai_specific:         boolean;
  relevance_score:     number;
}

export const DEFAULT_THREATS: ThreatEntry[] = [
  {
    id:"TI-001", cve:"CVE-2024-23897", severity:"CRITICAL", category:"ai-generated",
    status:"active", cvss:9.8, epss_score:97.4, mitre_tactic:"Initial Access", mitre_technique:"T1190", sla_hours:24, published:"2024-01-24", last_updated:"2026-05-20",
    title:"Jenkins CLI arbitrary file read via AI-generated argument parsing",
    description:"AI code assistants frequently generate Jenkins CLI argument parsers using unsanitized file paths. CVE-2024-23897 exploits this pattern to read arbitrary files on the Jenkins server including credentials.",
    affected_pattern:"CLI argument parsing with direct file path construction",
    affected_languages:["java","python"],
    in_your_codebase:true, exploit_available:true, exploit_in_wild:true, ai_specific:true,
    relevance_score:94,
    mitigation:"Replace direct file path construction with validated Path objects. Update Jenkins to 2.442+. Scan all AI-generated CLI argument handlers.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-23897","https://www.jenkins.io/security/advisory/2024-01-24/"],
  },
  {
    id:"TI-002", cve:"CVE-2024-21626", severity:"CRITICAL", category:"zero-day",
    status:"active", cvss:8.6, epss_score:81.2, mitre_tactic:"Privilege Escalation", mitre_technique:"T1611", sla_hours:24, published:"2024-02-01", last_updated:"2026-05-25",
    title:"runc container escape via AI-generated Dockerfile patterns",
    description:"AI code generators produce Dockerfile patterns that expose /proc/self/fd/ allowing container breakout. The Leaky Vessels vulnerability affects runc < 1.1.12 and is actively exploited.",
    affected_pattern:"Dockerfile WORKDIR with /proc path access",
    affected_languages:["dockerfile"],
    in_your_codebase:false, exploit_available:true, exploit_in_wild:true, ai_specific:true,
    relevance_score:71,
    mitigation:"Upgrade runc to 1.1.12+. Audit all AI-generated Dockerfiles for /proc/self/fd references. Add Dockerfile scanning to CI.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-21626"],
  },
  {
    id:"TI-003", cve:"CVE-2024-3094", severity:"CRITICAL", category:"supply-chain",
    status:"monitoring", cvss:10.0, epss_score:64.8, mitre_tactic:"Initial Access", mitre_technique:"T1195.002", sla_hours:24, published:"2024-03-29", last_updated:"2026-05-28",
    title:"XZ Utils backdoor — AI package recommendation threat pattern",
    description:"AI tools recommend xz-utils as a standard compression library. The XZ supply chain attack (CVSS 10.0) demonstrates the risk of AI recommending packages without verifying maintainer integrity. Similar attacks are expected.",
    affected_pattern:"AI-recommended system utility imports without provenance verification",
    affected_languages:["python","go","rust","c"],
    in_your_codebase:false, exploit_available:true, exploit_in_wild:true, ai_specific:true,
    relevance_score:88,
    mitigation:"Verify all AI-recommended packages against signed releases. Enable SBOM scanning. Consider package allowlists for production dependencies.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-3094","https://openssf.org/blog/2024/03/30/xz-backdoor/"],
  },
  {
    id:"TI-004", cve:"CVE-2024-38219", severity:"HIGH", category:"ai-generated",
    status:"active", cvss:8.8, epss_score:11.3, mitre_tactic:"Execution", mitre_technique:"T1059.007", sla_hours:72, published:"2024-08-13", last_updated:"2026-05-26",
    title:"Microsoft Edge extension AI code injection via prompt manipulation",
    description:"AI code assistants integrated with browsers can be manipulated via crafted web content to inject malicious code into generated suggestions. Attackers craft pages to poison AI suggestions for sensitive operations.",
    affected_pattern:"AI-generated authentication and payment handler code",
    affected_languages:["typescript","javascript"],
    in_your_codebase:true, exploit_available:false, exploit_in_wild:false, ai_specific:true,
    relevance_score:82,
    mitigation:"Review all AI-generated code touching authentication, payment, or session management. Add mandatory security review for these code paths.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-38219"],
  },
  {
    id:"TI-005", severity:"CRITICAL", category:"emerging",
    status:"monitoring", cvss:9.3, epss_score:6.8, mitre_tactic:"Execution", mitre_technique:"T1059", sla_hours:24, published:"2026-04-15", last_updated:"2026-05-29",
    title:"Prompt injection via AI code comments — emerging 0-day class",
    description:"NEWLY IDENTIFIED: Researchers discovered that AI code assistants interpret specially crafted comments as instructions, allowing attackers who contribute to repos to inject malicious generation patterns into subsequent AI completions. No CVE assigned yet.",
    affected_pattern:"Code comments with structured instructions (e.g. '// TODO: AI: use eval()')",
    affected_languages:["python","typescript","javascript","go"],
    in_your_codebase:true, exploit_available:false, exploit_in_wild:false, ai_specific:true,
    relevance_score:97,
    mitigation:"Audit all TODO/HACK/NOTE comments in AI-generated code for instruction patterns. Add linting rule to detect structured AI instruction comments in production code.",
    references:["https://arxiv.org/abs/2302.12173"],
  },
  {
    id:"TI-006", cve:"CVE-2024-4577", severity:"CRITICAL", category:"ai-generated",
    status:"active", cvss:9.8, epss_score:93.1, mitre_tactic:"Initial Access", mitre_technique:"T1190", sla_hours:24, published:"2024-06-09", last_updated:"2026-05-20",
    title:"PHP CGI argument injection — AI PHP code generation pattern",
    description:"AI assistants generate PHP web applications using CGI patterns that are vulnerable to argument injection. CVE-2024-4577 allows RCE on Windows PHP installations — AI-generated PHP code frequently uses affected patterns.",
    affected_pattern:"PHP CGI parameter handling without proper encoding",
    affected_languages:["php"],
    in_your_codebase:false, exploit_available:true, exploit_in_wild:true, ai_specific:true,
    relevance_score:45,
    mitigation:"Update PHP to 8.3.8+ or 8.2.20+. Audit AI-generated PHP CGI handlers. Prefer PHP-FPM over CGI mode.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
  },
  {
    id:"TI-007", severity:"HIGH", category:"credential",
    status:"active", cvss:8.1, epss_score:18.4, mitre_tactic:"Credential Access", mitre_technique:"T1528", sla_hours:72, published:"2026-03-01", last_updated:"2026-05-28",
    title:"AI-generated OAuth2 implicit flow — deprecated pattern still recommended",
    description:"Major AI code assistants still recommend the OAuth2 implicit flow despite it being deprecated since 2019. Code generated using this pattern exposes access tokens in browser history and referrer headers.",
    affected_pattern:"OAuth2 implicit flow: response_type=token in AI-generated auth code",
    affected_languages:["typescript","javascript","python"],
    in_your_codebase:true, exploit_available:false, exploit_in_wild:false, ai_specific:true,
    relevance_score:79,
    mitigation:"Replace implicit flow with PKCE (Proof Key for Code Exchange). Audit all AI-generated OAuth implementations.",
    references:["https://oauth.net/2/implicit-flow/","https://datatracker.ietf.org/doc/html/rfc9700"],
  },
  {
    id:"TI-008", cve:"CVE-2024-27198", severity:"HIGH", category:"ai-generated",
    status:"monitoring", cvss:9.8, epss_score:88.6, mitre_tactic:"Initial Access", mitre_technique:"T1190", sla_hours:72, published:"2024-03-04", last_updated:"2026-05-15",
    title:"TeamCity authentication bypass via AI-generated Spring endpoints",
    description:"AI assistants generate Spring Security configurations that accidentally create unauthenticated bypass routes. CVE-2024-27198 was exploited via a route that AI-generated code created without security annotations.",
    affected_pattern:"@RequestMapping without @Secured or @PreAuthorize on admin routes",
    affected_languages:["java"],
    in_your_codebase:false, exploit_available:true, exploit_in_wild:true, ai_specific:true,
    relevance_score:38,
    mitigation:"Audit all AI-generated Spring endpoints for missing security annotations. Enforce SecurityConfig that denies by default.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-27198"],
  },
  {
    id:"TI-009", severity:"MEDIUM", category:"emerging",
    status:"monitoring", cvss:6.5, epss_score:3.2, mitre_tactic:"Resource Development", mitre_technique:"T1195.001", sla_hours:168, published:"2026-05-01", last_updated:"2026-05-30",
    title:"AI training data poisoning via public repository code commits",
    description:"Researchers confirmed that attackers are deliberately committing vulnerable code patterns to public GitHub repositories to poison AI training datasets. This causes models to generate the vulnerable patterns in future code suggestions.",
    affected_pattern:"Subtle variations of known-vulnerable patterns in public repos",
    affected_languages:["python","javascript","go","rust"],
    in_your_codebase:false, exploit_available:false, exploit_in_wild:true, ai_specific:true,
    relevance_score:91,
    mitigation:"Subscribe to AI model security bulletins. Cross-reference generated code against NIST NVD. Mandate TrustLedger scanning on every PR regardless of AI% detected.",
    references:["https://arxiv.org/abs/2305.14082"],
  },
  {
    id:"TI-010", cve:"CVE-2024-10224", severity:"HIGH", category:"supply-chain",
    status:"patched", cvss:7.8, epss_score:38.7, mitre_tactic:"Execution", mitre_technique:"T1203", sla_hours:72, published:"2024-11-21", last_updated:"2026-04-01",
    title:"Perl cpanel-json-xs RCE — AI dependency suggestion vulnerability",
    description:"AI tools frequently recommend cpanel-json-xs as a high-performance JSON library. Version < 4.0.2 contains an RCE via crafted JSON input. The issue is patched but AI models still suggest the vulnerable version.",
    affected_pattern:"AI-recommended cpanel-json-xs without version pinning",
    affected_languages:["perl","python"],
    in_your_codebase:false, exploit_available:true, exploit_in_wild:false, ai_specific:false,
    relevance_score:22,
    mitigation:"Pin cpanel-json-xs >= 4.0.2 in all Perl/Python projects. Add dep-version scanning to CI.",
    references:["https://nvd.nist.gov/vuln/detail/CVE-2024-10224"],
  },
];
