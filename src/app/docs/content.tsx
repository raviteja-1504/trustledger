/**
 * The documentation pages. Coverage and language support are generated from the engines' registries
 * (lib/publicCoverage.ts), so they cannot drift from what the scanner actually reports.
 */
import Link from "next/link";
import { dataFlowRules, COVERAGE_LANGUAGES, LANGUAGE_ENGINES, rulesByLanguage } from "@/lib/publicCoverage";
import { BENCHMARK_REPORT } from "@/lib/benchmarkReport";
import { FINDING_CATALOG } from "@/lib/findingCatalog";
import { SCANNER_FEATURES, PIPELINE_STAGES, AI_FACTS, ENGINE_FACTS, IAC_FORMATS, CLOUD_API_GROUPS } from "@/lib/siteContent";
import type { DocsSlug } from "./docsNav";
import { planLimits } from "@/lib/limits";
import { contactEmail } from "@/lib/contacts";

const Code = ({ children }: { children: string }) => <pre><code>{children}</code></pre>;

function GettingStarted() {
  const free = planLimits("free");
  const email = contactEmail("sales");
  return (
    <>
      <p>Five steps take you from nothing to a scanned pull request. It takes about five minutes. Nothing is added to your CI pipeline and no configuration file is needed.</p>

      <h2>1. Create your account</h2>
      <p>Go to <Link href="/login?mode=signup">Sign up</Link>. Use an email and password (confirm the email we send), or choose <em>Continue with GitHub</em>.</p>
      <ul>
        <li><strong className="text-white">GitHub sign-in uses the GitHub account your browser is signed in to.</strong> It does not ask which one. If you have several GitHub accounts, check the avatar at the top right of github.com first, or use a separate browser profile for each account.</li>
        <li>The setup screens show <em>Signed in as</em> at the top: your name, how you signed in and your TrustLedger organisation. Check it reads what you expect before you continue.</li>
        <li>You can be signed in on one device at a time: signing in on a second device signs the first one out.</li>
      </ul>

      <h2>2. Connect GitHub</h2>
      <p>On the <em>Connect GitHub</em> setup step, click <em>Install on GitHub</em> and install the TrustLedger GitHub App.</p>
      <ul>
        <li>Choose the account that owns your repositories: your company, or your own account if the repositories are yours. GitHub installs on the account you are signed in to in this browser.</li>
        <li>Select the repositories you want scanned. One is enough to start. The app asks for read access to pull requests and code, and write access to checks (see the <Link href="/trust#permissions">Trust Center</Link>).</li>
        <li>GitHub sends you back to TrustLedger, which shows <em>GitHub App installed on &lt;name&gt;</em> and fills in your GitHub name.</li>
        <li>If you install on a company account you do not own, GitHub asks an owner to approve it first. Nothing is scanned until they do.</li>
      </ul>
      <h3>Your GitHub name</h3>
      <p>This is the one field people get wrong. It is the name that comes right after <code>github.com/</code> in your repository addresses: in <code>github.com/acme-corp/payments-api</code> it is <code>acme-corp</code>.</p>
      <ul>
        <li>TrustLedger matches every pull request to your organisation by this name. <strong className="text-white">If it does not match, the pull request is not scanned</strong> and no check appears.</li>
        <li>It is not your email address, your TrustLedger organisation&apos;s name or a full repository link. Capital letters do not matter.</li>
        <li>One GitHub name can be linked to one TrustLedger organisation.</li>
      </ul>

      <h2>3. Select your repository</h2>
      <p>The free early-access plan covers {free.repos} {free.repos === 1 ? "repository" : "repositories"}. The first repository that receives a scan is connected automatically, so you pick it by opening a pull request in it. You can see and manage connected repositories in the dashboard under <em>Repositories</em>. A second repository is not scanned on the free plan: the check on its pull request says so, and you can ask us for more at <a href={`mailto:${email}`}>{email}</a>.</p>

      <h2>4. Run your first scan</h2>
      <p>Open a pull request, or push a commit to an existing one, in the connected repository. Within a minute or two a check named <em>TrustLedger AI Governance</em> appears on the pull request, first as in progress and then with a result. Large pull requests take longer because scans run from a queue.</p>
      <p>No pull request handy? Try the <Link href="/demo">live demo</Link> first: it scans a sample in your browser.</p>

      <h2>5. Review the findings</h2>
      <p>Open the scan from the check&apos;s <em>Details</em> link or from the dashboard.</p>
      <ul>
        <li>The <em>Security findings</em> card counts vulnerabilities by severity. In the file list, the <em>Findings</em> column shows each file&apos;s share of that count; AI-provenance and code-hygiene hints are shown apart as <em>signals</em> and are not vulnerabilities.</li>
        <li>Open a finding to see its <em>Data flow</em>: where untrusted input enters, each step it passes through (including other files) and the dangerous call it reaches, with a suggested fix.</li>
        <li>Fix the code, or attest the file: a named reviewer signs it off. With the default policy, files at CRITICAL or HIGH risk block the merge until they are fixed or attested. A finding that is not real can be marked a false positive, or accepted as a risk with a reason and an optional expiry.</li>
      </ul>

      <h2>What the free early-access plan includes</h2>
      <p>The whole product, with an allowance of {free.scans} pull-request scans a month, {free.repos} {free.repos === 1 ? "repository" : "repositories"} and {free.members} team members. Reviewer sign-offs are {free.attestations < 0 ? "unlimited" : `limited to ${free.attestations}`}. The scan count restarts on the first day of each month (UTC). Need more while you evaluate? Write to <a href={`mailto:${email}`}>{email}</a>.</p>

      <h2>Scanning outside a pull request</h2>
      <p>To scan code from a CI job or a monorepo export, an administrator creates an API key under <em>Settings → API Access</em>, and the job sends the files to <code>POST /api/scans</code>. A key can submit scans and read their results; it can never attest a file. Scans sent this way count against your plan's limits, like any other scan:</p>
      <Code>{`curl -X POST https://<your-deployment>/api/scans \\
  -H "X-TrustLedger-Key: tl_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{"repo":"acme/api","pr_number":482,"commit_sha":"<sha>","files":[{"path":"src/db/users.ts","content":"..."}]}'`}</Code>
      <p>See the <Link href="/docs/api">API reference</Link> for every field. GitLab and Bitbucket are also supported.</p>

      <h2>Stuck?</h2>
      <p>Start with <Link href="/docs/troubleshooting">Troubleshooting</Link>. Anything else, or a false positive or missed vulnerability to report, goes through <Link href="/contact">Contact and feedback</Link>.</p>
    </>
  );
}

function Architecture() {
  return (
    <>
      <p>A scan takes the files a pull request changes, runs every applicable analysis on them together, and merges the results into one report per file. The same code path serves pull requests, API submissions and the live demo.</p>
      <h2>Parsing</h2>
      <p>Each language has a real parser: the TypeScript compiler for JavaScript/TypeScript, <code>java-parser</code> for Java, and tree-sitter grammars (compiled to WebAssembly) for Python, Go, C#, PHP, Ruby, Kotlin, Rust and C/C++. Files longer than 5,000 lines, and syntax trees nested more than 1,000 levels deep, skip the data-flow engines and are covered by the line-level detectors only.</p>
      <h2>Data-flow engines</h2>
      <p>One engine per language walks the syntax tree and tracks which values come from untrusted input and which dangerous calls (sinks) they reach. Engines summarise functions — which parameters reach a sink, which reach the return value — and iterate those summaries to a fixed point, within a file and then across the files of the batch. See <Link href="/docs/taint-analysis">Taint analysis</Link>.</p>
      <h2>Line-level detectors</h2>
      <p>Pattern-based detectors cover what is not a data flow: hardcoded secrets, weak cryptography, insecure configuration, infrastructure-as-code misconfigurations, and language-specific hardening rules (for example a rate limiter keyed on a spoofable header). Where a data-flow engine positively proves a sink safe, the matching line-level finding is withdrawn.</p>
      <h2>The scan, step by step</h2>
      <ol>{PIPELINE_STAGES.map(st => <li key={st.label}><strong className="text-white">{st.label}</strong> — {st.detail}</li>)}</ol>
      <h2>How the data-flow engines decide</h2>
      <ul>{ENGINE_FACTS.map(f => <li key={f.label}><strong className="text-white">{f.label}.</strong> {f.desc}</li>)}</ul>
      <h2>How the AI estimate is built</h2>
      <ul>{AI_FACTS.map(f => <li key={f.label}><strong className="text-white">{f.label}.</strong> {f.desc}</li>)}</ul>
      <p>The <Link href="/docs/ai-attribution">AI attribution</Link> page covers validation and limits.</p>
      <h2>Results</h2>
      <p>Findings from all layers are de-duplicated, mapped to CWE, scored for severity and confidence, and rolled up into a per-file risk level (CRITICAL, HIGH, MEDIUM, LOW). The pull request&apos;s merge decision is made from those risk levels by the merge gate (see <Link href="/docs/pr-integration">Pull-request integration</Link>). The AI-generated estimate is computed alongside, from separate signals (see <Link href="/docs/ai-attribution">AI attribution</Link>).</p>
    </>
  );
}

function Languages() {
  const counts = new Map(rulesByLanguage().map(r => [r.language, r.ruleCount]));
  return (
    <>
      <p>Ten languages have their own parser and data-flow engine. The number of rules each reports comes straight from the engine registry; the <Link href="/docs/coverage">coverage matrix</Link> lists them.</p>
      <table>
        <thead><tr><th>Language</th><th>Files</th><th>Data-flow rules</th><th>Frameworks modelled</th></tr></thead>
        <tbody>{LANGUAGE_ENGINES.map(l => <tr key={l.engine}><td><strong className="text-white">{l.lang}</strong><br /><span className="text-white/50 text-[12px]">{l.note}</span></td><td><code>{l.ext}</code></td><td>{counts.get(l.engine) ?? 0}</td><td>{l.frameworks.join(", ")}</td></tr>)}</tbody>
      </table>
      <h2>Status definitions</h2>
      <ul>
        <li><strong>Implemented</strong> — the language engine reports the rule (it is in the engine&apos;s registry, which is checked at compile time).</li>
        <li><strong>Measured</strong> — the language also has a public labelled corpus in the <Link href="/benchmarks">benchmark report</Link>, with per-category results.</li>
        <li><strong>Not covered</strong> — the engine does not report the rule; line-level detectors may still flag simple cases.</li>
      </ul>
      <p>Measured languages: {[...new Set(BENCHMARK_REPORT.corpora.flatMap(c => c.languages))].join(", ")}. Kotlin has no public labelled corpus and is tested with unit tests and deliberately vulnerable apps.</p>
      <h2>Known limitations</h2>
      <ul>{LANGUAGE_ENGINES.flatMap(l => l.limitations.map(x => <li key={x}><strong className="text-white">{l.short}:</strong> {x}</li>))}</ul>
    </>
  );
}

function Coverage() {
  const rules = dataFlowRules();
  return (
    <>
      <p>{rules.length} rules are reported by at least one data-flow engine. Each cell shows whether that language&apos;s engine reports the rule. Generated from the engine registry on every build.</p>
      <div className="overflow-x-auto">
        <table>
          <thead><tr><th>Rule</th><th>CWE</th>{COVERAGE_LANGUAGES.map(l => <th key={l} className="whitespace-nowrap">{l}</th>)}</tr></thead>
          <tbody>{rules.map(r => (
            <tr key={r.id}>
              <td><strong className="text-white">{r.title}</strong><br /><code>{r.id}</code></td>
              <td className="whitespace-nowrap">{r.cwe ?? "—"}</td>
              {COVERAGE_LANGUAGES.map(l => <td key={l} aria-label={r.languages.includes(l) ? "implemented" : "not covered"} style={{ color: r.languages.includes(l) ? "#34d399" : "rgba(255,255,255,0.2)" }}>{r.languages.includes(l) ? "●" : "·"}</td>)}
            </tr>
          ))}</tbody>
        </table>
      </div>
      <p>Line-level detectors add hardcoded secrets, weak cryptography, cookie flags, debug and diagnostics exposure, infrastructure-as-code and container checks, and hardening rules; they are pattern-based and are not listed in this matrix.</p>
      <h2>Infrastructure, container and API checks</h2>
      <p>Read from the same pull request as the code, with no cloud credentials. Formats: {IAC_FORMATS.join(", ")}, and OpenAPI / Swagger.</p>
      {CLOUD_API_GROUPS.map(g => {
        const titles = Array.from(new Set(Object.entries(FINDING_CATALOG).filter(([id]) => g.match(id)).map(([, e]) => e.title)));
        return (
          <div key={g.name}>
            <h3>{g.name} ({titles.length} checks)</h3>
            <p>{g.blurb}</p>
            <p className="text-white/70 text-[13px]">{titles.join(" · ")}</p>
          </div>
        );
      })}
    </>
  );
}

function Taint() {
  return (
    <>
      <h2>Sources</h2>
      <p>A source is where untrusted data enters: request parameters, headers, cookies and bodies in each framework; command-line arguments, environment variables, stdin and sockets in C/C++; Android intent extras and deep-link URIs; values returned by helper methods (in the same file or, for Java, in another file of the scan) that themselves return request data.</p>
      <h2>Sinks</h2>
      <p>A sink is a call where attacker-controlled data causes harm: SQL execution, shell commands, file paths, outbound URLs, HTML output, deserializers, template compilers, LDAP and XPath queries, raw memory operations and so on. Each sink is matched on the specific argument that matters — the SQL text, not the bound parameters; the program name and a shell <code>-c</code> string, not other arguments.</p>
      <h2>Sink classes and sanitizers</h2>
      <p>A tracked value carries a set of vulnerability classes rather than a single &quot;tainted&quot; flag. A sanitizer clears only the classes it actually neutralises: HTML escaping clears XSS but not SQL injection, so an HTML-escaped value reaching a SQL query is still reported, and the trace says so. Converting to a number clears the injection classes but keeps the fact that an attacker chose the value — which is what matters for an unbounded allocation or an out-of-range index.</p>
      <h2>Guards</h2>
      <p>Only unambiguous checks clear a value: membership in a literal allow-list, a fully anchored character-class pattern, equality with a literal, a bound check against a constant or a length, a resolved path checked against its base directory. A loose regular-expression match is deliberately not trusted.</p>
      <h2>Paths and functions</h2>
      <p>Branches are analysed separately and merged (a value sanitised on one branch and raw on the other stays reported). Function summaries record which parameters reach a sink or the return value, and are iterated to a fixed point so long helper chains resolve.</p>
      <h2>Across files</h2>
      <p>Imports, injected services, packages and includes are followed in all ten languages. A flow that crosses files is reported once, at the caller, with every file on its path in the trace. For C#, a public helper that other files only ever call with constants is proven safe from those call sites.</p>
      <h2>Reading a trace</h2>
      <p>Each step has a kind — <code>source</code>, <code>assignment</code>, <code>call</code>, <code>sanitizer</code>, <code>cross-file</code>, <code>parameter</code>, <code>sink</code> — a file and line, a short label and the code snippet. The <Link href="/demo">live demo</Link> shows real traces.</p>
      <h2>What sets the engines apart</h2>
      <ul>{SCANNER_FEATURES.map(f => <li key={f.title}><strong className="text-white">{f.title}.</strong> {f.desc}</li>)}</ul>
    </>
  );
}

function AiAttribution() {
  const a = BENCHMARK_REPORT.aiAttribution;
  return (
    <>
      <p>For every scanned file TrustLedger estimates how much of it is AI-generated, and which assistant most likely produced it. It is an estimate, and it is presented as one.</p>
      <h2>Signals</h2>
      <p>47 signals feed the estimate, combined with a noisy-OR ensemble and calibrated with a sigmoid. They fall into three groups:</p>
      <ul>
        <li><strong>Code structure</strong> — patterns in the syntax tree that correlate with model output (uniform naming, characteristic comment and docstring shapes, missing edge-case handling, boilerplate density).</li>
        <li><strong>Repository provenance</strong> — assistant configuration and markers in the repository (<code>.cursor/</code>, <code>.claude/</code>, Copilot instructions, Windsurf config, inline marker comments) used to attribute a tool.</li>
        <li><strong>Behaviour</strong> — a contributor&apos;s change compared with their own baseline, so a sudden shift is visible even when the absolute score is moderate.</li>
      </ul>
      <h2>Validation</h2>
      <p>The estimate is checked against a labelled corpus kept in the repository: {a.samples} TypeScript/JavaScript files. At a threshold of {a.threshold}: precision {(a.precision * 100).toFixed(0)}%, recall {(a.recall * 100).toFixed(0)}%, accuracy {(a.accuracy * 100).toFixed(0)}%, ROC-AUC {a.rocAuc.toFixed(2)}; tool attribution is correct on {(a.toolAccuracy * 100).toFixed(0)}% of {a.toolSamples} labelled samples. This is a small regression check, not a statistically strong evaluation.</p>
      <h2>Limitations</h2>
      <ul>
        <li>The estimate is probabilistic. It is not proof that a person or a tool wrote any line, and it should not be used to judge individuals.</li>
        <li>Human code written in a model-like style scores high; model output edited heavily by a person scores low.</li>
        <li>Tool attribution depends on markers and configuration the repository contains; without them the tool is reported as unknown.</li>
        <li>Validation covers TypeScript/JavaScript only; other languages use the same signals without a labelled check.</li>
      </ul>
      <p>Policies can flag files above an AI-percentage threshold for review; by default that does not block a merge on its own.</p>
    </>
  );
}

function PrIntegration() {
  return (
    <>
      <h2>Check run and annotations</h2>
      <p>On GitHub, each scan posts a check run named <code>TrustLedger AI Governance</code> to the pull request; on GitLab and Bitbucket the result is posted as a commit or build status. Findings of medium severity and above are attached as annotations on the flagged lines in the &quot;Files changed&quot; view — up to 50 per check run, most important first; the full trace and the &quot;why this was flagged&quot; checklist are in the check run&apos;s raw output.</p>
      <h2>Merge gate</h2>
      <p>The merge gate decides which unattested files block the merge. Organisations choose in Settings whether CRITICAL files, HIGH files, or both block; by default both do. It fails closed: if the setting cannot be read, files block. Files that do not block still need review — their findings stay open, they just do not hold the merge. To enforce it, make the check a required status check in your branch protection rules.</p>
      <h2>Clearing a block</h2>
      <ul>
        <li><strong>Fix the code</strong> — the next push is rescanned; a fixed file no longer blocks.</li>
        <li><strong>Attest the file</strong> — a named reviewer signs off on the file as it is (see <Link href="/docs/attestation">Attestation</Link>); the check run is re-synchronised.</li>
        <li><strong>Triage the finding</strong> — a security reviewer or admin marks it a false positive or accepts its risk, with a reason and optionally an expiry. The decision follows the finding&apos;s stable fingerprint across pushes and pull requests, takes effect on the next scan, and is written to the audit log.</li>
      </ul>
      <h2>Policies</h2>
      <p>Two presets exist. <em>Standard</em> blocks CRITICAL and HIGH files until one attestation each and flags files over 65% AI-generated for review. <em>Strict</em> also blocks MEDIUM files, requires two attestations for CRITICAL files and a designated reviewer, and flags files over 50%.</p>
    </>
  );
}

function Attestation() {
  return (
    <>
      <p>An attestation is a reviewer&apos;s recorded decision that a flagged file is acceptable to merge as it is.</p>
      <h2>What is recorded</h2>
      <ul>
        <li>The reviewer&apos;s identity (a named account, not a shared token), the time, and the file and scan it applies to.</li>
        <li>A payload hash over the scan, file, reviewer and timestamp.</li>
        <li>The file&apos;s risk context at the moment of review.</li>
        <li>An entry in the organisation&apos;s hash-chained audit log.</li>
      </ul>
      <h2>What it covers</h2>
      <p>An attestation is bound to the file&apos;s <strong>content hash</strong>. A later scan of byte-identical content — a new push that did not touch the file, or the same file in another pull request of the repository — inherits the attestation. If the file changes, the hash changes and the old attestation does not cover it: the file must be attested again. Attestations cannot be edited or deleted.</p>
      <h2>Verifying records</h2>
      <p>Trust Records and audit-log exports are signed with Ed25519. The public key is at <a href="/.well-known/trustledger-export-signing-key">/.well-known/trustledger-export-signing-key</a>; the signed content is the canonical JSON of the document&apos;s <code>record</code> (keys sorted at every level, no whitespace). <code>scripts/verify-trust-record.mjs</code> in the repository verifies a document offline, without trusting TrustLedger. The audit log&apos;s hash chain can be verified from the Audit page.</p>
    </>
  );
}

function Troubleshooting() {
  const free = planLimits("free");
  const email = contactEmail("sales");
  return (
    <>
      <h2>A pull request was not scanned</h2>
      <p>Work down this list; the first two cause most cases.</p>
      <ul>
        <li><strong className="text-white">Your GitHub name does not match.</strong> TrustLedger matches pull requests to your organisation by the GitHub name saved in setup: the part after <code>github.com/</code> in the repository address. If it is missing, misspelt (for example <code>acme</code> instead of <code>acme-corp</code>) or belongs to another TrustLedger organisation, the pull request is ignored and no check appears. Open <code>/onboarding</code>, go to <em>Connect GitHub</em> and correct it. Capital letters do not matter.</li>
        <li><strong className="text-white">The app is not installed on that repository.</strong> In GitHub, open the installation settings for the TrustLedger app and check the repository is selected, and that it is installed on the account that owns the repository.</li>
        <li>Check webhook deliveries in the GitHub App settings: a 401 means the webhook secret does not match, so the signature check rejected it.</li>
        <li>Scans run from a queue, so a result can take a little while on a large pull request. Pushing a new commit queues a fresh scan.</li>
      </ul>

      <h2>The check says &ldquo;Plan limit reached&rdquo;</h2>
      <p>The free early-access plan includes {free.scans} pull-request scans a month and {free.repos} {free.repos === 1 ? "repository" : "repositories"}. When either is used up, TrustLedger does not scan the pull request and says so on the check instead of failing silently. Existing scans can still be viewed and attested. The scan count restarts on the first day of the month (UTC). Need more now? Write to <a href={`mailto:${email}`}>{email}</a>.</p>

      <h2>Setup shows the wrong account or organisation</h2>
      <ul>
        <li>Check <em>Signed in as</em> at the top of the setup screens. GitHub sign-in uses whichever GitHub account the browser is signed in to, so a different GitHub login in the same browser signs you in as someone else. Use <em>Not you? Sign out</em>, sign out of github.com, and sign in again, or use a separate browser profile for each account.</li>
        <li>The GitHub name can belong to only one TrustLedger organisation. &ldquo;Already linked to another TrustLedger organisation&rdquo; means a different one holds it: sign in as the account that created that organisation, or contact us.</li>
      </ul>

      <h2>I was signed out on one device after signing in on another</h2>
      <p>One session is active per person at a time. Signing in on a second device ends the first. This protects the account; sign in again where you want to work.</p>

      <h2>The numbers on the pull request page do not match</h2>
      <p>The <em>Security findings</em> card and the <em>Findings</em> column count the same thing: vulnerabilities. <em>Signals</em> are AI-provenance and code-hygiene hints and are never added into the finding counts. A file&apos;s risk rating comes from its worst finding, so a CRITICAL file can also hold lower-severity findings.</p>

      <h2>No check run on the pull request</h2>
      <p>On GitHub the app needs <em>Checks: write</em>. If permissions were changed after installation, accept the updated permissions in the installation settings. GitLab and Bitbucket report a commit status instead of a check run.</p>

      <h2>Known limitations</h2>
      <ul>
        <li><strong className="text-white">Detection is not equal in every language.</strong> The <Link href="/benchmarks">benchmark report</Link> shows recall and false-positive rate per corpus and language. Read the row for your language, not only the headline.</li>
        <li>Generated, minified and vendored files are skipped or treated as third-party code.</li>
        <li>Files over 5,000 lines, or with syntax nested over 1,000 levels deep, are covered by line-level detectors only.</li>
        <li>Flows through code outside the files in the pull request, and through frameworks or libraries the engines do not model, can be missed. See each language&apos;s <Link href="/docs/languages">known limitations</Link>.</li>
        <li>TrustLedger is not yet SOC 2 or ISO 27001 certified and has not had an independent penetration test. The <Link href="/trust">Trust Center</Link> says exactly what is and is not in place.</li>
      </ul>

      <h2>A finding looks wrong, or a vulnerability was not reported</h2>
      <p>Read the finding&apos;s data flow: every data-flow finding shows how the value got from the source to the sink. If a step is wrong (for example a validation the engine did not recognise), mark the finding a false positive with a reason. Check the <Link href="/docs/coverage">coverage matrix</Link> for the rule and language before reporting a miss. Then tell us through <Link href="/contact">Contact and feedback</Link>: false positives and missed vulnerabilities are the most useful feedback we get.</p>

      <h2>A file was not analysed by its language engine</h2>
      <p>See the known limitations above: generated, minified, vendored and very large files get line-level detectors only.</p>
    </>
  );
}

export const DOCS_CONTENT: Record<Exclude<DocsSlug, "api">, () => React.ReactNode> = {
  "getting-started": GettingStarted,
  architecture: Architecture,
  languages: Languages,
  coverage: Coverage,
  "taint-analysis": Taint,
  "ai-attribution": AiAttribution,
  "pr-integration": PrIntegration,
  attestation: Attestation,
  troubleshooting: Troubleshooting,
};
