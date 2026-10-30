/**
 * Engineering articles. Each describes real engine work, with numbers from the benchmark harness in
 * benchmarks/ (see /benchmarks for the current run) -- including the mistakes we made along the way.
 */
import Link from "next/link";

export interface Post { slug: string; title: string; date: string; summary: string; body: () => React.ReactNode }

const Pre = ({ children }: { children: string }) => <pre><code>{children}</code></pre>;

function CallerProofs() {
  return (
    <>
      <p>Static analysers have two ways to be wrong about a helper function. Treat its parameters as clean and you miss every injection that arrives through it. Treat them as attacker-controlled and you report every concatenation inside it — including the ones that only ever receive constants. The second mistake is the one that makes developers stop reading findings.</p>
      <p>On the NIST Juliet C# suite our SQL-injection rule had a false-positive rate of 48.6%. Almost every false positive had the same shape: a public sink method in one file, called from another file with a hard-coded string.</p>
      <Pre>{`// CWE89_..._51b.cs                                  // CWE89_..._51a.cs
public static void GoodG2BSink(string data, ...)     string data = "foo";
{                                                    CWE89_..._51b.GoodG2BSink(data, req, resp);
    cmd.CommandText = "update users set hitcount=hitcount+1 where name='" + data + "'";
}`}</Pre>
      <h2>Asking the callers</h2>
      <p>Our engines already run a <em>proof pass</em>: every method is walked with its parameters tainted, and a sink whose argument stays clean even then is proven safe, which also withdraws the line-level pattern match on that line. The weakness was the first assumption. A public method&apos;s parameters were always assumed tainted, because any caller anywhere could reach it.</p>
      <p>But in a pull-request scan we can see the callers. So the batch now computes, for every <code>Type.Method</code> other files call, what each call site passes — under the same pessimistic proof assumptions — and iterates that to a fixed point so a constant passed through a relay helper stays a constant. A method called from other files is then seeded from those masks instead of from &quot;anything&quot;. It still starts fully tainted when it looks like an entry point: an attributed action, a controller, hub or page class, an event handler, or a method nothing in the batch calls.</p>
      <h2>The bug the mutation test caught</h2>
      <p>The first version cut the false-positive rate to 14% — and quietly dropped detection from 100% to 97.3%. Every lost case was Juliet flow variant 67, where the tainted value travels inside an object:</p>
      <Pre>{`Container dataContainer = new Container();
dataContainer.containerOne = data;      // tainted
Helper_67b.BadSink(dataContainer, ...); // the call site's mask for dataContainer was empty`}</Pre>
      <p>The engine does not follow a field write into the object&apos;s own mask, so the call site looked clean and a vulnerable sink was &quot;proven&quot; safe. That is the worst failure a proof can have. The fix is conservative: an object variable its method writes into — a field, an indexer, an <code>Add</code>-style call — counts as carrying anything. Detection went back to 100%, and the false-positive rate settled at 27.3%: a smaller improvement than the broken version, and a real one.</p>
      <p>Closing the last surviving mutants found a second, older bug: for a named argument such as <code>Find(conn: x, data: y)</code> the engine evaluated the argument&apos;s <em>name</em> instead of its value, and cross-file facts matched arguments by position. Both are fixed, with tests.</p>
      <h2>What is left</h2>
      <p>The remaining C# false positives are mostly flow variant 61, where the constant comes back as the <em>return value</em> of a method in another file. Following return values across files in the proof pass is next. The current numbers are on the <Link href="/benchmarks">benchmark report</Link>.</p>
    </>
  );
}

function LabelsDisagree() {
  return (
    <>
      <p>Public benchmarks are the best tool we have for measuring a scanner honestly, and we publish our results on them. But a benchmark is a set of labels someone wrote, and some labels describe the benchmark&apos;s intent rather than the behaviour of the real library. Chasing those labels makes a scanner score better and work worse. Here are three places where we deliberately score lower than we could.</p>
      <h2>XXE in Nokogiri</h2>
      <p>One Ruby corpus marks <code>Nokogiri::XML(input)</code> as vulnerable to XML external entities and <code>Nokogiri::XML(input) {"{ |c| c.nonet.noent }"}</code> as safe. In the real library it is the other way round. The default parse does not substitute external entities; <code>noent</code> is the option that <em>turns substitution on</em>. Flagging the default and trusting <code>noent</code> would teach every Ruby team the wrong lesson, so our Ruby XXE score stays at 0 on that corpus.</p>
      <h2>CSRF without a cookie</h2>
      <p>A PHP corpus labels any state-changing handler without a CSRF token as vulnerable — including API handlers that read a bearer token or take no credentials at all. Cross-site request forgery needs a credential the browser attaches by itself: a session cookie. We report CSRF only when a handler relies on the session or a cookie and has no token, nonce, Origin/Referer check or SameSite cookie. On DVWA that catches the real CSRF page and leaves its three defended versions alone. On the corpus it scores 4%.</p>
      <h2>rand() as attacker input</h2>
      <p>The Juliet C/C++ suite uses <code>rand()</code> as one of its sources of &quot;untrusted&quot; sizes. Treating a PRNG as attacker input would flag every <code>malloc(rand() % n)</code> in games and simulations. We don&apos;t, so those cases count as misses in our uncontrolled-allocation results.</p>
      <h2>How we decide</h2>
      <p>We take the corpus label at face value unless we can point to the library&apos;s documented behaviour, or to a real application where following the label would produce a false positive or a false negative. When we diverge, the <Link href="/benchmarks#failures">benchmark report</Link> lists the case and the reason, so you can disagree with us.</p>
    </>
  );
}

function SinkClasses() {
  return (
    <>
      <p>Most taint analysers carry one bit per value: tainted or clean. A sanitizer flips it to clean. That model has a blind spot that shows up constantly in real code:</p>
      <Pre>{`$name = htmlspecialchars($_GET['name']);
$db->query("SELECT * FROM users WHERE name = '$name'");`}</Pre>
      <p>HTML escaping makes the value safe to print in a page. It was not designed for SQL: depending on its flags it may leave single quotes alone, it never handles backslashes, and in a numeric context no quote is needed at all. A one-bit model calls this clean.</p>
      <h2>A set of classes per value</h2>
      <p>Our engines track a bitmask of vulnerability classes per value: SQL, command, path, XSS, SSRF, redirect, LDAP, XPath, header, template, deserialization and more. A source sets all of them. Each sanitizer clears only the classes it actually neutralises: <code>htmlspecialchars</code> clears XSS, a parameterised query clears SQL, <code>basename</code> clears path traversal. A sink fires when the value still carries <em>its</em> class, so the example above is still reported as SQL injection.</p>
      <h2>Converting to a number</h2>
      <p>A value parsed as an integer cannot inject anything, so numeric conversion clears every injection class. But it keeps one bit: the attacker still chose the number. That bit is what an unbounded allocation (<code>new char[n]</code>, <code>Vec::with_capacity(n)</code>), an out-of-range index, or an integer overflow (<code>a * b</code> on two request values) needs. A bound check against a constant or a length clears it, as does clamping (Rust&apos;s <code>.min(4096)</code>); a sanitizer for some other class does not.</p>
      <h2>Proofs, not just findings</h2>
      <p>The same masks let an engine prove something stronger than &quot;no finding&quot;: that a sink is safe even when every parameter, field and unknown call is assumed hostile. When that proof holds, the matching line-level pattern finding is withdrawn — which is how a concatenated SQL string built only from constants stops being reported. You can watch the masks at work in the <Link href="/demo">live demo</Link>: the Python sample&apos;s fix escapes the value for HTML, and the XSS finding disappears.</p>
    </>
  );
}

export const POSTS: Post[] = [
  { slug: "proving-sinks-safe-from-their-callers", title: "Proving a sink safe from its callers — and the bug a mutation test caught", date: "2026-10-30", summary: "How cross-file call-site analysis cut C# SQL false positives on Juliet from 48.6% to 27.3%, after a first version that was faster to improve and wrong.", body: CallerProofs },
  { slug: "when-the-benchmark-label-is-wrong", title: "When the benchmark label is wrong", date: "2026-10-30", summary: "XXE in Nokogiri, CSRF without a cookie, and rand() as attacker input: three cases where we score lower on purpose, and how we decide.", body: LabelsDisagree },
  { slug: "taint-is-not-a-boolean", title: "Taint is not a boolean", date: "2026-10-30", summary: "Why our engines track a set of vulnerability classes per value, how sanitizers clear only what they neutralise, and what a numeric conversion keeps.", body: SinkClasses },
];
