/**
 * @jest-environment node
 *
 * Kotlin on Android (found scanning AndroGoat): what the user types into an EditText, what another app puts in an
 * Intent, and a deep link's query are input; SQLiteDatabase.rawQuery/execSQL, WebView.loadUrl/loadData and
 * Runtime.exec are where they do harm.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";

beforeAll(async () => { await warmKotlinTaintEngine(); }, 120000);

const activity = (body: string, fields = "") =>
  `package app\n\nclass DemoActivity : AppCompatActivity() {\n${fields}\n    override fun onCreate(savedInstanceState: Bundle?) {\n        super.onCreate(savedInstanceState)\n${body}\n    }\n}\n`;
const flow = (code: string, id: string) =>
  analyzeFile("app/src/main/java/app/DemoActivity.kt", code).indicators.some(i => i.id === id && /real data-flow|WebView/.test(i.detail ?? ""));

describe("sources", () => {
  it("an EditText's text (findViewById<EditText> or a declared EditText) is input; a TextView's is not", () => {
    expect(flow(activity(`        val ip = findViewById<EditText>(R.id.ip)\n        val p = Runtime.getRuntime().exec("ping " + ip.text.toString())`), "command-injection")).toBe(true);
    expect(flow(activity(`        val ip: EditText = findViewById(R.id.ip)\n        val p = Runtime.getRuntime().exec("ping " + ip.text.toString())`), "command-injection")).toBe(true);
    expect(flow(activity(`        val label = findViewById<TextView>(R.id.label)\n        val p = Runtime.getRuntime().exec("ping " + label.text.toString())`), "command-injection")).toBe(false);
  });

  it("an incoming Intent's extras and data are input; an Intent this code builds is not", () => {
    expect(flow(activity(`        val url = intent.getStringExtra("url")\n        webView.loadUrl(url)`), "open-redirect")).toBe(true);
    expect(flow(activity(`        val q = intent.data?.getQueryParameter("q")\n        mDB.rawQuery("SELECT * FROM t WHERE n = '" + q + "'", null)`), "sql-injection")).toBe(true);
    expect(flow(activity(`        val intent = Intent(this, Other::class.java)\n        val url = intent.getStringExtra("url")\n        webView.loadUrl(url)`), "open-redirect")).toBe(false);
  });

  it("a BroadcastReceiver's intent parameter is what the sender put there", () => {
    const code = `package app\n\nclass ShowData : BroadcastReceiver() {\n    override fun onReceive(context: Context, intent: Intent) {\n        val cmd = intent.getStringExtra("cmd")\n        Runtime.getRuntime().exec(cmd)\n    }\n}\n`;
    expect(flow(code, "command-injection")).toBe(true);
  });
});

describe("sinks", () => {
  it("SQLiteDatabase.rawQuery / execSQL take SQL text", () => {
    const input = `        val u = findViewById<EditText>(R.id.user)\n`;
    expect(flow(activity(`${input}        val c = mDB.rawQuery("SELECT * FROM users WHERE username='" + u.text + "'", null)`), "sql-injection")).toBe(true);
    expect(flow(activity(`${input}        mDB.execSQL("INSERT INTO users (u) VALUES('\${u.text}')")`), "sql-injection")).toBe(true);
    expect(flow(activity(`${input}        val c = mDB.rawQuery("SELECT * FROM users WHERE username=?", arrayOf(u.text.toString()))`), "sql-injection")).toBe(false);
  });

  it("WebView.loadData renders HTML; loadUrl navigates; a non-WebView loadUrl is neither", () => {
    const input = `        val e = findViewById<EditText>(R.id.e)\n`;
    expect(flow(activity(`${input}        webView.loadData("<p>" + e.text + "</p>", "text/html", "UTF-8")`), "xss")).toBe(true);
    expect(flow(activity(`${input}        webView.loadUrl(e.text.toString())`), "open-redirect")).toBe(true);
    expect(flow(activity(`${input}        loader.loadUrl(e.text.toString())`), "open-redirect")).toBe(false);
  });
});
