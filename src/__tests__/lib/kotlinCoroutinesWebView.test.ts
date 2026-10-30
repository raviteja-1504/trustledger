/**
 * @jest-environment node
 *
 * Kotlin flows through coroutine builders and calls with both arguments and a trailing lambda
 * (`withContext(IO) { ... }` parses as a call on a call), and a WebView that loads an attacker-chosen URL while
 * exposing a JavaScript bridge.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";

beforeAll(async () => { await warmKotlinTaintEngine(); }, 120000);

const act = (body: string) => `package app.demo

import android.database.sqlite.SQLiteDatabase
import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SearchActivity : AppCompatActivity() {
    private lateinit var db: SQLiteDatabase
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
${body}
    }
}
`;
const found = (body: string) => analyzeFile("app/src/main/java/app/demo/SearchActivity.kt", act(body)).indicators.filter(i => !!i.sourceExpr);
const ids = (body: string) => found(body).map(i => i.id);
const sink = `        db.execSQL("DELETE FROM notes WHERE title = '$q'")`;

describe("values out of coroutine builders and argument + lambda calls", () => {
  it("withContext(IO) { input } / async(IO) { input } carry the input; a constant block does not", () => {
    expect(ids(`        lifecycleScope.launch {\n            val q = withContext(Dispatchers.IO) { intent.getStringExtra("q") }\n    ${sink}\n        }`)).toContain("sql-injection");
    expect(ids(`        val q = withContext(Dispatchers.IO) { intent.getStringExtra("q") }\n${sink}`)).toContain("sql-injection");
    expect(ids(`        val q = withContext(Dispatchers.IO) { "fixed" }\n${sink}`)).not.toContain("sql-injection");
    expect(ids(`        val q = runCatching { intent.getStringExtra("q") }.getOrNull()\n${sink}`)).toContain("sql-injection");
  });
  it("fold(initial) { acc, x -> ... }: the block's value", () => {
    expect(ids(`        val q = listOf(1).fold("") { acc, _ -> acc + intent.getStringExtra("q") }\n${sink}`)).toContain("sql-injection");
    expect(ids(`        val q = listOf(1).fold("") { acc, _ -> acc + "x" }\n${sink}`)).not.toContain("sql-injection");
  });
});

describe("a sink with arguments and a trailing lambda", () => {
  it("jdbcTemplate.query(sql) { rs, _ -> ... }: the SQL argument, not the row mapper", () => {
    const ctl = (sql: string) => `package app.demo

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class NoteController(private val jdbcTemplate: JdbcTemplate) {
    @GetMapping("/notes")
    fun find(@RequestParam name: String): List<String> {
        return jdbcTemplate.query(${sql}) { rs, _ -> rs.getString(1) }
    }
}
`;
    const sqlIds = (sql: string) => analyzeFile("src/main/kotlin/app/demo/NoteController.kt", ctl(sql)).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
    expect(sqlIds(`"SELECT title FROM notes WHERE owner = '" + name + "'"`)).toContain("sql-injection");
    expect(sqlIds(`"SELECT title FROM notes WHERE owner = 'admin'"`)).not.toContain("sql-injection");
  });
});

describe("WebView with a JavaScript bridge", () => {
  const web = (bridge: string) => `        val web = findViewById<WebView>(R.id.web)\n        web.settings.javaScriptEnabled = true\n${bridge}        web.loadUrl(intent.getStringExtra("url") ?: "")`;
  it("an attacker-chosen URL is critical when the page can call into the app", () => {
    const withBridge = found(web(`        web.addJavascriptInterface(Bridge(), "bridge")\n`)).find(i => i.id === "open-redirect");
    expect(withBridge?.severity).toBe("critical");
    expect(withBridge?.detail).toMatch(/JavaScript bridge/);
    const plain = found(web("")).find(i => i.id === "open-redirect");
    expect(plain?.severity).not.toBe("critical");
  });
});
