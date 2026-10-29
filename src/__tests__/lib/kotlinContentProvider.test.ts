/**
 * @jest-environment node
 *
 * Kotlin / Android found scanning Goatlin and AndroGoat: an exported ContentProvider's query / update / delete
 * parameters reaching SQLiteQueryBuilder / SQLiteDatabase by argument position (selectionArgs stay bound and clean),
 * and android.util.Log's one-letter methods as log sinks.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";

beforeAll(async () => { await warmKotlinTaintEngine(); }, 120000);

const provider = (base: string, body: string) => `package com.example
import android.content.ContentProvider
import android.database.Cursor
import android.database.sqlite.SQLiteQueryBuilder
import android.net.Uri

class NotesProvider : ${base} {
    lateinit var database: DatabaseHelper
    override fun query(uri: Uri, projection: Array<String>?, selection: String?,
                       selectionArgs: Array<String>?, sortOrder: String?): Cursor? {
        val queryBuilder = SQLiteQueryBuilder()
        queryBuilder.tables = "notes"
${body}
    }
}
`;
const sqli = (code: string) => analyzeFile("app/src/main/java/com/example/NotesProvider.kt", code).indicators.some(i => i.id === "sql-injection" && !!i.sourceExpr);

describe("ContentProvider SQL injection", () => {
  it("the caller's selection / sortOrder reach SQLiteQueryBuilder.query", () => {
    expect(sqli(provider("ContentProvider()", `        return queryBuilder.query(database.readableDatabase, projection, selection, selectionArgs, null, null, sortOrder)`))).toBe(true);
  });
  it("only selectionArgs (bound) from the caller is safe", () => {
    expect(sqli(provider("ContentProvider()", `        return queryBuilder.query(database.readableDatabase, projection, "owner = ?", selectionArgs, null, null, "title")`))).toBe(false);
  });
  it("the URI's last segment appended to the WHERE clause", () => {
    expect(sqli(provider("ContentProvider()", `        queryBuilder.appendWhere("_id=" + uri.lastPathSegment)\n        return queryBuilder.query(database.readableDatabase, projection, "1", null, null, null, null)`))).toBe(true);
    expect(sqli(provider("ContentProvider()", `        queryBuilder.appendWhereEscapeString(uri.lastPathSegment ?: "")\n        return queryBuilder.query(database.readableDatabase, projection, "1", null, null, null, null)`))).toBe(false);
  });
  it("the same method in a class that is no provider is not an entry point", () => {
    expect(sqli(provider("Repository()", `        return queryBuilder.query(database.readableDatabase, projection, selection, selectionArgs, null, null, sortOrder)`))).toBe(false);
  });
});

describe("android.util.Log", () => {
  const act = (stmt: string) => `package com.example
import android.util.Log
import android.widget.EditText

class LoginActivity : AppCompatActivity() {
    fun onLogin() {
        val username = findViewById<EditText>(R.id.userName)
        ${stmt}
    }
}
`;
  it("Log.i / Log.d with what the user typed; a constant message is not", () => {
    const ids = (s: string) => analyzeFile("app/LoginActivity.kt", act(s)).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
    expect(ids(`Log.i("Info:", "Username: \${username.text} verified")`)).toContain("log-injection");
    expect(ids(`Log.d("Login", username.text.toString())`)).toContain("log-injection");
    expect(ids(`Log.i("Info:", "login verified")`)).not.toContain("log-injection");
  });
});
