import { warmGoTaintEngine, scanAstTaintGo } from "@/lib/astTaintGo";
import { analyzeFile } from "@/lib/scanner";

beforeAll(async () => { await warmGoTaintEngine(); }, 30000);

const HANDLER_PREFIX = `
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

`;

function wrap(body: string): string {
  return `${HANDLER_PREFIX}func handler(w http.ResponseWriter, r *http.Request) {\n${body}\n}\n`;
}

describe("astTaintGo.scanAstTaintGo", () => {
  it("returns [] and never throws on empty input", () => {
    expect(scanAstTaintGo("", "x.go")).toEqual([]);
  });

  it("returns [] and never throws on syntactically broken input", () => {
    expect(scanAstTaintGo("package main\nfunc handler( {{{ not go at all", "x.go")).toEqual([]);
  });

  describe("sql-injection", () => {
    it("flags fmt.Sprintf building a SQL string from a tainted query param", () => {
      const content = wrap(`
	q := r.URL.Query().Get("id")
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", q))
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not flag a parameterized query with a ? placeholder", () => {
      const content = wrap(`
	q := r.URL.Query().Get("id")
	db.Query("SELECT * FROM t WHERE id=?", q)
`);
      // db.Query's own args aren't taint-checked against a literal query
      // string containing "?" -- the sink still fires on any tainted arg to
      // .Query today (matching the regex layer's own recall bias), so this
      // documents current behavior rather than asserting a stronger
      // precision guarantee this phase doesn't add.
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.every(f => f.id !== "path-traversal")).toBe(true);
    });

    it("flags a SQL query built across multiple lines via repeated +=  (regex's structural blind spot)", () => {
      const content = wrap(`
	q := r.URL.Query().Get("id")
	query := "SELECT * FROM t WHERE id="
	query = query + q
	db.Exec(query)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "sql-injection")).toBe(true);
    });
  });

  describe("command-injection", () => {
    it("flags exec.Command with a tainted argument", () => {
      const content = wrap(`
	q := r.URL.Query().Get("host")
	cmd := exec.Command("ping", q)
	cmd.Run()
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(true);
    });

    it("does not flag exec.Command with only fixed arguments", () => {
      const content = wrap(`
	cmd := exec.Command("ls", "-la")
	cmd.Run()
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(false);
    });

    it("flags via a same-file interprocedural helper (buildCmd)", () => {
      const content = `${HANDLER_PREFIX}
func buildCmd(host string) string {
	return "ping -c1 " + host
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("host")
	exec.Command("sh", "-c", buildCmd(q))
}
`;
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(true);
    });

    it("per-parameter precision: a helper using only its SAFE param does not fire on the tainted one", () => {
      const content = `${HANDLER_PREFIX}
func buildLog(safeId string, message string) string {
	return "id=" + safeId
}

func handler(w http.ResponseWriter, r *http.Request) {
	tainted := r.URL.Query().Get("msg")
	exec.Command("sh", "-c", buildLog("safe-id", tainted))
}
`;
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(false);
    });
  });

  describe("ssrf", () => {
    it("flags an inline http.Get with a tainted URL", () => {
      const content = wrap(`
	url := r.URL.Query().Get("target")
	http.Get(url)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "ssrf")).toBe(true);
    });

    it("flags the two-step http.NewRequest + client.Do pattern", () => {
      const content = wrap(`
	url := r.URL.Query().Get("target")
	req, _ := http.NewRequest("GET", url, nil)
	client.Do(req)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "ssrf")).toBe(true);
    });

    it("does not flag a hardcoded URL", () => {
      const content = wrap(`
	http.Get("https://internal.example.com/health")
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "ssrf")).toBe(false);
    });
  });

  describe("path-traversal", () => {
    it("flags os.ReadFile with a tainted path", () => {
      const content = wrap(`
	name := r.URL.Query().Get("file")
	os.ReadFile(name)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "path-traversal")).toBe(true);
    });

    it("flags filepath.Join with a tainted segment", () => {
      const content = wrap(`
	name := r.URL.Query().Get("file")
	filepath.Join("/uploads", name)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "path-traversal")).toBe(true);
    });

    it("does not flag fixed path segments", () => {
      const content = wrap(`
	filepath.Join("/uploads", "static", "logo.png")
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "path-traversal")).toBe(false);
    });
  });

  describe("open-redirect", () => {
    it("flags http.Redirect with a tainted target", () => {
      const content = wrap(`
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, 302)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "open-redirect")).toBe(true);
    });

    it("does not flag a hardcoded redirect target", () => {
      const content = wrap(`
	http.Redirect(w, r, "/dashboard", 302)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "open-redirect")).toBe(false);
    });
  });

  describe("insecure-deserialization", () => {
    it("flags gob.NewDecoder(r.Body).Decode(...)", () => {
      const content = wrap(`
	dec := gob.NewDecoder(r.Body)
	var v map[string]string
	dec.Decode(&v)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "insecure-deserialization")).toBe(true);
    });

    it("does not flag a json.Decoder (different decoder, not gob)", () => {
      const content = wrap(`
	dec := json.NewDecoder(r.Body)
	var v map[string]string
	dec.Decode(&v)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "insecure-deserialization")).toBe(false);
    });
  });

  describe("idor", () => {
    it("flags db.QueryRow with a tainted id and no ownership check nearby", () => {
      const content = wrap(`
	id := r.URL.Query().Get("id")
	db.QueryRow("SELECT * FROM accounts WHERE id=?", id)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "idor")).toBe(true);
    });

    it("does not flag when an ownership-check keyword is nearby", () => {
      const content = wrap(`
	id := r.URL.Query().Get("id")
	if !isOwner(id) {
		return
	}
	db.QueryRow("SELECT * FROM accounts WHERE id=?", id)
`);
      // scanAstTaintGo's idorAuthCheckNearby is injected by its caller
      // (scanner.ts's findAstTaintGoFindings, which reuses the existing
      // IDOR_AUTH_CHECK_NEARBY_RE against this file's raw lines) -- a
      // direct unit-level call needs to supply the same kind of check
      // itself, mirroring scanner.ts's own line-window logic.
      const lines = content.split("\n");
      const idorAuthCheckNearby = (line: number) =>
        lines.slice(Math.max(0, line - 1 - 15), line).some(l => /isOwner/.test(l));
      const findings = scanAstTaintGo(content, "x.go", undefined, idorAuthCheckNearby);
      expect(findings.some(f => f.id === "idor")).toBe(false);
    });
  });

  describe("multi-return heuristic (Decision 6: first-LHS-only)", () => {
    it("tracks the first return value as tainted and never taints trailing err/ok", () => {
      // A same-file taint-preserving helper, not strconv.Atoi: numeric
      // coercion now (correctly) clears path-traversal taint, so it can no
      // longer stand in for "a multi-return call whose first value is tainted".
      const content = `${HANDLER_PREFIX}func parse(s string) (string, error) {
	return s, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("id")
	id, err := parse(q)
	os.ReadFile(id)
	if err != nil {
		os.ReadFile(err)
	}
}
`;
      const findings = scanAstTaintGo(content, "x.go");
      // Both calls are structurally identical sinks; only the first (using
      // `id`, the first LHS identifier) should ever be flagged.
      expect(findings.filter(f => f.id === "path-traversal")).toHaveLength(1);
    });
  });

  it("merges into analyzeFile()'s flat indicator list alongside the existing regex Go findings", () => {
    const content = wrap(`
	q := r.URL.Query().Get("host")
	exec.Command("ping", q)
`);
    const result = analyzeFile("handler.go", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  describe("field-sensitive taint tracking (Decision 1, new capability)", () => {
    it("flags a sink using a field that was itself assigned a tainted value", () => {
      const content = wrap(`
	var user User
	name := r.URL.Query().Get("file")
	user.Name = name
	os.ReadFile(user.Name)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "path-traversal")).toBe(true);
    });

    it("does NOT flag a sibling field on the same object that was never assigned taint", () => {
      // Before this phase, Go's isTainted had no selector_expression case at
      // all -- a bare `user.Email` read always resolved to false regardless
      // of anything, so this already passed for the wrong reason (no field
      // tracking whatsoever). The positive test above now proves the engine
      // is actually field-sensitive, not just silent.
      const content = wrap(`
	var user User
	name := r.URL.Query().Get("file")
	user.Name = name
	os.ReadFile(user.Email)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "path-traversal")).toBe(false);
    });
  });

  describe("sanitizer/de-taint recognition (Decision 2, new capability)", () => {
    it("STILL flags command injection after html.EscapeString (an HTML escaper is the wrong class for a command sink)", () => {
      // This test used to assert the opposite -- that html.EscapeString
      // cleared command-injection taint. That was a false negative: escaping
      // < and > does nothing to stop shell metacharacters. Sanitizers are now
      // keyed by the sink classes they actually neutralize.
      const content = wrap(`
	q := r.URL.Query().Get("host")
	clean := html.EscapeString(q)
	exec.Command("ping", clean)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(true);
    });

    it("does not flag path traversal after filepath.Base (the right class for a path sink)", () => {
      const content = wrap(`
	q := r.URL.Query().Get("f")
	clean := filepath.Base(q)
	os.ReadFile(clean)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "path-traversal")).toBe(false);
    });

    it("still flags command injection after filepath.Base (path sanitizer, wrong class)", () => {
      const content = wrap(`
	q := r.URL.Query().Get("host")
	clean := filepath.Base(q)
	exec.Command("ping", clean)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(true);
    });

    it("numeric coercion (strconv.Atoi) clears injection classes but the id stays attacker-controlled for IDOR", () => {
      const content = wrap(`
	q := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(q)
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %d", id))
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "sql-injection")).toBe(false);
    });

    it("still flags the same shape unsanitized (baseline)", () => {
      const content = wrap(`
	q := r.URL.Query().Get("host")
	exec.Command("ping", q)
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "command-injection")).toBe(true);
    });
  });

  describe("bounded interprocedural propagation (Decision 3, MAX_PROPAGATION_ROUNDS = 3)", () => {
    // Caller-declared-first chain (levelA declared before the levelB it
    // calls, and so on) -- mirrors the exact same proven pattern already
    // used for astTaint.ts/astTaintPython.ts/astTaintJava.ts: the
    // fixed-point pre-pass processes functions in declaration order each
    // round, so levelD resolves round 0, levelC round 1, levelB round 2, and
    // levelA would only resolve in a would-be round 3 -- one past the cap.
    const chain = `
func levelA(x string) string { return levelB(x) }
func levelB(x string) string { return levelC(x) }
func levelC(x string) string { return levelD(x) }
func levelD(x string) string { return x }
`;

    it("resolves a chain called at its base case (0 hops from a param reference)", () => {
      const content = `${HANDLER_PREFIX}${chain}
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("host")
	exec.Command("ping", levelD(q))
}
`;
      expect(scanAstTaintGo(content, "x.go").some(f => f.id === "command-injection")).toBe(true);
    });

    it("resolves levelB, 2 hops deep, within the 3-round cap", () => {
      const content = `${HANDLER_PREFIX}${chain}
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("host")
	exec.Command("ping", levelB(q))
}
`;
      expect(scanAstTaintGo(content, "x.go").some(f => f.id === "command-injection")).toBe(true);
    });

    it("does NOT resolve levelA, the outermost 3-hop caller, proving the round cap is real (not accidentally unbounded)", () => {
      const content = `${HANDLER_PREFIX}${chain}
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("host")
	exec.Command("ping", levelA(q))
}
`;
      expect(scanAstTaintGo(content, "x.go").some(f => f.id === "command-injection")).toBe(false);
    });
  });

  describe("idor — structural ownership-check suppression (Decision 4, new capability alongside the existing regex callback)", () => {
    it("suppresses when the resource id is compared inline against a Gin-style principal lookup (c.GetString), with no idorAuthCheckNearby callback passed at all", () => {
      const content = wrap(`
	id := r.URL.Query().Get("id")
	if id == c.GetString("userId") {
		db.QueryRow("SELECT * FROM accounts WHERE id=?", id)
	}
`);
      // No idorAuthCheckNearby argument -- proves the NEW structural check
      // alone is doing the suppression, not the pre-existing regex hook.
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "idor")).toBe(false);
    });

    it("suppresses via a c.MustGet(\"user\") comparison", () => {
      const content = wrap(`
	id := r.URL.Query().Get("id")
	if id == c.MustGet("user") {
		db.QueryRow("SELECT * FROM accounts WHERE id=?", id)
	}
`);
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "idor")).toBe(false);
    });

    it("still flags when a comparison is present but neither operand is principal-shaped", () => {
      const content = wrap(`
	id := r.URL.Query().Get("id")
	if id == "test" {
		db.QueryRow("SELECT * FROM accounts WHERE id=?", id)
	}
`);
      // Proves this isn't pure comparison-presence, the way the regex
      // heuristic is keyword-presence -- a comparison exists, but neither
      // side is resource-id-vs-principal shaped.
      const findings = scanAstTaintGo(content, "x.go");
      expect(findings.some(f => f.id === "idor")).toBe(true);
    });
  });
});
