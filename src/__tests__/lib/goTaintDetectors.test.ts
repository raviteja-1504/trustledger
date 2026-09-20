import { analyzeFile } from "@/lib/scanner";

describe("Go SQL injection via fmt.Sprintf", () => {
  it("flags a tainted variable interpolated via fmt.Sprintf into a SQL string", () => {
    const content = `
package main
func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)
	rows, err := db.Query(query)
}
`;
    const result = analyzeFile("handlers/user.go", content);
    const finding = result.indicators.find(i => i.id === "sql-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("does not flag a parameterised query using a ? placeholder", () => {
    const content = `
package main
func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, err := db.Query("SELECT * FROM users WHERE id=?", id)
}
`;
    const result = analyzeFile("handlers/user_safe.go", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(false);
  });

  it("flags a tainted variable concatenated with + (already-existing generic coverage)", () => {
    const content = `
package main
func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + id
	rows, err := db.Query(query)
}
`;
    const result = analyzeFile("handlers/user_concat.go", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });
});

describe("Go insecure deserialization via encoding/gob", () => {
  it("flags gob.NewDecoder(r.Body).Decode(...) chained one-liner", () => {
    const content = `
package main
func handle(w http.ResponseWriter, r *http.Request) {
	var payload MyType
	gob.NewDecoder(r.Body).Decode(&payload)
}
`;
    const result = analyzeFile("handlers/decode.go", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(true);
  });

  it("flags a two-step decoder variable built from r.Body", () => {
    const content = `
package main
func handle(w http.ResponseWriter, r *http.Request) {
	var payload MyType
	dec := gob.NewDecoder(r.Body)
	dec.Decode(&payload)
}
`;
    const result = analyzeFile("handlers/decode2.go", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(true);
  });

  it("does not flag json.Decoder on a request body", () => {
    const content = `
package main
func handle(w http.ResponseWriter, r *http.Request) {
	var payload MyType
	json.NewDecoder(r.Body).Decode(&payload)
}
`;
    const result = analyzeFile("handlers/json.go", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(false);
  });

  it("does not flag gob decoding a local trusted file", () => {
    const content = `
package main
func loadCache() {
	f, _ := os.Open("cache.gob")
	dec := gob.NewDecoder(f)
	dec.Decode(&cacheData)
}
`;
    const result = analyzeFile("cache/load.go", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(false);
  });
});

describe("Go weak cryptography", () => {
  it("flags md5.New() used to hash a password", () => {
    const content = `
package main
func hashPassword(password string) string {
	h := md5.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}
`;
    const result = analyzeFile("auth/hash.go", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });

  it("flags des.NewCipher", () => {
    const content = `
package main
func encrypt(key []byte) {
	block, err := des.NewCipher(key)
}
`;
    const result = analyzeFile("auth/cipher.go", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });

  it("does not flag bcrypt", () => {
    const content = `
package main
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}
`;
    const result = analyzeFile("auth/hash_safe.go", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(false);
  });
});

describe("Go SSRF via http.NewRequest + client.Do", () => {
  it("flags a request built from a tainted URL then sent via client.Do", () => {
    const content = `
package main
func proxy(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	req, err := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
}
`;
    const result = analyzeFile("handlers/proxy.go", content);
    const finding = result.indicators.find(i => i.id === "ssrf");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("flags http.NewRequestWithContext built from a tainted URL", () => {
    const content = `
package main
func proxy(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
}
`;
    const result = analyzeFile("handlers/proxy_ctx.go", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });

  it("does not flag a request built from a hardcoded URL", () => {
    const content = `
package main
func fetchStatus() {
	req, err := http.NewRequest("GET", "https://api.internal.example.com/status", nil)
	resp, err := client.Do(req)
}
`;
    const result = analyzeFile("internal/status.go", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(false);
  });
});

describe("Go command injection via exec.Command/CommandContext", () => {
  it("flags a tainted variable passed as an exec.Command argument", () => {
    const content = `
package main
func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("ping", host)
	out, err := cmd.Output()
}
`;
    const result = analyzeFile("handlers/ping.go", content);
    const finding = result.indicators.find(i => i.id === "command-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("flags exec.CommandContext with a tainted argument", () => {
    const content = `
package main
func ping(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.CommandContext(ctx, "ping", host)
	out, err := cmd.Output()
}
`;
    const result = analyzeFile("handlers/ping_ctx.go", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  it("does not flag exec.Command with only fixed arguments", () => {
    const content = `
package main
func listFiles() {
	cmd := exec.Command("ls", "-la")
	out, err := cmd.Output()
}
`;
    const result = analyzeFile("internal/ls.go", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(false);
  });
});

describe("Go path traversal", () => {
  it("flags os.ReadFile with a tainted filename", () => {
    const content = `
package main
func download(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, err := os.ReadFile(filename)
}
`;
    const result = analyzeFile("handlers/download.go", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });

  it("flags filepath.Join with a tainted component", () => {
    const content = `
package main
func serveFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := filepath.Join("/var/data", name)
	data, _ := os.ReadFile(p)
}
`;
    const result = analyzeFile("handlers/serve.go", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });

  it("does not flag a filepath.Join with only fixed, non-tainted segments", () => {
    const content = `
package main
func loadConfig() {
	p := filepath.Join("/etc/app", "config.yaml")
	data, _ := os.ReadFile(p)
}
`;
    const result = analyzeFile("internal/config.go", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(false);
  });
});

describe("Go IDOR via route param flowing into a database/sql or GORM lookup", () => {
  it("flags a route param used in db.QueryRow with no ownership check nearby", () => {
    const content = `
package main
func getOrder(c *gin.Context) {
	id := c.Param("id")
	row := db.QueryRow("SELECT * FROM orders WHERE id=?", id)
}
`;
    const result = analyzeFile("handlers/order.go", content);
    const finding = result.indicators.find(i => i.id === "idor");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("does not flag when an ownership check keyword is nearby", () => {
    const content = `
package main
func getOrder(c *gin.Context) {
	id := c.Param("id")
	userID := c.MustGet("userID").(string)
	if !isOwner(userID, id) {
		c.AbortWithStatus(403)
		return
	}
	row := db.QueryRow("SELECT * FROM orders WHERE id=?", id)
}
`;
    const result = analyzeFile("handlers/order_safe.go", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });

  it("does not flag when only Gin's identity-from-context call is nearby (new Go-specific guard)", () => {
    const content = `
package main
func getOrder(c *gin.Context) {
	userID := c.MustGet("userID").(string)
	id := c.Param("id")
	row := db.QueryRow("SELECT * FROM orders WHERE id=? AND user_id=?", id, userID)
}
`;
    const result = analyzeFile("handlers/order_ctxguard.go", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });

  it("propagates taint through a := second-hop and strconv.Atoi multi-return", () => {
    const content = `
package main
func serveFile(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	row := db.QueryRow("SELECT * FROM files WHERE id=?", id)
}
`;
    const result = analyzeFile("handlers/files.go", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(true);
  });

  it("flags a chi-router param flowing through mux.Vars-equivalent second-hop propagation", () => {
    const content = `
package main
func getOrder(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	row := db.QueryRow("SELECT * FROM orders WHERE id=?", id)
}
`;
    const result = analyzeFile("handlers/mux_order.go", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(true);
  });
});

describe("Go hardcoded secrets — MySQL connection string", () => {
  it("flags a MySQL connection string with embedded credentials", () => {
    const content = `
package main
const databaseURL = "mysql://admin:SuperSecretPassword@db.internal:3306/app"
func main() {}
`;
    const result = analyzeFile("config.go", content);
    expect(result.indicators.some(i => i.id === "hardcoded-secret")).toBe(true);
  });

  it("does not suppress a real branded secret whose value happens to contain the word 'password'", () => {
    // Regression for the actual root-cause bug found while adding the MySQL
    // pattern above: PLACEHOLDER_VALUE_RE's old bare "password" marker (no
    // word boundary) matched "SuperSecretPassword" as a substring, silently
    // treating the whole line as placeholder text and suppressing every
    // SECRET_PATTERNS check on it -- not just the new MySQL pattern.
    // Uses a Postgres connection string (not a Stripe-shaped key) so this
    // fixture doesn't resemble a real, scannable secret format on its own.
    const content = `
package main
const dbURL = "postgresql://admin:SuperSecretPassword@db.internal:5432/app"
func main() {}
`;
    const result = analyzeFile("config2.go", content);
    expect(result.indicators.some(i => i.id === "hardcoded-secret")).toBe(true);
  });

  it("still suppresses a genuine your_password_here-style placeholder", () => {
    const content = `
package main
const apiKey = "your_password_here"
func main() {}
`;
    const result = analyzeFile("config3.go", content);
    expect(result.indicators.some(i => i.id === "hardcoded-secret")).toBe(false);
  });
});

describe("Go insecure randomness — math/rand inside a security-sounding function", () => {
  it("flags rand.Int() used inside a function named createSessionToken", () => {
    const content = `
package main
func createSessionToken() string {
	return fmt.Sprintf("%d-%d", time.Now().Unix(), rand.Int())
}
`;
    const result = analyzeFile("session.go", content);
    expect(result.indicators.some(i => i.id === "insecure-randomness")).toBe(true);
  });

  it("flags a keyword+rand call on the same line (the previously-broken flat entry)", () => {
    const content = `
package main
func build() {
	token := fmt.Sprintf("%d", rand.Intn(1000000))
}
`;
    const result = analyzeFile("build.go", content);
    expect(result.indicators.some(i => i.id === "insecure-randomness")).toBe(true);
  });

  it("does not flag rand.Int() inside a function with no security-sounding name", () => {
    const content = `
package main
func randomJitter() int {
	return rand.Int()
}
`;
    const result = analyzeFile("jitter.go", content);
    expect(result.indicators.some(i => i.id === "insecure-randomness")).toBe(false);
  });

  it("does not flag crypto/rand.Int(reader, max) even inside a security-sounding function", () => {
    const content = `
package main
func createSecureToken() (*big.Int, error) {
	return rand.Int(rand.Reader, max)
}
`;
    const result = analyzeFile("secure_session.go", content);
    expect(result.indicators.some(i => i.id === "insecure-randomness")).toBe(false);
  });
});

describe("Go open redirect", () => {
  it("flags a named-taint redirect target assigned on an earlier line", () => {
    const content = `
package main
func openRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	http.Redirect(w, r, target, http.StatusFound)
}
`;
    const result = analyzeFile("handlers/redirect.go", content);
    expect(result.indicators.some(i => i.id === "open-redirect")).toBe(true);
  });

  it("flags a request-derived target passed inline to http.Redirect", () => {
    const content = `
package main
func redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}
`;
    const result = analyzeFile("handlers/redirect2.go", content);
    expect(result.indicators.some(i => i.id === "open-redirect")).toBe(true);
  });

  it("does not flag a redirect to a hardcoded path", () => {
    const content = `
package main
func redirectHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/home", http.StatusFound)
}
`;
    const result = analyzeFile("handlers/redirect_safe.go", content);
    expect(result.indicators.some(i => i.id === "open-redirect")).toBe(false);
  });
});

describe("Go cookie security — http.SetCookie struct-literal shape", () => {
  it("flags a session cookie with no HttpOnly flag", () => {
    const content = `
package main
func insecureSession(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: createSessionToken(),
	})
}
`;
    const result = analyzeFile("handlers/session.go", content);
    const finding = result.indicators.find(i => i.id === "cookie-no-httponly");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("flags an auth cookie whose value is set directly from form input", () => {
    const content = `
package main
func weakCookie(w http.ResponseWriter, r *http.Request) {
	value := r.FormValue("value")
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: value})
}
`;
    const result = analyzeFile("handlers/weak_cookie.go", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(true);
  });

  it("flags cookie-no-secure when HttpOnly is set but Secure is missing", () => {
    const content = `
package main
func setCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "x",
		HttpOnly: true,
	})
}
`;
    const result = analyzeFile("handlers/partial.go", content);
    expect(result.indicators.some(i => i.id === "cookie-no-secure")).toBe(true);
  });

  it("does not flag a fully-hardened cookie", () => {
    const content = `
package main
func setCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "x",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
`;
    const result = analyzeFile("handlers/hardened.go", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(false);
    expect(result.indicators.some(i => i.id === "cookie-no-secure")).toBe(false);
  });

  it("does not flag a non-auth cookie missing HttpOnly", () => {
    const content = `
package main
func setPreference(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
}
`;
    const result = analyzeFile("handlers/prefs.go", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(false);
  });
});

describe("Go PII in logs — log.Printf with a labeled sensitive field", () => {
  it("flags log.Printf with password=%s in the format string", () => {
    const content = `
package main
func logSensitiveData(r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	log.Printf("login username=%s password=%s", username, password)
}
`;
    const result = analyzeFile("handlers/logging.go", content);
    expect(result.indicators.some(i => i.id === "pii-in-logs")).toBe(true);
  });

  it("does not flag an ordinary log.Printf with no sensitive field label", () => {
    const content = `
package main
func logRequest(r *http.Request) {
	log.Printf("handled request method=%s path=%s", r.Method, r.URL.Path)
}
`;
    const result = analyzeFile("handlers/logging_safe.go", content);
    expect(result.indicators.some(i => i.id === "pii-in-logs")).toBe(false);
  });
});
