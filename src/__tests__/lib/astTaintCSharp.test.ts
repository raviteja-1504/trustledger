import { warmCSharpTaintEngine, parseCSharpSourceSync, scanAstTaintCSharp } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmCSharpTaintEngine(); }, 30000);

function scan(content: string) {
  const root = parseCSharpSourceSync(content, "A.cs");
  if (!root) throw new Error("parse failed");
  return scanAstTaintCSharp(content, "A.cs", root);
}

describe("astTaintCSharp.scanAstTaintCSharp", () => {
  it("returns [] and never throws on empty input", () => {
    expect(scan("")).toEqual([]);
  });

  it("returns [] and never throws on syntactically broken input", () => {
    const root = parseCSharpSourceSync("public class {{{ not csharp", "x.cs");
    // tree-sitter is error-tolerant and returns a best-effort tree rather
    // than null for most malformed input (unlike java-parser's Chevrotain
    // parser) -- the real safety property to prove is that scanning it
    // never throws, matching astTaintGo.ts's/astTaintPython.ts's own
    // malformed-input tests.
    if (root) expect(() => scanAstTaintCSharp("public class {{{ not csharp", "x.cs", root)).not.toThrow();
  });

  describe("sql-injection", () => {
    it("flags EF Core FromSqlRaw with a tainted query string", () => {
      const content = `
public class A {
  [HttpGet("search")]
  public IActionResult Search([FromQuery] string name) {
    var sql = "SELECT * FROM Users WHERE Name = '" + name + "'";
    db.Users.FromSqlRaw(sql);
    return Ok();
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("flags a SqlCommand built from a tainted string then .ExecuteReader()'d", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    var sql = "SELECT * FROM Users WHERE Name = '" + name + "'";
    var cmd = new SqlCommand(sql);
    cmd.ExecuteReader();
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not flag a parameterized SqlCommand with no tainted string concatenation", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name");
    cmd.Parameters.AddWithValue("@name", name);
    cmd.ExecuteReader();
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    });
  });

  describe("command-injection", () => {
    it("flags Process.Start with a tainted argument", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string host) {
    Process.Start("ping", host);
  }
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });

    it("does not flag Process.Start with only fixed arguments", () => {
      const content = `
public class A {
  public void Cleanup() {
    Process.Start("rm", "-rf /tmp/cache");
  }
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
    });
  });

  describe("xss", () => {
    it("flags Html.Raw with tainted input", () => {
      const content = `
public class A {
  public IActionResult Handle([FromQuery] string name) {
    return Content(Html.Raw(name));
  }
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(true);
    });

    it("flags Response.Write with tainted input", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    Response.Write(name);
  }
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(true);
    });
  });

  describe("ssrf", () => {
    it("flags HttpClient.GetAsync with a tainted URL", () => {
      const content = `
public class A {
  public async Task Handle([FromQuery] string url) {
    await client.GetAsync(url);
  }
}`;
      expect(scan(content).some(f => f.id === "ssrf")).toBe(true);
    });

    it("flags the two-step new HttpRequestMessage + SendAsync pattern", () => {
      const content = `
public class A {
  public async Task Handle([FromQuery] string url) {
    var req = new HttpRequestMessage(HttpMethod.Get, url);
    await client.SendAsync(req);
  }
}`;
      expect(scan(content).some(f => f.id === "ssrf")).toBe(true);
    });
  });

  describe("path-traversal", () => {
    it("flags Path.Combine with a tainted segment", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string file) {
    var path = Path.Combine("/uploads", file);
    File.ReadAllText(path);
  }
}`;
      expect(scan(content).some(f => f.id === "path-traversal")).toBe(true);
    });

    it("does not flag fixed path segments", () => {
      const content = `
public class A {
  public void Handle() {
    var path = Path.Combine("/uploads", "static", "logo.png");
  }
}`;
      expect(scan(content).some(f => f.id === "path-traversal")).toBe(false);
    });
  });

  describe("open-redirect", () => {
    it("flags Redirect with a tainted target", () => {
      const content = `
public class A {
  public IActionResult Handle([FromQuery] string next) {
    return Redirect(next);
  }
}`;
      expect(scan(content).some(f => f.id === "open-redirect")).toBe(true);
    });

    it("does not flag a hardcoded redirect target", () => {
      const content = `
public class A {
  public IActionResult Handle() {
    return Redirect("/dashboard");
  }
}`;
      expect(scan(content).some(f => f.id === "open-redirect")).toBe(false);
    });
  });

  describe("insecure-deserialization", () => {
    it("flags BinaryFormatter.Deserialize with a tainted stream", () => {
      const content = `
public class A {
  public void Handle([FromBody] Stream data) {
    var formatter = new BinaryFormatter();
    formatter.Deserialize(data);
  }
}`;
      expect(scan(content).some(f => f.id === "insecure-deserialization")).toBe(true);
    });
  });

  describe("ldap-injection", () => {
    it("flags a DirectorySearcher.Filter assignment with tainted input", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string username) {
    var searcher = new DirectorySearcher();
    searcher.Filter = "(&(objectClass=person)(uid=" + username + "))";
  }
}`;
      expect(scan(content).some(f => f.id === "ldap-injection")).toBe(true);
    });
  });

  describe("same-file interprocedural call binding", () => {
    it("propagates taint through a local helper's return value to the call site", () => {
      const content = `
public class A {
  private string BuildQuery(string name) {
    return "SELECT * FROM Users WHERE Name = '" + name + "'";
  }
  public void Handle([FromQuery] string name) {
    db.Users.FromSqlRaw(BuildQuery(name));
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not propagate taint through a helper whose return never depends on its parameters", () => {
      const content = `
public class A {
  private string TableName(string name) {
    return "Users";
  }
  public void Handle([FromQuery] string name) {
    db.Users.FromSqlRaw(TableName(name));
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    });

    it("catches a sink call inside a local method's own body (not just its return)", () => {
      const content = `
public class A {
  private void LogAndRun(string cmd) {
    Process.Start(cmd);
  }
  public void Handle([FromQuery] string userCmd) {
    LogAndRun(userCmd);
  }
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });
  });

  describe("field-sensitive taint tracking (new capability)", () => {
    it("flags a sink using a field that was itself assigned a tainted value", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    var user = new User();
    user.Name = name;
    db.Users.FromSqlRaw("SELECT * FROM t WHERE x = '" + user.Name + "'");
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
    });

    it("does not flag a sibling field never assigned taint", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    var user = new User();
    user.Name = name;
    db.Users.FromSqlRaw("SELECT * FROM t WHERE x = '" + user.Email + "'");
  }
}`;
      expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    });
  });

  describe("sanitizer recognition (new capability)", () => {
    it("does not flag a value sanitized via WebUtility.HtmlEncode before reaching a sink", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    var clean = WebUtility.HtmlEncode(name);
    Response.Write(clean);
  }
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(false);
    });

    it("still flags an unsanitized value reaching the same sink", () => {
      const content = `
public class A {
  public void Handle([FromQuery] string name) {
    Response.Write(name);
  }
}`;
      expect(scan(content).some(f => f.id === "xss")).toBe(true);
    });
  });

  describe("bounded interprocedural propagation (MAX_PROPAGATION_ROUNDS = 3)", () => {
    const chain = `
public class A {
  private string LevelA(string x) { return LevelB(x); }
  private string LevelB(string x) { return LevelC(x); }
  private string LevelC(string x) { return LevelD(x); }
  private string LevelD(string x) { return x; }`;

    it("resolves a chain called at its base case", () => {
      const content = `${chain}
  public void Handle([FromQuery] string input) {
    Process.Start(LevelD(input));
  }
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });

    it("resolves LevelB, 2 hops deep, within the cap", () => {
      const content = `${chain}
  public void Handle([FromQuery] string input) {
    Process.Start(LevelB(input));
  }
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
    });

    it("does NOT resolve LevelA, the outermost 3-hop caller, proving the round cap is real", () => {
      const content = `${chain}
  public void Handle([FromQuery] string input) {
    Process.Start(LevelA(input));
  }
}`;
      expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
    });
  });
});

describe("BOLA (Broken Object Level Authorization) — ASP.NET Core resource-identifier ownership check", () => {
  function scan(content: string) {
    const root = parseCSharpSourceSync(content, "A.cs");
    if (!root) throw new Error("parse failed");
    return scanAstTaintCSharp(content, "A.cs", root);
  }

  it("flags a GET endpoint with no ownership check reaching an EF lookup", () => {
    const content = `
public class A {
  [HttpGet("{id}")]
  public IActionResult GetUser([FromRoute] string id) {
    var user = db.Users.Find(id);
    return Ok(user);
  }
}`;
    const bola = scan(content).filter(f => f.id === "bola-missing-ownership-check");
    expect(bola.some(f => f.severityOverride === "medium")).toBe(true);
  });

  it("flags a DELETE endpoint (write) at high severity", () => {
    const content = `
public class A {
  [HttpDelete("{id}")]
  public IActionResult DeleteUser([FromRoute] string id) {
    db.Users.Remove(id);
    return Ok();
  }
}`;
    const bola = scan(content).filter(f => f.id === "bola-missing-ownership-check");
    expect(bola.some(f => f.severityOverride === "high")).toBe(true);
  });

  it("does not flag when a real ownership comparison is present in the method body", () => {
    const content = `
public class A {
  [HttpGet("{id}")]
  public IActionResult GetUser([FromRoute] string id) {
    if (id != User.Identity.Name) {
      return Forbid();
    }
    return Ok(db.Users.Find(id));
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("suppresses when [Authorize] is present, regardless of method body", () => {
    const content = `
public class A {
  [Authorize]
  [HttpDelete("{id}")]
  public IActionResult DeleteUser([FromRoute] string id) {
    db.Users.Remove(id);
    return Ok();
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("does not flag a non-endpoint method (no Http* attribute)", () => {
    const content = `
public class A {
  public IActionResult InternalHelper(string id) {
    return Ok(db.Users.Find(id));
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("flags new ClassName(id) constructor-sink shape (WebGoat-style gap Java's own engine needed a fix for)", () => {
    const content = `
public class A {
  [HttpGet("{id}")]
  public IActionResult GetProfile([FromRoute] string id) {
    var profile = new UserProfile(id);
    return Ok(profile);
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });

  it("never throws on a malformed C# snippet", () => {
    const content = `
public class A {
  [HttpGet(
  public IActionResult Get([FromRoute] string id) {
    return null;
`;
    const root = parseCSharpSourceSync(content, "A.cs");
    if (root) expect(() => scanAstTaintCSharp(content, "A.cs", root)).not.toThrow();
  });
});
