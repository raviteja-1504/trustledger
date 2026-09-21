import { analyzeFile } from "@/lib/scanner";

// Regex-layer (scanner.ts) detectors added while closing C#-detector gaps
// surfaced by a real ASP.NET Core OWASP benchmark file -- mirrors
// goTaintDetectors.test.ts's own analyzeFile()-based, end-to-end style.
// The AST-layer (astTaintCSharp.ts) counterparts of the sink-broadening
// decisions (BOLA, LDAP, SSRF, XSS, path-traversal) are already covered
// in astTaintCSharp.test.ts -- this file covers the categories that are
// regex-only (weak-crypto, insecure-randomness, weak-signing-secret,
// cookie security, missing-security-headers) plus the regex-layer mirrors
// of the AST-layer decisions.

describe("C# weak-crypto (regex-only, no AST engine equivalent anywhere)", () => {
  it("flags MD5.Create()", () => {
    const content = `
public class A {
  [HttpPost("hash-md5")]
  public IActionResult WeakMd5([FromBody] string password) {
    using var md5 = MD5.Create();
    var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
    return Ok(Convert.ToHexString(hash));
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });

  it("flags SHA1.Create()", () => {
    const content = `
public class A {
  [HttpPost("hash-sha1")]
  public IActionResult WeakSha1([FromBody] string password) {
    using var sha1 = SHA1.Create();
    return Ok(sha1.ComputeHash(Encoding.UTF8.GetBytes(password)));
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });

  it("flags CipherMode.ECB", () => {
    const content = `
public class A {
  [HttpPost("encrypt")]
  public IActionResult WeakEncryption([FromBody] string input) {
    using var aes = Aes.Create();
    aes.Mode = CipherMode.ECB;
    return Ok();
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "weak-crypto")).toBe(true);
  });
});

describe("C# insecure-randomness (System.Random inside a security-named method, two-line idiom)", () => {
  it("flags Random().Next(...) used inside a method whose name is security-sounding", () => {
    const content = `
public class A {
  [HttpGet("weak-token")]
  public IActionResult WeakToken() {
    var random = new Random();
    return Ok(random.Next(100000, 999999));
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-randomness")).toBe(true);
  });

  it("does not flag System.Random used inside an unrelated, non-security-named method", () => {
    const content = `
public class A {
  [HttpGet("shuffle")]
  public IActionResult ShuffleDeck() {
    var random = new Random();
    return Ok(random.Next(0, 52));
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-randomness")).toBe(false);
  });
});

describe("C# weak-signing-secret (private const string modifier chain)", () => {
  it("flags a hardcoded JWT secret declared as a private const string", () => {
    const content = `
public class A {
  private const string JwtSecret = "super-secret-jwt-key-123456";
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(true);
  });
});

describe("C# insecure session cookie (Response.Cookies.Append + CookieOptions object initializer)", () => {
  it("flags an auth cookie set with HttpOnly = false", () => {
    const content = `
public class A {
  [HttpPost("session")]
  public IActionResult CreateSession(string userId) {
    Response.Cookies.Append("session", userId, new CookieOptions {
      HttpOnly = false,
      Secure = false,
      SameSite = SameSiteMode.None
    });
    return Ok();
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(true);
  });

  it("does not flag a non-auth-named cookie", () => {
    const content = `
public class A {
  [HttpGet("theme")]
  public IActionResult SetTheme(string theme) {
    Response.Cookies.Append("theme", theme, new CookieOptions { HttpOnly = false });
    return Ok();
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "cookie-no-httponly")).toBe(false);
  });
});

describe("C# plaintext password storage (call-shaped, not field-assignment)", () => {
  it("flags a tainted password passed straight into a SavePassword(...) call", () => {
    const content = `
public class A {
  [HttpPost("password")]
  public IActionResult StorePassword([FromBody] LoginRequest request) {
    Database.SavePassword(request.Username, request.Password);
    return Ok();
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "plaintext-password-storage")).toBe(true);
  });
});

describe("C# mass assignment (whole [FromBody] object passed into a write-shaped call)", () => {
  it("flags a [FromBody]-bound profile object passed whole into UpdateProfile(...)", () => {
    const content = `
public class A {
  [HttpPut("profile")]
  public IActionResult UpdateProfile([FromBody] UserProfile profile) {
    Database.UpdateProfile(profile);
    return Ok(profile);
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "mass-assignment")).toBe(true);
  });
});

describe("C# missing security headers (explicit Response.Headers.Remove of a known security header)", () => {
  it("flags removal of X-Frame-Options/CSP/X-Content-Type-Options", () => {
    const content = `
public class A {
  [HttpGet("headers")]
  public IActionResult MissingHeaders() {
    Response.Headers.Remove("X-Content-Type-Options");
    Response.Headers.Remove("Content-Security-Policy");
    Response.Headers.Remove("X-Frame-Options");
    return Ok("unsafe headers");
  }
}`;
    const result = analyzeFile("A.cs", content);
    const findings = result.indicators.filter(i => i.id === "missing-security-headers");
    expect(findings.length).toBe(3);
  });

  it("does not flag removal of an unrelated, non-security header", () => {
    const content = `
public class A {
  [HttpGet("headers")]
  public IActionResult RemoveServerHeader() {
    Response.Headers.Remove("Server");
    return Ok();
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "missing-security-headers")).toBe(false);
  });
});

describe("C# implicit ASP.NET Core model binding -- regex layer (extractTaintedVars mirror of the AST fix)", () => {
  it("flags path-traversal for Path.Combine(..., file) where `file` has no [FromQuery] attribute", () => {
    const content = `
public class A {
  [HttpGet("download")]
  public IActionResult Download(string file) {
    var path = Path.Combine("/var/app/files", file);
    return PhysicalFile(path, "application/octet-stream");
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });
});

describe("C# SSRF via HttpClient shorthand methods (regex layer)", () => {
  it("flags GetStringAsync(url) where url is a tainted bare identifier", () => {
    const content = `
public class A {
  [HttpGet("fetch")]
  public async Task<IActionResult> Fetch([FromQuery] string url) {
    using var client = new HttpClient();
    return Ok(await client.GetStringAsync(url));
  }
}`;
    const result = analyzeFile("A.cs", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });
});
