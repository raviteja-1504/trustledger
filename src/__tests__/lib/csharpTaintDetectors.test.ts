import { analyzeFile } from "@/lib/scanner";

describe("C# extractTaintedVars: [FromRoute]/[FromQuery] attribute-parameter taint", () => {
  it("propagates a [FromRoute]-bound parameter into a real detector end-to-end", () => {
    const content = `
public class UsersController : ControllerBase {
    public IActionResult GetUser([FromRoute] int id) {
        var user = _db.Users.Find(id);
        return Ok(user);
    }
}
`;
    const result = analyzeFile("Controllers/UsersController.cs", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(true);
  });

  it("propagates a [FromQuery]-bound parameter too", () => {
    const content = `
public class OrdersController : ControllerBase {
    public IActionResult GetOrder([FromQuery] int orderId) {
        var order = _db.Orders.Find(orderId);
        return Ok(order);
    }
}
`;
    const result = analyzeFile("Controllers/OrdersController.cs", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(true);
  });
});

describe("C# SQL injection", () => {
  it("flags SqlCommand built with string concatenation", () => {
    const content = `
public IActionResult GetUser([FromQuery] string id) {
    var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);
    return Ok(cmd.ExecuteReader());
}
`;
    const result = analyzeFile("Controllers/UsersController.cs", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });

  it("flags EF FromSqlRaw with an interpolated string", () => {
    const content = `
public IActionResult GetUser([FromQuery] string id) {
    var user = _context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}").First();
    return Ok(user);
}
`;
    const result = analyzeFile("Controllers/UsersController.cs", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });

  it("does not flag EF's safe FromSqlInterpolated", () => {
    const content = `
public IActionResult GetUser([FromQuery] string id) {
    var user = _context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}").First();
    return Ok(user);
}
`;
    const result = analyzeFile("Controllers/UsersController_safe.cs", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(false);
  });

  it("does not flag a parameterized ADO.NET query even with a tainted value nearby", () => {
    const content = `
public IActionResult GetUser([FromQuery] string id) {
    var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM Users WHERE Id = @id";
    cmd.Parameters.AddWithValue("@id", id);
    return Ok(cmd.ExecuteReader());
}
`;
    const result = analyzeFile("Controllers/UsersController_param.cs", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(false);
  });
});

describe("C# XSS", () => {
  it("flags Html.Raw with a tainted parameter", () => {
    const content = `
public IActionResult Comment([FromQuery] string comment) {
    return Content(Html.Raw(comment).ToString());
}
`;
    const result = analyzeFile("Controllers/CommentController.cs", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(true);
  });

  it("does not flag Razor's default auto-encoded output (no Html.Raw call)", () => {
    const content = `
@model UserViewModel
<h1>Welcome, @Model.Name</h1>
`;
    const result = analyzeFile("Views/Home/Index.cshtml", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(false);
  });
});

describe("C# SSRF", () => {
  it("flags a tainted URL passed to HttpClient.GetAsync", () => {
    const content = `
public async Task<IActionResult> Fetch([FromQuery] string url) {
    var client = new HttpClient();
    var response = await client.GetAsync(url);
    return Ok(response);
}
`;
    const result = analyzeFile("Controllers/FetchController.cs", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });

  it("flags the HttpRequestMessage/SendAsync two-step idiom", () => {
    const content = `
public async Task<IActionResult> Fetch([FromQuery] string url) {
    var request = new HttpRequestMessage(HttpMethod.Get, url);
    var response = await client.SendAsync(request);
    return Ok(response);
}
`;
    const result = analyzeFile("Controllers/FetchController2.cs", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });

  it("does not flag a hardcoded destination", () => {
    const content = `
public async Task<IActionResult> Health() {
    var client = new HttpClient();
    var response = await client.GetAsync("https://internal-health-check.example.com");
    return Ok(response);
}
`;
    const result = analyzeFile("Controllers/HealthController.cs", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(false);
  });
});

describe("C# insecure deserialization", () => {
  it("flags BinaryFormatter.Deserialize on a stream", () => {
    const content = `
public object Load(Stream s) {
    var bf = new BinaryFormatter();
    return bf.Deserialize(s);
}
`;
    const result = analyzeFile("Services/CacheService.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(true);
  });

  it("flags JsonConvert.DeserializeObject with TypeNameHandling.All set nearby", () => {
    const content = `
public object Load(string json) {
    var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
    return JsonConvert.DeserializeObject(json, settings);
}
`;
    const result = analyzeFile("Services/JsonService.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(true);
  });

  it("does not flag plain JsonConvert.DeserializeObject<T> with no TypeNameHandling", () => {
    const content = `
public UserDto Load(string json) {
    return JsonConvert.DeserializeObject<UserDto>(json);
}
`;
    const result = analyzeFile("Services/JsonService_safe.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(false);
  });

  it("does not flag System.Text.Json's safe JsonSerializer.Deserialize<T>", () => {
    const content = `
public UserDto Load(string json) {
    return JsonSerializer.Deserialize<UserDto>(json);
}
`;
    const result = analyzeFile("Services/SystemTextJsonService_safe.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-deserialization")).toBe(false);
  });
});

describe("C# IDOR/BOLA", () => {
  it("flags EF .Find(id) with a tainted route param and no ownership check", () => {
    const content = `
public IActionResult GetUser([FromRoute] int id) {
    var user = _db.Users.Find(id);
    return Ok(user);
}
`;
    const result = analyzeFile("Controllers/UsersController.cs", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(true);
  });

  it("does not flag when an ownership check is present before the lookup", () => {
    const content = `
public IActionResult GetUser([FromRoute] int id) {
    if (!isOwner(currentUserId, id)) return Forbid();
    var user = _db.Users.Find(id);
    return Ok(user);
}
`;
    const result = analyzeFile("Controllers/UsersController_safe.cs", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });

  it("does not flag when [Authorize] is present nearby", () => {
    const content = `
[Authorize]
public IActionResult GetUser([FromRoute] int id) {
    var user = _db.Users.Find(id);
    return Ok(user);
}
`;
    const result = analyzeFile("Controllers/UsersController_authorized.cs", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });
});

describe("C# path traversal", () => {
  it("flags a tainted filename joined via Path.Combine", () => {
    const content = `
public IActionResult Download([FromQuery] string filename) {
    var path = Path.Combine(_basePath, filename);
    return PhysicalFile(path, "application/octet-stream");
}
`;
    const result = analyzeFile("Controllers/FilesController.cs", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });

  it("does not flag a Path.Combine with only fixed, non-tainted segments", () => {
    const content = `
public IActionResult Download() {
    var path = Path.Combine(_basePath, "report.pdf");
    return PhysicalFile(path, "application/pdf");
}
`;
    const result = analyzeFile("Controllers/FilesController_safe.cs", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(false);
  });
});

describe("C# XXE", () => {
  it("flags XmlDocument with no XmlResolver = null", () => {
    const content = `
public void Load(string xml) {
    var doc = new XmlDocument();
    doc.LoadXml(xml);
}
`;
    const result = analyzeFile("Services/XmlService.cs", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(true);
  });

  it("does not flag XmlDocument with XmlResolver explicitly nulled", () => {
    const content = `
public void Load(string xml) {
    var doc = new XmlDocument();
    doc.XmlResolver = null;
    doc.LoadXml(xml);
}
`;
    const result = analyzeFile("Services/XmlService_safe.cs", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(false);
  });

  it("does not flag a bare XmlReaderSettings with no DtdProcessing override", () => {
    const content = `
public void Load(string xml) {
    var settings = new XmlReaderSettings();
    using var reader = XmlReader.Create(new StringReader(xml), settings);
}
`;
    const result = analyzeFile("Services/XmlReaderService_safe.cs", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(false);
  });

  it("flags DtdProcessing explicitly set to Parse", () => {
    const content = `
public void Load(string xml) {
    var settings = new XmlReaderSettings();
    settings.DtdProcessing = DtdProcessing.Parse;
    using var reader = XmlReader.Create(new StringReader(xml), settings);
}
`;
    const result = analyzeFile("Services/XmlReaderService.cs", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(true);
  });
});

describe("C# insecure file upload", () => {
  it("flags IFormFile saved with no extension validation", () => {
    const content = `
public async Task<IActionResult> Upload(IFormFile file) {
    var path = Path.Combine(_uploadDir, file.FileName);
    using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok();
}
`;
    const result = analyzeFile("Controllers/UploadController.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-file-upload")).toBe(true);
  });

  it("does not flag a validated upload path", () => {
    const content = `
public async Task<IActionResult> Upload(IFormFile file) {
    var ext = Path.GetExtension(file.FileName);
    if (!allowedExtensions.Contains(ext)) return BadRequest();
    var path = Path.Combine(_uploadDir, Guid.NewGuid() + ext);
    using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok();
}
`;
    const result = analyzeFile("Controllers/UploadController_safe.cs", content);
    expect(result.indicators.some(i => i.id === "insecure-file-upload")).toBe(false);
  });
});
