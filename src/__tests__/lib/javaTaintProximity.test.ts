import { analyzeFile } from "@/lib/scanner";

describe("Java taint-proximity detectors (found via real-world Spring Boot benchmark testing)", () => {
  it("flags SQL injection built across multiple wrapped lines from a @RequestParam", () => {
    const content = `
@GetMapping("/api/search")
public ResponseEntity<?> search(
        @RequestParam String username) throws Exception {

    String query =
            "SELECT * FROM users WHERE username = '"
            + username
            + "'";

    List<Map<String, Object>> result =
            executeQuery(query);

    return ResponseEntity.ok(result);
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });

  it("flags command injection via Runtime.exec fed by a @RequestParam", () => {
    const content = `
@GetMapping("/api/ping")
public ResponseEntity<?> ping(
        @RequestParam String host) throws Exception {

    String command = "ping -c 1 " + host;

    Process process =
            Runtime.getRuntime().exec(
                    new String[]{"sh", "-c", command}
            );

    return ResponseEntity.ok(readProcess(process));
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  it("flags command injection via ProcessBuilder", () => {
    const content = `
@GetMapping("/api/run")
public ResponseEntity<?> run(
        @RequestParam String command) throws Exception {

    ProcessBuilder builder =
            new ProcessBuilder("sh", "-c", command);

    Process process = builder.start();

    return ResponseEntity.ok(readProcess(process));
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
  });

  it("flags path traversal via Paths.get/Files.readString fed by a @RequestParam", () => {
    const content = `
@GetMapping("/download")
public ResponseEntity<?> download(
        @RequestParam String file) throws Exception {

    Path path =
            Paths.get("/tmp/uploads/" + file);

    return ResponseEntity.ok(Files.readString(path));
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(true);
  });

  it("flags reflected XSS via a raw HTML response body corroborated by an HTML tag nearby", () => {
    const content = `
@GetMapping("/hello")
public ResponseEntity<?> hello(
        @RequestParam String name) {

    String html =
            "<html><body><h1>Hello "
            + name
            + "</h1></body></html>";

    return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body(html);
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(true);
  });

  it("does not flag .body(x) for an ordinary JSON response with no HTML tag nearby", () => {
    const content = `
@GetMapping("/api/data")
public ResponseEntity<?> data(@RequestParam String apiKey) {
    Map<String, Object> result = Map.of("apiKey", apiKey);
    return ResponseEntity.ok().body(result);
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(false);
  });

  it("flags a JWT secret whose declaration and literal value are split across two lines", () => {
    const content = `
private static final String JWT_SECRET =
        "trustledger-super-secret-jwt-key-987654";
`;
    const result = analyzeFile("Benchmark.java", content);
    const finding = result.indicators.find(i => i.id === "weak-signing-secret");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("does not flag command injection with no request-derived taint anywhere nearby", () => {
    const content = `
public void cleanup() {
    try {
        Process process = Runtime.getRuntime().exec("rm -rf /tmp/cache");
    } catch (Exception e) {}
}
`;
    const result = analyzeFile("Benchmark.java", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(false);
  });
});
