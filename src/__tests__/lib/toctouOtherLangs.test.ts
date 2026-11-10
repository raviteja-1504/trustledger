/**
 * @jest-environment node
 *
 * Check-then-create outside JavaScript (CWE-367): a path is checked and then created or written under the same name,
 * so another process can swap in a symlink or a different file in between. Each language has twins that stay silent:
 * a read after the check, a different path, an exclusive create, a lock, an idempotent mkdir.
 */
import { analyzeFile } from "@/lib/scanner";

const has = (file: string, code: string) => analyzeFile(file, code).indicators.some(i => i.id === "toctou");

describe("TOCTOU: check, then create or write the same path", () => {
  it("Go: os.Stat then os.Create / os.WriteFile; a read, another path, O_EXCL, a lock are not", () => {
    const go = (body: string) => `package main\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tpath := r.URL.Query().Get("p")\n${body}\n}\n`;
    expect(has("a.go", go(`\t_, err := os.Stat(path)\n\tif err == nil { return }\n\tf, _ := os.Create(path)\n\tf.Close()`))).toBe(true);
    expect(has("a.go", go(`\tif _, err := os.Stat(path); err != nil {\n\t\tos.WriteFile(path, []byte("x"), 0644)\n\t}`))).toBe(true);
    expect(has("a.go", go(`\t_, err := os.Stat(path)\n\tif err != nil { return }\n\tdata, _ := os.ReadFile(path)\n\t_ = data`))).toBe(false);
    expect(has("a.go", go(`\t_, err := os.Stat(path)\n\tif err == nil { return }\n\tf, _ := os.Create(other)\n\tf.Close()`))).toBe(false);
    expect(has("a.go", go(`\t_, err := os.Stat(path)\n\tif err == nil { return }\n\tf, _ := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)\n\tf.Close()`))).toBe(false);
    expect(has("a.go", go(`\tmu.Lock()\n\t_, err := os.Stat(path)\n\tif err == nil { return }\n\tos.WriteFile(path, nil, 0644)`))).toBe(false);
    expect(has("a.go", go(`\tif _, err := os.Stat(dir); os.IsNotExist(err) {\n\t\tos.MkdirAll(dir, 0755)\n\t}`))).toBe(false);
  });
  it("Python: exists then open for writing / rename; reading, 'x' mode and tempfile are not", () => {
    expect(has("a.py", `import os\n\ndef save(p, data):\n    if not os.path.exists(p):\n        with open(p, "w") as f:\n            f.write(data)\n`)).toBe(true);
    expect(has("a.py", `import os\n\ndef move(p, q):\n    if os.path.isfile(p):\n        os.rename(p, q)\n`)).toBe(false);   // different path for the second call: p is renamed, q is the target
    expect(has("a.py", `import os\n\ndef fix(p):\n    if os.path.isfile(p):\n        os.chmod(p, 0o777)\n`)).toBe(true);
    expect(has("a.py", `import os\n\ndef load(p):\n    if os.path.exists(p):\n        return open(p, "r").read()\n`)).toBe(false);
    expect(has("a.py", `import os, tempfile\n\ndef save(p, data):\n    if not os.path.exists(p):\n        fd = tempfile.NamedTemporaryFile()\n        open(p, "w").write(data)\n`)).toBe(false);
  });
  it("Ruby, PHP, Java, C# and Rust", () => {
    expect(has("a.rb", `def save(path, data)\n  unless File.exist?(path)\n    File.write(path, data)\n  end\nend\n`)).toBe(true);
    expect(has("a.rb", `def load(path)\n  File.read(path) if File.exist?(path)\nend\n`)).toBe(false);
    expect(has("a.php", `<?php\nfunction save($file, $data) {\n    if (!file_exists($file)) {\n        file_put_contents($file, $data);\n    }\n}\n`)).toBe(true);
    expect(has("a.php", `<?php\nfunction load($file) {\n    if (file_exists($file)) { return file_get_contents($file); }\n}\n`)).toBe(false);
    expect(has("A.java", `class A {\n  void save(Path p, byte[] b) throws Exception {\n    if (!Files.exists(p)) {\n      Files.write(p, b);\n    }\n  }\n}\n`)).toBe(true);
    expect(has("A.java", `class A {\n  void save(Path p, byte[] b) throws Exception {\n    Files.write(p, b, StandardOpenOption.CREATE_NEW);\n  }\n}\n`)).toBe(false);
    expect(has("A.cs", `class A {\n  void Save(string path, string text) {\n    if (!File.Exists(path)) {\n      File.WriteAllText(path, text);\n    }\n  }\n}\n`)).toBe(true);
    expect(has("a.rs", `fn save(path: &str, data: &[u8]) {\n    if !Path::new(path).exists() {\n        fs::write(path, data).unwrap();\n    }\n}\n`)).toBe(true);
    expect(has("a.rs", `fn save(path: &str, data: &[u8]) {\n    let f = OpenOptions::new().write(true).create_new(true).open(path);\n}\n`)).toBe(false);
  });
});
