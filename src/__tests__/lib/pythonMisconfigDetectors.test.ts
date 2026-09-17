import { analyzeFile } from "@/lib/scanner";

describe("Python subprocess command injection via shell=True (found via real-world OWASP-style Flask testing)", () => {
  it("flags a tainted variable built via concatenation, then passed to subprocess with shell=True", () => {
    const content = `
from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    command = "ping -c 1 " + host
    output = subprocess.check_output(command, shell=True)
    return output.decode(errors="ignore")
`;
    const result = analyzeFile("app.py", content);
    const finding = result.indicators.find(i => i.id === "command-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(finding?.detail).toContain("command");
  });

  it("does not flag subprocess without shell=True", () => {
    const content = `
import subprocess
from flask import request

def ping():
    host = request.args.get("host", "")
    output = subprocess.check_output(["ping", "-c", "1", host])
    return output
`;
    const result = analyzeFile("app.py", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(false);
  });
});

describe("Python named-taint SSRF via requests library (found via real-world OWASP-style Flask testing)", () => {
  it("flags a request-args-derived variable passed to requests.get()", () => {
    const content = `
from flask import Flask, request
import requests
app = Flask(__name__)

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    response = requests.get(url, timeout=10)
    return response.text
`;
    const result = analyzeFile("app.py", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });
});

describe("Debug mode enabled (found via real-world OWASP-style Flask testing)", () => {
  it("flags app.config['DEBUG'] = True", () => {
    const content = `
from flask import Flask
app = Flask(__name__)
app.config["DEBUG"] = True
`;
    const result = analyzeFile("app.py", content);
    const finding = result.indicators.find(i => i.id === "debug-mode-enabled");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("flags app.run(debug=True)", () => {
    const content = `
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
`;
    const result = analyzeFile("app.py", content);
    expect(result.indicators.some(i => i.id === "debug-mode-enabled")).toBe(true);
  });

  it("does not flag debug=False", () => {
    const content = `
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
`;
    const result = analyzeFile("app.py", content);
    expect(result.indicators.some(i => i.id === "debug-mode-enabled")).toBe(false);
  });
});

describe("Python-style CORS wildcard via dict-bracket header assignment (found via real-world OWASP-style Flask testing)", () => {
  it("flags response.headers dict-bracket assignment to a wildcard origin", () => {
    const content = `
@app.after_request
def insecure_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response
`;
    const result = analyzeFile("app.py", content);
    expect(result.indicators.some(i => i.id === "weak-cors")).toBe(true);
  });
});
