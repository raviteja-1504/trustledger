import { analyzeFile } from "@/lib/scanner";

describe("hardcoded JWT/session signing secret (found via real-world VAmPI testing)", () => {
  it("flags a Flask app.config dict-key assignment to a literal, regardless of how weak the value looks", () => {
    const content = `
import connexion
vuln_app = connexion.App(__name__)
vuln_app.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
vuln_app.app.config['SECRET_KEY'] = 'random'
db = SQLAlchemy(vuln_app.app)
`;
    const result = analyzeFile("config.py", content);
    const finding = result.indicators.find(i => i.id === "weak-signing-secret");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(result.risk_score).toBe("CRITICAL");
  });

  it("flags Flask's app.secret_key attribute form", () => {
    const content = `
from flask import Flask
app = Flask(__name__)
app.secret_key = "supersecretkey12345"
`;
    const result = analyzeFile("app.py", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(true);
  });

  it("flags a Django-style bare SECRET_KEY module constant", () => {
    const content = `
DEBUG = True
ALLOWED_HOSTS = []
SECRET_KEY = 'django-insecure-abc123xyz789'
INSTALLED_APPS = []
`;
    const result = analyzeFile("settings.py", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(true);
  });

  it("flags a literal secret passed directly to jsonwebtoken's sign()", () => {
    const content = `
const jwt = require("jsonwebtoken");
function issueToken(user) {
  return jwt.sign({ sub: user.id }, "hardcoded-dev-secret", { expiresIn: "1h" });
}
module.exports = issueToken;
`;
    const result = analyzeFile("auth/tokens.js", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(true);
  });

  it("does not flag a signing key loaded from an environment variable", () => {
    const content = `
import os
from flask import Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
`;
    const result = analyzeFile("config.py", content);
    expect(result.indicators.some(i => i.id === "weak-signing-secret")).toBe(false);
  });
});
