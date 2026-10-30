/**
 * The live demo's sample applications: each a small, deliberately vulnerable program and its corrected version.
 * The demo page shows them, and /api/demo/scan runs the real scanner on them (or on a visitor's edit of them).
 * src/__tests__/lib/demoScan.test.ts pins what the engine reports for every sample, so the demo can never quietly
 * show a finding the engine no longer produces.
 */

export interface DemoFile {
  path: string;
  vulnerable: string;
  fixed: string;
}

export interface DemoSample {
  id: string;
  title: string;
  /** The rule the vulnerable version should trigger (and the fixed version must not). */
  expectRule: string;
  cwe: string;
  language: string;
  summary: string;
  fixNote: string;
  files: DemoFile[];
}

export const DEMO_SAMPLES: DemoSample[] = [
  {
    id: "sqli-ts",
    title: "SQL injection across two files",
    expectRule: "sql-injection",
    cwe: "CWE-89",
    language: "TypeScript (Express)",
    summary: "A route reads an email from the query string and passes it to a repository function in another file, which builds the SQL by string concatenation.",
    fixNote: "The repository uses a parameterised query: the email is sent as a bound value, never spliced into the SQL text.",
    files: [
      {
        path: "src/routes/users.ts",
        vulnerable: `import express from "express";
import { findUserByEmail } from "../db/users";

const router = express.Router();

router.get("/users/search", async (req, res) => {
  const email = String(req.query.email ?? "");
  const user = await findUserByEmail(email);
  res.json(user ?? { error: "not found" });
});

export default router;
`,
        fixed: `import express from "express";
import { findUserByEmail } from "../db/users";

const router = express.Router();

router.get("/users/search", async (req, res) => {
  const email = String(req.query.email ?? "");
  const user = await findUserByEmail(email);
  res.json(user ?? { error: "not found" });
});

export default router;
`,
      },
      {
        path: "src/db/users.ts",
        vulnerable: `import { pool } from "./pool";

export async function findUserByEmail(email: string) {
  const sql = "SELECT id, name, email FROM users WHERE email = '" + email + "'";
  const result = await pool.query(sql);
  return result.rows[0];
}
`,
        fixed: `import { pool } from "./pool";

export async function findUserByEmail(email: string) {
  const result = await pool.query("SELECT id, name, email FROM users WHERE email = $1", [email]);
  return result.rows[0];
}
`,
      },
    ],
  },
  {
    id: "xss-py",
    title: "Reflected XSS in a Flask view",
    expectRule: "xss",
    cwe: "CWE-79",
    language: "Python (Flask)",
    summary: "A search page echoes the query parameter back into HTML without escaping it.",
    fixNote: "The value is HTML-escaped with markupsafe.escape before it is placed in the page.",
    files: [
      {
        path: "app/views.py",
        vulnerable: `from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    html = "<h1>Results for " + term + "</h1>"
    return make_response(html)
`,
        fixed: `from flask import Flask, request, make_response
from markupsafe import escape

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    html = "<h1>Results for " + str(escape(term)) + "</h1>"
    return make_response(html)
`,
      },
    ],
  },
  {
    id: "cmdi-go",
    title: "Command injection through a shell",
    expectRule: "command-injection",
    cwe: "CWE-78",
    language: "Go (net/http)",
    summary: "A diagnostics handler builds a shell command line from a query parameter and runs it with sh -c.",
    fixNote: "The host is checked against an anchored allow-list pattern and passed to ping as its own argument, with no shell in between.",
    files: [
      {
        path: "internal/diag/ping.go",
        vulnerable: `package diag

import (
	"net/http"
	"os/exec"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
	if err != nil {
		http.Error(w, "ping failed", http.StatusBadGateway)
		return
	}
	w.Write(out)
}
`,
        fixed: `package diag

import (
	"net/http"
	"os/exec"
	"regexp"
)

var hostPattern = regexp.MustCompile(\`^[a-zA-Z0-9.-]+$\`)

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !hostPattern.MatchString(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("ping", "-c", "1", "--", host).CombinedOutput()
	if err != nil {
		http.Error(w, "ping failed", http.StatusBadGateway)
		return
	}
	w.Write(out)
}
`,
      },
    ],
  },
  {
    id: "deser-java",
    title: "Unsafe deserialization of a request body",
    expectRule: "insecure-deserialization",
    cwe: "CWE-502",
    language: "Java (Servlet)",
    summary: "An import endpoint turns the raw request body into Java objects with ObjectInputStream, which runs code chosen by whoever crafted the bytes.",
    fixNote: "The body is parsed as JSON into a plain data class; no class named by the input is ever instantiated.",
    files: [
      {
        path: "src/main/java/app/ImportServlet.java",
        vulnerable: `package app;

import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ImportServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        try {
            Object order = in.readObject();
            response.getWriter().println("imported " + order.getClass().getSimpleName());
        } catch (ClassNotFoundException e) {
            response.sendError(400);
        }
    }
}
`,
        fixed: `package app;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ImportServlet extends HttpServlet {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Order order = MAPPER.readValue(request.getInputStream(), Order.class);
        response.getWriter().println("imported order " + order.id);
    }

    static class Order {
        public long id;
        public String sku;
    }
}
`,
      },
    ],
  },
];

export const DEMO_LIMITS = { maxFiles: 4, maxFileBytes: 16 * 1024 } as const;

export function demoSample(id: string): DemoSample | undefined {
  return DEMO_SAMPLES.find(s => s.id === id);
}
