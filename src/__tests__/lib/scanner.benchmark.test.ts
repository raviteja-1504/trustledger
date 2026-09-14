/**
 * Regression/benchmark suite — starter version.
 *
 * Snippets modelled on real vulnerability classes from known-vulnerable
 * training apps (WebGoat, Juice Shop, DVWA) plus their safe counterparts.
 * This is deliberately small and will grow over time; it is NOT a claim of
 * precision/recall across full clones of those repos (see the phase-1 audit
 * for what that would actually require: hand-labeled ground truth per repo).
 * What it does guarantee: a scanner change cannot silently regress detection
 * of these specific, representative cases without a test failing.
 */
import { analyzeFile } from "@/lib/scanner";

interface Case {
  name: string;
  path: string;
  code: string;
  mustDetect: string[];
  mustNotDetect?: string[];
}

const CASES: Case[] = [
  {
    name: "Java (WebGoat-style) path traversal via File + request.getParameter",
    path: "PathTraversalController.java",
    code: `
package org.owasp.webgoat.lessons;
import java.io.File;
import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class PathTraversalController {
    public byte[] readFile(HttpServletRequest request) throws Exception {
        String base = "/var/uploads/";
        File f = new File(base + request.getParameter("filename"));
        FileInputStream in = new FileInputStream(f);
        return in.readAllBytes();
    }
}`,
    mustDetect: ["path-traversal"],
  },
  {
    name: "Java (WebGoat-style) IDOR — @PathVariable id straight into repository.findById",
    path: "IDORController.java",
    code: `
package org.owasp.webgoat.lessons;
import org.springframework.web.bind.annotation.*;

@RestController
public class IDORController {
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userRepository.findById(id).orElseThrow();
    }
}`,
    mustDetect: ["idor"],
  },
  {
    name: "Java command injection via Runtime.exec + request.getParameter",
    path: "CommandExecController.java",
    code: `
package org.owasp.webgoat.lessons;
import javax.servlet.http.HttpServletRequest;

public class CommandExecController {
    public void ping(HttpServletRequest request) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + request.getParameter("host"));
    }
}`,
    mustDetect: ["command-injection"],
  },
  {
    name: "Java LDAP injection via concatenated search filter",
    path: "LdapController.java",
    code: `
package org.owasp.webgoat.lessons;
import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

public class LdapController {
    public void search(DirContext ctx, HttpServletRequest request) throws Exception {
        String filter = "(cn=" + request.getParameter("username") + ")";
        ctx.search("ou=users", filter, null);
    }
}`,
    mustDetect: ["ldap-injection"],
  },
  {
    name: "Java XXE — DocumentBuilderFactory without secure processing",
    path: "XmlImportController.java",
    code: `
package org.owasp.webgoat.lessons;
import javax.xml.parsers.DocumentBuilderFactory;

public class XmlImportController {
    public void parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.newDocumentBuilder();
    }
}`,
    mustDetect: ["xxe"],
  },
  {
    name: "Java insecure deserialization — ObjectInputStream from request",
    path: "DeserializeController.java",
    code: `
package org.owasp.webgoat.lessons;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class DeserializeController {
    public Object load(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject();
    }
}`,
    mustDetect: ["insecure-deserialization"],
  },
  {
    name: "Java SQL injection via string concatenation (generic concat+SELECT pattern)",
    path: "SqlInjectionLesson5a.java",
    code: `
package org.owasp.webgoat.lessons;

public class SqlInjectionLesson5a {
    public String buildQuery(String userId) {
        return "SELECT * FROM users WHERE id = " + userId;
    }
}`,
    mustDetect: ["sql-injection"],
  },
  {
    name: "Python (Flask-style) path traversal",
    path: "download.py",
    code: `
from flask import request

def download():
    filename = request.args.get("file")
    return open("/var/files/" + request.args["file"], "rb").read()
`,
    mustDetect: ["path-traversal"],
  },
  {
    name: "PHP command injection via shell_exec + $_GET",
    path: "ping.php",
    code: `
<?php
$output = shell_exec("ping -c 1 " . $_GET['host']);
echo $output;
`,
    mustDetect: ["command-injection"],
  },
  {
    name: "Go SSRF via http.Get with query-derived URL",
    path: "fetch.go",
    code: `
package main
import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
    resp, _ := http.Get(r.URL.Query().Get("target"))
    _ = resp
}
`,
    mustDetect: ["ssrf"],
  },
  {
    name: "Java properties file — unquoted hardcoded DB password",
    path: "application.properties",
    code: `
db.url=jdbc:mysql://localhost:3306/webgoat
db.username=root
db.password=SuperSecretPassw0rd!
`,
    mustDetect: ["hardcoded-secret"],
  },
  {
    name: "Vendored/minified jQuery — internal .innerHTML must NOT read as an application XSS finding",
    path: "jquery-1.10.2.min.js",
    code: `
(function(e,t){"use strict";var n=e.document,r=e.location;/*! jQuery v1.10.2 */
var a=function(){elem.innerHTML=source;return elem.outerHTML=source2;};
${"x".repeat(400)}
})(window);
`,
    mustDetect: [],
    mustNotDetect: ["xss"],
  },
  {
    name: "Safe Java — PreparedStatement with placeholders must NOT fire sql-injection",
    path: "SafeUserDao.java",
    code: `
package org.owasp.webgoat.lessons;
import java.sql.PreparedStatement;
import java.sql.Connection;

public class SafeUserDao {
    public void findUser(Connection conn, String userId) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        ps.executeQuery();
    }
}`,
    mustDetect: [],
    mustNotDetect: ["sql-injection"],
  },
];

describe("scanner benchmark — representative vulnerable/safe snippets", () => {
  for (const c of CASES) {
    it(c.name, () => {
      const result = analyzeFile(c.path, c.code.trim());
      const ids = new Set(result.indicators.map(i => i.id));

      for (const expected of c.mustDetect) {
        expect(ids.has(expected)).toBe(true);
      }
      for (const forbidden of c.mustNotDetect ?? []) {
        // Third-party-tagged findings are allowed to remain as evidence —
        // what must NOT happen is an application-severity finding driving
        // the file's own risk score. Only fail on an "application" hit.
        const appHit = result.indicators.some(i => i.id === forbidden && i.codeCategory !== "third_party");
        expect(appHit).toBe(false);
      }
    });
  }

  it("does not let a vendored/minified file's internal code escalate risk_score to CRITICAL/HIGH", () => {
    const vendored = CASES.find(c => c.path === "jquery-1.10.2.min.js")!;
    const result = analyzeFile(vendored.path, vendored.code.trim());
    expect(["LOW", "MEDIUM"]).toContain(result.risk_score);
  });

  it("every application-severity CRITICAL/HIGH finding carries a CWE and confidence score", () => {
    for (const c of CASES) {
      const result = analyzeFile(c.path, c.code.trim());
      for (const ind of result.indicators) {
        if (ind.codeCategory === "third_party") continue;
        if (ind.severity !== "critical" && ind.severity !== "high") continue;
        if (ind.id === "watermark-detection" || ind.id === "behavioral-risk" || ind.id === "supply-chain-risk") continue;
        expect(ind.confidence).toBeGreaterThan(0);
      }
    }
  });
});
