import { analyzeFile } from "@/lib/scanner";

describe("named-taint detector fixes (found via real-world OWASP NodeGoat testing)", () => {
  it("flags SSRF when a method-chained HTTP client (needle.get) receives a tainted variable", () => {
    const content = `
const needle = require("needle");

function ResearchHandler(db) {
  this.displayResearch = (req, res) => {
    if (req.query.symbol) {
      const url = req.query.url + req.query.symbol;
      return needle.get(url, (error, response, body) => {
        res.write(body);
        return res.end();
      });
    }
    return res.render("research", {});
  };
}

module.exports = ResearchHandler;
`;
    const result = analyzeFile("routes/research.js", content);
    const ssrf = result.indicators.find(i => i.id === "ssrf");
    expect(ssrf).toBeDefined();
    expect(ssrf?.severity).toBe("critical");
  });

  it("flags SSRF when superagent.post receives a tainted variable", () => {
    const content = `
const superagent = require("superagent");

function handler(req, res) {
  const target = req.body.callbackUrl;
  superagent.post(target).send({ ok: true }).end((err, resp) => {
    res.json(resp.body);
  });
}

module.exports = handler;
`;
    const result = analyzeFile("routes/callback.js", content);
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(true);
  });

  it("flags IDOR when a Prettier-style multi-line destructured field flows into a DAO update with no ownership check", () => {
    const content = `
const { BenefitsDAO } = require("../data/benefits-dao");

function BenefitsHandler(db) {
  const benefitsDAO = new BenefitsDAO(db);

  this.updateBenefits = (req, res, next) => {
    const {
      userId,
      benefitStartDate
    } = req.body;

    benefitsDAO.updateBenefits(userId, benefitStartDate, (error) => {
      if (error) return next(error);
      return res.render("benefits", {});
    });
  };
}

module.exports = BenefitsHandler;
`;
    const result = analyzeFile("routes/benefits.js", content);
    const idor = result.indicators.find(i => i.id === "idor");
    expect(idor).toBeDefined();
    expect(idor?.severity).toBe("medium");
    expect(idor?.detail).toContain("userId");
  });

  it("does not flag IDOR when an ownership check guards the same lookup", () => {
    const content = `
const { OrderDAO } = require("../data/order-dao");

function OrderHandler(db) {
  const orderDAO = new OrderDAO(db);

  this.getOrder = (req, res, next) => {
    const {
      orderId
    } = req.params;

    if (!req.user || !isOwner(req.user, orderId)) {
      return res.status(403).end();
    }

    orderDAO.getOrderById(orderId, (error, order) => {
      if (error) return next(error);
      return res.json(order);
    });
  };
}

module.exports = OrderHandler;
`;
    const result = analyzeFile("routes/order.js", content);
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });

  it("resolves a multi-line destructured request field for XSS taint tracking too", () => {
    const content = `
function render(req) {
  const {
    comment,
    author
  } = req.body;

  document.getElementById("out").innerHTML = comment;
  return author;
}

module.exports = render;
`;
    const result = analyzeFile("views/comment.js", content);
    expect(result.indicators.some(i => i.id === "xss")).toBe(true);
  });
});

describe("XXE via JS XML libraries (found via real-world OWASP Juice Shop testing)", () => {
  it("flags XXE when a libxml2-based parser is called with entity-expansion/DTD-loading options enabled", () => {
    const content = `
import libxml2 from "libxml2-wasm";

export async function parseXmlString(data) {
  const option = libxml2.ParseOption.XML_PARSE_NOENT | libxml2.ParseOption.XML_PARSE_DTDLOAD;
  const xmlDoc = libxml2.XmlDocument.fromString(data, { option });
  const xmlString = xmlDoc.toString();
  xmlDoc.dispose();
  return xmlString;
}
`;
    const result = analyzeFile("lib/xml.ts", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(true);
  });

  it("flags XXE when libxmljs is called with noent/dtdload options set to true", () => {
    const content = `
const libxmljs = require("libxmljs");

function parse(data) {
  return libxmljs.parseXml(data, { noent: true, dtdload: true });
}

module.exports = parse;
`;
    const result = analyzeFile("lib/parse.js", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(true);
  });

  it("does not flag a safe XML parse with no entity-expansion options", () => {
    const content = `
const libxmljs = require("libxmljs");

function parse(data) {
  return libxmljs.parseXml(data);
}

module.exports = parse;
`;
    const result = analyzeFile("lib/parse.js", content);
    expect(result.indicators.some(i => i.id === "xxe")).toBe(false);
  });
});

describe("Zip Slip via archive entry names (found via real-world OWASP WebGoat testing)", () => {
  it("flags a File joined from a ZipEntry name with no canonicalization/containment check", () => {
    const content = `
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ProfileZipSlip {
  private AttackResult processZipUpload(MultipartFile file, String username) {
    ZipFile zip = new ZipFile(uploadedZipFile.toFile());
    Enumeration<? extends ZipEntry> entries = zip.entries();
    while (entries.hasMoreElements()) {
      ZipEntry e = entries.nextElement();
      File f = new File(tmpZipDirectory.toFile(), e.getName());
      InputStream is = zip.getInputStream(e);
      Files.copy(is, f.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }
    return isSolved();
  }
}
`;
    const result = analyzeFile("ProfileZipSlip.java", content);
    const finding = result.indicators.find(i => i.id === "path-traversal" && i.label?.includes("Zip Slip"));
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });

  it("does not flag zip extraction that validates the resolved path stays within the target directory", () => {
    const content = `
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SafeZipExtract {
  private void extract(ZipFile zip, File targetDir) throws IOException {
    Enumeration<? extends ZipEntry> entries = zip.entries();
    while (entries.hasMoreElements()) {
      ZipEntry e = entries.nextElement();
      File f = new File(targetDir, e.getName());
      if (!f.getCanonicalPath().startsWith(targetDir.getCanonicalPath())) {
        throw new IOException("Entry is outside of the target dir: " + e.getName());
      }
      Files.copy(zip.getInputStream(e), f.toPath());
    }
  }
}
`;
    const result = analyzeFile("SafeZipExtract.java", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(false);
  });

  it("does not flag an ordinary File(dir, name) join with no zip-extraction context nearby", () => {
    const content = `
public class ProfileImage {
  public void saveCopy(File sourceFile, File destDir) throws IOException {
    File copy = new File(destDir, sourceFile.getName());
    Files.copy(sourceFile.toPath(), copy.toPath());
  }
}
`;
    const result = analyzeFile("ProfileImage.java", content);
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(false);
  });
});
