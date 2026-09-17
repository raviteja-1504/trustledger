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
