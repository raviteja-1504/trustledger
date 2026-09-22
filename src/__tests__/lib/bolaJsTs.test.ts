import { runScan } from "@/lib/scanner";

// JS/TS AST-based BOLA/ownership-dominance detector (bola-missing-ownership-check) -- mirrors
// astTaintJava.ts's/astTaintCSharp.ts's/astTaintPHP.ts's own collectBolaFindings exactly, adapted to
// JS/TS's request-handler shape: a resource id is read from req.params.<name>/req.query.<name>
// (Express/Next.js convention), not a typed method parameter/route-template binding.

function bolaFindings(content: string) {
  const result = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/route.ts", content }] });
  return result.files[0].indicators.filter(i => i.id === "bola-missing-ownership-check");
}
const fires = (content: string) => bolaFindings(content).length > 0;

describe("recall", () => {
  it("flags a lookup by an inline req.params.<id> with no ownership check", () => {
    const code = `app.get("/invoices/:invoiceId", async (req, res) => {
  const invoice = await Invoice.findById(req.params.invoiceId);
  res.json(invoice);
});`;
    expect(fires(code)).toBe(true);
  });

  it("flags a write-verb (delete) lookup with no ownership check at HIGH severity", () => {
    const code = `app.delete("/orders/:orderId", async (req, res) => {
  await Order.deleteOne({ id: req.params.orderId });
  res.status(204).end();
});`;
    const f = bolaFindings(code);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].severity).toBe("high");
  });

  it("flags a GET-verb lookup with no ownership check at MEDIUM severity", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  res.json(order);
});`;
    const f = bolaFindings(code);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].severity).toBe("medium");
  });

  it("flags a where-clause shorthand-property lookup", () => {
    const code = `app.get("/orders/:id", async (req, res) => {
  const id = req.params.id;
  const order = await Order.findOne({ where: { id } });
  res.json(order);
});`;
    expect(fires(code)).toBe(true);
  });

  it("flags when a comparison exists but guards an unrelated variable, not the resource id", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  const other = "x";
  if (other === req.user.id) { console.log("unrelated"); }
  const order = await Order.findById(orderId);
  res.json(order);
});`;
    expect(fires(code)).toBe(true);
  });

  it("flags when the ownership check follows the lookup instead of guarding it", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  const order = await Order.findById(orderId);
  if (orderId !== req.user.id) { return res.status(403).end(); }
  res.json(order);
});`;
    expect(fires(code)).toBe(true);
  });
});

describe("precision", () => {
  it("does not flag a lookup guarded by a matching if-check (narrow polarity)", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  if (orderId !== req.user.id) { return res.status(403).end(); }
  const order = await Order.findById(orderId);
  res.json(order);
});`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag when the comparison operands are reversed (principal === id)", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  if (req.user.id !== orderId) { return res.status(403).end(); }
  const order = await Order.findOne({ where: { id: orderId } });
  res.json(order);
});`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag when the positive-polarity check wraps the lookup in its true branch", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  if (orderId === req.user.id) {
    const order = await Order.findById(orderId);
    res.json(order);
  } else {
    res.status(403).end();
  }
});`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag a plain helper function with no request parameter", () => {
    const code = `function helper(orderId) {
  return Order.findById(orderId);
}`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag a lookup whose argument isn't resource-id-shaped", () => {
    const code = `app.get("/search", async (req, res) => {
  const results = await Product.findOne({ name: req.query.term });
  res.json(results);
});`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag a non-lookup method call even with a resource id in scope", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  console.log("looking up", orderId);
  res.json({ ok: true });
});`;
    expect(fires(code)).toBe(false);
  });

  it("resolves a one-hop boolean helper variable (const isOwner = ...)", () => {
    const code = `app.get("/orders/:orderId", async (req, res) => {
  const orderId = req.params.orderId;
  const isOwner = orderId === req.user.id;
  if (!isOwner) { return res.status(403).end(); }
  const order = await Order.findById(orderId);
  res.json(order);
});`;
    expect(fires(code)).toBe(false);
  });
});
