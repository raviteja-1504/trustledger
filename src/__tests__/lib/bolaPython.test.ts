import { scanAstTaintPython, parsePythonSourceSync, warmPythonTaintEngine } from "@/lib/astTaintPython";

// Python AST-based BOLA/ownership-dominance detector (bola-missing-ownership-check) -- mirrors
// astTaintPHP.ts's own collectBolaFindings, adapted to Python's binding conventions: a resource id
// is a function PARAMETER matching the naming convention (Flask URL converters and Django path-kwarg
// views both bind the URL segment straight to a parameter, e.g. `def order_detail(request, pk):`),
// with no isEndpoint gate -- same reasoning astTaintPHP.ts's own docblock gives (no annotation
// system as rigid as Spring/ASP.NET to gate on).

beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

function bolaFindings(content: string) {
  const root = parsePythonSourceSync(content, "x.py");
  if (!root) throw new Error("parse failed");
  return scanAstTaintPython(content, "x.py", root).filter(f => f.id === "bola-missing-ownership-check");
}
const fires = (content: string) => bolaFindings(content).length > 0;

describe("recall", () => {
  it("flags a Django get_object_or_404 lookup with no ownership check", () => {
    const code = `def order_detail(request, pk):
    order = get_object_or_404(Order, id=pk)
    return render(request, "order.html", {"order": order})
`;
    expect(fires(code)).toBe(true);
  });

  it("flags at MEDIUM severity for a read-shaped function name", () => {
    const code = `def get_order(request, pk):
    return get_object_or_404(Order, id=pk)
`;
    const f = bolaFindings(code);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].severityOverride).toBe("medium");
  });

  it("flags at HIGH severity for a write-shaped function name", () => {
    const code = `def delete_order(request, order_id):
    Order.objects.filter(id=order_id).delete()
`;
    const f = bolaFindings(code);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].severityOverride).toBe("high");
  });

  it("flags a SQLAlchemy-style filter_by lookup", () => {
    const code = `def get_order(order_id):
    return Order.query.filter_by(id=order_id).first()
`;
    expect(fires(code)).toBe(true);
  });

  it("flags a pymongo-style dict-shaped filter argument", () => {
    const code = `def get_order(request, pk):
    return collection.find_one({"id": pk})
`;
    expect(fires(code)).toBe(true);
  });

  it("flags when a comparison exists but guards an unrelated variable, not the resource id", () => {
    const code = `def get_order(request, pk):
    other = "x"
    if other == request.user.id:
        pass
    return get_object_or_404(Order, id=pk)
`;
    expect(fires(code)).toBe(true);
  });

  it("flags when the ownership check follows the lookup instead of guarding it", () => {
    const code = `def get_order(request, pk):
    order = get_object_or_404(Order, id=pk)
    if pk != request.user.id:
        return HttpResponseForbidden()
    return render(request, "order.html", {"order": order})
`;
    expect(fires(code)).toBe(true);
  });
});

describe("precision", () => {
  it("does not flag a lookup guarded by a matching if-check (narrow polarity)", () => {
    const code = `def get_order(request, pk):
    if pk != request.user.id:
        return HttpResponseForbidden()
    return get_object_or_404(Order, id=pk)
`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag when the comparison operands are reversed (principal == id)", () => {
    const code = `def get_order(request, pk):
    if request.user.id != pk:
        return HttpResponseForbidden()
    return get_object_or_404(Order, id=pk)
`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag when the positive-polarity check wraps the lookup in its true branch", () => {
    const code = `def get_order(request, pk):
    if pk == request.user.id:
        return get_object_or_404(Order, id=pk)
    return HttpResponseForbidden()
`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag a function with no resource-id-shaped parameter", () => {
    const code = `def list_orders(request):
    return Order.objects.filter(status="open")
`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag a non-lookup call even with a resource id in scope", () => {
    const code = `def get_order(request, pk):
    print("looking up", pk)
    return {"ok": True}
`;
    expect(fires(code)).toBe(false);
  });

  it("resolves a one-hop boolean helper variable", () => {
    const code = `def get_order(request, pk):
    is_owner = pk == request.user.id
    if not is_owner:
        return HttpResponseForbidden()
    return get_object_or_404(Order, id=pk)
`;
    expect(fires(code)).toBe(false);
  });

  it("does not flag a lookup whose keyword argument isn't resource-id-shaped", () => {
    const code = `def search(request, term):
    return Product.objects.filter(name=term)
`;
    expect(fires(code)).toBe(false);
  });
});
