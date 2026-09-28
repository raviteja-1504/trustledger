import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

// BOLA as authorization STATE, Python engine: ownership (proven) vs role (real control, object still unproven) vs nothing.

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

const scan = (content: string) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "shop/views.py", content }] });
const bola = (content: string) => scan(content).files[0].indicators.filter(i => i.id === "bola-missing-ownership-check");
// `deco` is a decorator line(s) placed above the view; `body` is indented into it
const view = (body: string, deco = "", name = "get_order") =>
  [deco, `def ${name}(request, pk):`, ...body.split("\n").map(l => "    " + l), ""].filter(l => l !== "").join("\n") + "\n";

describe("unchecked lookup (baseline)", () => {
  it("is reported", () => {
    expect(bola(view("order = get_object_or_404(Order, pk=pk)\nreturn render(request, 't.html', {'o': order})"))).toHaveLength(1);
  });
  it("authentication alone is not authorization", () => {
    expect(bola(view("order = get_object_or_404(Order, pk=pk)\nreturn render(request, 't.html', {'o': order})", "@login_required"))).toHaveLength(1);
  });
});

describe("ownership IN the query is protection", () => {
  it.each([
    ["get_object_or_404 with owner kwarg", "order = get_object_or_404(Order, pk=pk, user=request.user)"],
    ["Django manager .get with owner", "order = Order.objects.get(pk=pk, owner=request.user)"],
    ["double-underscore relation", "order = Order.objects.get(pk=pk, user__id=request.user.id)"],
    ["chained filter then get", "order = Order.objects.filter(user=request.user).get(pk=pk)"],
    ["related manager off the principal", "order = request.user.orders.get(pk=pk)"],
    ["principal alias", "user = request.user\norder = Order.objects.get(pk=pk, user=user)"],
    ["SQLAlchemy filter_by + current_user", "order = Order.query.filter_by(id=pk, user_id=current_user.id).first()"],
    ["SQLAlchemy comparison expression", "order = Order.query.filter(Order.id == pk, Order.user_id == current_user.id).first()"],
    ["pymongo dict", "order = db.orders.find_one({'_id': pk, 'owner': request.user.id})"],
    ["mutating lookup scoped by owner", "db.orders.delete_one({'_id': pk, 'owner': request.user.id})"],
  ])("%s -> no finding", (_n, body) => {
    expect(bola(view(body))).toHaveLength(0);
  });

  it.each([
    ["owner kwarg compared to something else", "order = Order.objects.get(pk=pk, user=other_user)"],
    ["principal under a non-owner key", "order = Order.objects.get(pk=pk, status=request.user.status)"],
    ["a different chain is not the principal's", "order = Order.objects.get(pk=pk)"],
    ["name that only STARTS like the principal", "order = current_user_orders.get(pk=pk)"],
  ])("%s -> still reported", (_n, body) => {
    expect(bola(view(body))).toHaveLength(1);
  });
});

describe("ownership checked on the LOADED record", () => {
  const load = "order = get_object_or_404(Order, pk=pk)\n";
  it.each([
    ["!= then raise", load + "if order.user != request.user:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"],
    ["!= then return 403", load + "if order.owner_id != request.user.id:\n    return HttpResponseForbidden()\nreturn render(request, 't.html', {'o': order})"],
    ["nested owner id", load + "if order.user.id != request.user.id:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"],
    ["Flask abort(403)", load + "if order.user_id != current_user.id:\n    abort(403)\nreturn render_template('t.html', o=order)"],
    ["== with else terminating", load + "if order.user == request.user:\n    return render(request, 't.html', {'o': order})\nelse:\n    raise PermissionDenied"],
    ["not (==)", load + "if not order.user == request.user:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"],
    ["a 404 guard first", "order = Order.objects.filter(pk=pk).first()\nif order is None:\n    raise Http404\nif order.user != request.user:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"],
  ])("%s -> protected", (_n, body) => {
    expect(bola(view(body))).toHaveLength(0);
  });

  it("a check that does NOT leave on failure protects nothing", () => {
    expect(bola(view(load + "if order.user != request.user:\n    print('not owner')\nreturn render(request, 't.html', {'o': order})"))).toHaveLength(1);
  });
  it("a check on a different field is not ownership", () => {
    expect(bola(view(load + "if order.status != request.user.id:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"))).toHaveLength(1);
  });
  it("a check of some OTHER record does not protect this one", () => {
    expect(bola(view(load + "other = Other.objects.first()\nif other.user != request.user:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"))).toHaveLength(1);
  });
  it("a check AFTER a lookup that mutates as it fetches is too late", () => {
    const body = "order = db.orders.find_one_and_update({'_id': pk}, {'$set': {'t': 1}})\nif order.owner != request.user.id:\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})";
    expect(bola(view(body))).toHaveLength(1);
  });
});

describe("decorators and guard clauses", () => {
  const body = "order = get_object_or_404(Order, pk=pk)\nreturn render(request, 't.html', {'o': order})";
  it("an ownership decorator is protection", () => {
    expect(bola(view(body, "@owner_required"))).toHaveLength(0);
    expect(bola(view(body, "@permission_classes([IsOwner])"))).toHaveLength(0);
  });
  it("a role decorator is role-only", () => {
    const f = bola(view(body, "@permission_required('shop.view_order')"));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].detail).toMatch(/decorator 'permission_required'/);
  });
  it("DRF permission_classes with only IsAuthenticated is authentication, not authorization", () => {
    const f = bola(view(body, "@permission_classes([IsAuthenticated])"));
    expect(f).toHaveLength(1);
    expect(f[0].detail).not.toMatch(/role\/permission check/);
  });
  it("an object-level guard call handed the object is ownership", () => {
    expect(bola(view("order = get_object_or_404(Order, pk=pk)\nif not can_access(request.user, order):\n    raise PermissionDenied\nreturn render(request, 't.html', {'o': order})"))).toHaveLength(0);
    expect(bola(view("if not request.user.has_perm('shop.view_order', pk):\n    raise PermissionDenied\norder = get_object_or_404(Order, pk=pk)\nreturn render(request, 't.html', {'o': order})"))).toHaveLength(0);
  });
  it("a role gate in the body still reports, downgraded, and says why", () => {
    const f = bola(view("if not request.user.is_staff:\n    raise PermissionDenied\norder = get_object_or_404(Order, pk=pk)\nreturn render(request, 't.html', {'o': order})"));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].detail).toMatch(/role\/permission check/);
    expect(f[0].detail).toMatch(/owns THIS object/);
  });
  it("a WRITE view is capped at medium when role-gated, but high when nothing guards it", () => {
    // the view loads by pk, then deletes: a write endpoint by name
    const w = (deco: string) => view("order = Order.objects.get(pk=pk)\norder.delete()\nreturn HttpResponse(status=204)", deco, "delete_order");
    expect(bola(w(""))[0].severity).toBe("high");
    expect(bola(w("@staff_member_required"))[0].severity).toBe("medium");
  });
  it("a role gate PLUS ownership in the query is proven", () => {
    expect(bola(view("order = get_object_or_404(Order, pk=pk, user=request.user)", "@permission_required('shop.view_order')"))).toHaveLength(0);
  });
  it("a role condition that does not leave on failure is not a gate", () => {
    const f = bola(view("if not request.user.is_staff:\n    print('x')\norder = get_object_or_404(Order, pk=pk)\nreturn render(request, 't.html', {'o': order})"));
    expect(f).toHaveLength(1);
    expect(f[0].detail).not.toMatch(/role\/permission check/);
  });
});

describe("existing id-vs-principal comparison still protects", () => {
  it("guard clause", () => {
    const body = "if pk != request.user.id:\n    return HttpResponseForbidden()\norder = get_object_or_404(Order, pk=pk)";
    expect(bola(view(body))).toHaveLength(0);
  });
});

describe("principal injected by an authentication decorator", () => {
  const check = "order = Order.objects.get(id=pk)\nif user != order.user:\n    return HttpResponseForbidden()\nreturn JsonResponse({'o': order.id})";
  const viewWithUser = (body: string, deco: string) =>
    [deco, "def get_order(request, pk, user=None):", ...body.split("\n").map(l => "    " + l), ""].filter(l => l !== "").join("\n") + "\n";
  it("`user` is the principal under @jwt_auth_required / @login_required", () => {
    expect(bola(viewWithUser(check, "@jwt_auth_required"))).toHaveLength(0);
    expect(bola(viewWithUser(check, "@login_required"))).toHaveLength(0);
  });
  it("without an authentication decorator `user` is just a parameter", () => {
    expect(bola(viewWithUser(check, ""))).toHaveLength(1);
    expect(bola(viewWithUser(check, "@app.route('/o/<pk>')"))).toHaveLength(1);
  });
  it("a differently named parameter is not the principal", () => {
    const other = ["@jwt_auth_required", "def get_order(request, pk, account=None):", "    order = Order.objects.get(id=pk)", "    if account != order.user:", "        return HttpResponseForbidden()", "    return JsonResponse({})", ""].join("\n");
    expect(bola(other)).toHaveLength(1);
  });
  it("an id-vs-`user` comparison still needs the principal to be the injected one", () => {
    expect(bola(viewWithUser("if pk != user.id:\n    return HttpResponseForbidden()\norder = Order.objects.get(id=pk)", "@jwt_auth_required"))).toHaveLength(0);
  });
});
