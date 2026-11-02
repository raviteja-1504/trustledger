/**
 * Advanced interprocedural taint suite: one single-file program per case, each moving request input to a sink
 * through a hard propagation mechanism (middleware state, event dispatch, promises, closures, collections, virtual
 * dispatch, decorators, generators, channels, function values, session state, executors...). The programs are
 * in fixtures/ exactly as given; the expectations name the source, the sink and the meaningful intermediate steps
 * by a snippet of their line (the first line containing it), so they read like the code.
 *
 * Scored by runInterprocedural.ts. Each case also has a safe twin -- the source replaced by a constant -- that
 * must produce no data-flow finding: a propagation rule that invents taint shows up there.
 */
export interface InterproceduralCase {
  id: string;
  language: "javascript" | "python" | "go" | "java";
  /** The name the file is scanned under (Java: the public class's file). */
  path: string;
  /** Finding ids that report this weakness. */
  ids: string[];
  source: string;
  sink: string;
  /** Lines the trace must pass through, besides the source and sink. */
  steps: string[];
  /** What the safe twin puts where the source was. */
  constant: string;
}

const JS = (id: string, ids: string[], source: string, sink: string, steps: string[]): InterproceduralCase =>
  ({ id, language: "javascript", path: `${id.toLowerCase()}.js`, ids, source, sink, steps, constant: `"fixed"` });
const PY = (id: string, ids: string[], source: string, sink: string, steps: string[]): InterproceduralCase =>
  ({ id, language: "python", path: `${id.toLowerCase().replace("-", "_")}.py`, ids, source, sink, steps, constant: `"fixed"` });
const GO = (id: string, ids: string[], source: string, sink: string, steps: string[]): InterproceduralCase =>
  ({ id, language: "go", path: `${id.toLowerCase().replace("-", "_")}.go`, ids, source, sink, steps, constant: `"fixed"` });
const JAVA = (id: string, path: string, ids: string[], source: string, sink: string, steps: string[], constant = `"fixed"`): InterproceduralCase =>
  ({ id, language: "java", path, ids, source, sink, steps, constant });

export const INTERPROCEDURAL_CASES: InterproceduralCase[] = [
  JS("JS-01", ["xss"], "req.query.term", `res.type("html").send(html)`, ["const model = {", "return `<h1>", "const html = render(model)"]),
  JS("JS-02", ["command-injection"], "req.query.command", "exec(command)", ["return { command: value }", `bus.emit("job", job)`, `return "echo " + job.command`]),
  JS("JS-03", ["command-injection"], "req.query.arg", "exec(command)", ["const raw = await load(req)", "const alias = value", `return "echo " + alias`, "const command = await prepare(raw)"]),
  JS("JS-04", ["path-traversal"], "req.query.path", "fs.writeFileSync(path", ["const captured = userPath", "callback(captured)"]),
  JS("JS-05", ["ssrf"], "req.query.url", "return axios.get(url)", ["targets.set(k, v)", "return targets.get(k)", "const target = recall", "await fetchTarget(target)"]),
  JS("JS-06", ["xss"], "req.query.message", `res.type("html").send(output)`, ["const output = renderer.render()", "return `<div>${super.render()}", "return this.value"]),

  PY("PY-01", ["ssrf"], `request.args.get("url")`, "requests.get(target", ["STATE[key] = value", "return STATE.get(key)", `target = load("target")`, "return self.send(target)"]),
  PY("PY-02", ["eval-exec"], `request.args.get("expression")`, "eval(self.expression)", ["return func(self"]),
  PY("PY-03", ["command-injection"], `request.args.get("cmd")`, "subprocess.run(command", ["yield value", "for item in values", `command = "echo " + item`]),
  PY("PY-04", ["path-traversal"], `request.args.get("path")`, "open(path", [`self.metadata = {"files": [path]}`, `files = model.metadata["files"]`, "selected = files[0]", "path = select_file(model)"]),
  PY("PY-05", ["ssrf"], `request.args.get("url")`, "asyncio.to_thread(requests.get, target", ["asyncio.run(run_job(target))", "asyncio.create_task(fetch_url(target))"]),
  PY("PY-06", ["xss"], `request.args.get("name")`, "Response(html", ["intermediate = value", "return callback(intermediate)", `return "<h1>" + value`]),

  GO("GO-01", ["path-traversal"], `r.URL.Query().Get("path")`, "os.WriteFile(job.Path", ["job := makeJob(path)", "jobs <- job", "for job := range jobs"]),
  GO("GO-02", ["ssrf"], `r.URL.Query().Get("url")`, "http.Get(target)", ["_ = execute(fetcher, target)", "return f.Fetch(target)"]),
  GO("GO-03", ["command-injection"], `r.URL.Query().Get("cmd")`, `exec.Command("sh", "-c", command)`, ["runLater(command)"]),
  GO("GO-04", ["path-traversal"], `r.URL.Query().Get("name")`, "os.Create(destination)", [`_ = extract("/tmp/unpack", name)`, `selected := entries["entry"]`, "destination := filepath.Join(root, selected)"]),
  GO("GO-05", ["path-traversal"], `r.URL.Query().Get("path")`, "os.WriteFile(path", ["_ = dispatch(path, save)", "return writer(path)"]),

  JAVA("JAVA-01", "SessionPathServlet.java", ["path-traversal"], `req.getParameter("file")`, "new FileInputStream(path)", [`session.setAttribute("selected", path)`, `session.getAttribute("selected")`, "new FileService().read(saved)", "return new FileHandler().read(path)"]),
  JAVA("JAVA-02", "AsyncDeserializeServlet.java", ["insecure-deserialization"], "req.getInputStream().readAllBytes()", "in.readObject()", ["try { process(payload); }", "deserialize(bytes)"], "new byte[0]"),
  JAVA("JAVA-03", "RedirectServlet.java", ["open-redirect"], `req.getParameter("next")`, "response.sendRedirect(target)", ["redirector.redirect(res, target)"]),
  JAVA("JAVA-04", "CommandServlet.java", ["command-injection"], `req.getParameter("value")`, "new ProcessBuilder(", ["values.add(input)", "new CommandService().execute(values)", "run(it.next())"]),
  JAVA("JAVA-05", "XmlServlet.java", ["xxe"], "new String(req.getInputStream().readAllBytes())", "builder.parse(", ["parse(xml);"]),
];
