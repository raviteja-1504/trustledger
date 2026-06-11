/**
 * TrustLedger SSA Engine (Static Single Assignment)
 *
 * Converts function bodies into SSA form to enable precise data-flow and
 * taint analysis. Implements:
 *   1. Basic block extraction — split function body at branch/return boundaries
 *   2. Control-flow graph (CFG) — predecessor/successor edge lists
 *   3. Iterative dominator computation — idom per block (O(n²) but exact)
 *   4. Dominance frontier computation — where φ-functions are needed
 *   5. φ-function insertion — at join points for each variable
 *   6. SSA rename pass — each definition gets a unique subscript version
 *   7. Taint propagation — BFS through def-use chains from source to sink
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface Instruction {
  line:    number;
  text:    string;
  kind:    "assign" | "call" | "return" | "branch" | "phi" | "other";
  def?:    string;   // variable defined on the LHS (SSA: varName_version)
  uses:    string[]; // variables read on the RHS (SSA renamed)
  tainted: boolean;  // propagated taint
}

export interface BasicBlock {
  id:           number;
  instructions: Instruction[];
  preds:        number[]; // predecessor block IDs
  succs:        number[]; // successor block IDs
  label?:       string;   // "entry" | "exit" | branch label
}

export interface PhiNode {
  blockId:  number;
  variable: string;
  operands: Array<{ version: number; fromBlock: number }>;
  version:  number; // the version this phi defines
}

export interface SSAVariable {
  name:    string;
  version: number;
  defBlock: number;
  defLine:  number;
  tainted:  boolean;
  uses:     Array<{ block: number; line: number }>;
}

export interface TaintPath {
  source:     string;  // var_name@line
  sink:       string;  // sink kind (sql-injection, xss, etc.)
  sinkLine:   number;
  path:       string[]; // SSA variable chain
  confidence: number;   // 0–1
}

export interface SSAResult {
  blocks:        BasicBlock[];
  phis:          PhiNode[];
  variables:     Map<string, SSAVariable>;
  taintPaths:    TaintPath[];
  idom:          Map<number, number>;  // block_id → immediate dominator
  domFrontier:   Map<number, Set<number>>;
  defUse:        Map<string, string[]>; // ssaVar → list of ssaVars that use it
}

// ── String preprocessing ──────────────────────────────────────────────────────

function stripInline(raw: string): string {
  let out = "";
  let inStr = false;
  let strCh = "";
  let exprDepth = 0; // depth of ${ ... } interpolation inside a template literal
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    const n = i + 1 < raw.length ? raw[i + 1] : "";
    if (!inStr && c === "/" && n === "/") break;
    if (!inStr && c === "#" && out.trimStart().length === 0) break;
    // Template-literal interpolation `${...}` contains real code (often the
    // tainted variable feeding a sink, e.g. `db.query(\`...${id}\`)`) — keep
    // it instead of stripping it like ordinary string contents.
    if (inStr && strCh === "`" && exprDepth === 0 && c === "$" && n === "{") {
      exprDepth = 1; out += "${"; i++; continue;
    }
    if (inStr && strCh === "`" && exprDepth > 0) {
      if (c === "{") exprDepth++;
      else if (c === "}") exprDepth--;
      out += c;
      continue;
    }
    // Preserve string/template delimiters themselves so sink patterns that
    // anchor on quote characters (e.g. the `db.query(\`...${` SQL-injection
    // shape) can still match against the stripped text.
    if (!inStr && (c === "'" || c === '"' || c === "`")) { inStr = true; strCh = c; out += c; continue; }
    if (inStr && c === "\\" && strCh !== "`") { i++; continue; }
    if (inStr && c === strCh) { inStr = false; out += c; continue; }
    if (!inStr) out += c;
  }
  return out;
}

// ── Instruction classifier ────────────────────────────────────────────────────

const BRANCH_KEYWORDS  = /^\s*(?:if|else|for|while|do\b|switch|catch|try|elif|except)\b/;
const RETURN_KEYWORDS  = /^\s*(?:return|throw|raise|break|continue)\b/;
const ASSIGN_RE        = /^\s*(?:const|let|var)\s+(\w+)\s*=\s*(.+)/;
const ASSIGN_BARE_RE   = /^\s*(\w+)\s*=\s*(?!=)(.+)/;   // x = expr  (not ==)
const CALL_RE          = /^\s*(?:await\s+)?(\w+(?:\.\w+)*)\s*\(/;
const TAINT_SOURCES    = [
  /\breq\.(?:query|body|params|headers)\b/,
  /\brequest\.(?:query|body|params|headers|args)\b/,
  /\$_(?:POST|GET|REQUEST|COOKIE)\b/,
  /\bsearchParams\.get\b/,
  /\bformData\.get\b/,
  /\buserInput\b|\buserData\b|\binputData\b/,
  /\bprocess\.argv\b/,
];
const SINK_PATTERNS: Array<[RegExp, string]> = [
  [/db\.(query|execute|raw)\s*\(`[^`]*\$\{|['"][^'"]*'\s*\+/, "sql-injection"],
  [/innerHTML\s*=|document\.write\s*\(/,                       "xss"],
  [/child_process|execSync|exec\s*\(|spawn\s*\(/,              "command-injection"],
  [/res\.redirect\s*\(/,                                        "open-redirect"],
  [/fetch\s*\([^)]*\+|axios\.[a-z]+\s*\([^)]*\+/,             "ssrf"],
  [/fs\.(readFile|writeFile|unlink|rmdir)\s*\(/,               "path-traversal"],
];

function classifyInstruction(line: string, lineNum: number): Instruction {
  const s = stripInline(line);
  if (BRANCH_KEYWORDS.test(s)) {
    return { line: lineNum, text: s.trim(), kind: "branch", uses: extractUses(s), tainted: false };
  }
  if (RETURN_KEYWORDS.test(s)) {
    return { line: lineNum, text: s.trim(), kind: "return", uses: extractUses(s), tainted: false };
  }

  let m = ASSIGN_RE.exec(s);
  if (m) {
    const rhs = m[2];
    const tainted = TAINT_SOURCES.some(re => re.test(rhs));
    return { line: lineNum, text: s.trim(), kind: "assign", def: m[1], uses: extractUses(rhs), tainted };
  }
  m = ASSIGN_BARE_RE.exec(s);
  if (m) {
    const rhs = m[2];
    const tainted = TAINT_SOURCES.some(re => re.test(rhs));
    return { line: lineNum, text: s.trim(), kind: "assign", def: m[1], uses: extractUses(rhs), tainted };
  }
  if (CALL_RE.test(s)) {
    return { line: lineNum, text: s.trim(), kind: "call", uses: extractUses(s), tainted: false };
  }
  return { line: lineNum, text: s.trim(), kind: "other", uses: [], tainted: false };
}

function extractUses(expr: string): string[] {
  const idents = expr.match(/\b[a-zA-Z_]\w*\b/g) ?? [];
  const keywords = new Set(["const","let","var","function","return","if","else","for","while","new","true","false","null","undefined","await","async"]);
  return idents.filter(id => !keywords.has(id));
}

// ── Basic block extraction ────────────────────────────────────────────────────

function extractBlocks(bodyLines: string[], startLine: number): BasicBlock[] {
  const blocks: BasicBlock[] = [];
  let curBlock: BasicBlock = { id: 0, instructions: [], preds: [], succs: [], label: "entry" };

  const startNewBlock = (id: number, label?: string) => {
    if (curBlock.instructions.length > 0 || curBlock.label) {
      blocks.push(curBlock);
    }
    curBlock = { id, instructions: [], preds: [], succs: [], label };
  };

  let blockId = 1;

  for (let i = 0; i < bodyLines.length; i++) {
    const raw = bodyLines[i];
    const s   = stripInline(raw);
    const instr = classifyInstruction(raw, startLine + i);
    curBlock.instructions.push(instr);

    if (instr.kind === "branch") {
      // Branch ends the current block and starts two new ones (fall-through + target)
      const nextId = blockId++;
      curBlock.succs.push(nextId, nextId + 1);
      startNewBlock(nextId);
    } else if (instr.kind === "return") {
      // Return ends the block; connect to exit
      curBlock.succs.push(-1); // -1 = exit
      startNewBlock(blockId++);
    }

    void s; // suppress unused warning
  }

  if (curBlock.instructions.length > 0) blocks.push(curBlock);

  // Wire predecessor lists
  for (const blk of blocks) {
    for (const succId of blk.succs) {
      const succ = blocks.find(b => b.id === succId);
      if (succ && !succ.preds.includes(blk.id)) succ.preds.push(blk.id);
    }
  }

  return blocks;
}

// ── Iterative dominator computation (Cooper et al. 2001) ─────────────────────

function computeIDom(blocks: BasicBlock[]): Map<number, number> {
  if (blocks.length === 0) return new Map();
  const n    = blocks.length;
  const UNDEF = -1;
  const idom  = new Map<number, number>();

  // Post-order numbering (index into blocks array; blocks[0] is entry)
  const postOrder: number[] = [];
  const visited = new Set<number>();
  const dfs = (id: number) => {
    if (visited.has(id)) return;
    visited.add(id);
    const blk = blocks.find(b => b.id === id);
    for (const s of blk?.succs ?? []) if (s >= 0) dfs(s);
    postOrder.push(id);
  };
  dfs(blocks[0].id);

  const rpo = [...postOrder].reverse();  // reverse post-order
  const rpoIndex = new Map(rpo.map((id, i) => [id, i]));

  // Init: idom[entry] = entry; all others = UNDEF
  idom.set(blocks[0].id, blocks[0].id);
  for (const blk of blocks) {
    if (blk.id !== blocks[0].id) idom.set(blk.id, UNDEF);
  }

  const intersect = (b1: number, b2: number): number => {
    let f1 = b1, f2 = b2;
    while (f1 !== f2) {
      while ((rpoIndex.get(f1) ?? 0) > (rpoIndex.get(f2) ?? 0)) {
        f1 = idom.get(f1) ?? f1;
      }
      while ((rpoIndex.get(f2) ?? 0) > (rpoIndex.get(f1) ?? 0)) {
        f2 = idom.get(f2) ?? f2;
      }
    }
    return f1;
  };

  let changed = true;
  while (changed) {
    changed = false;
    for (const id of rpo) {
      const blk = blocks.find(b => b.id === id);
      if (!blk) continue;
      const processedPreds = blk.preds.filter(p => idom.get(p) !== UNDEF);
      if (processedPreds.length === 0) continue;
      let newIdom = processedPreds[0];
      for (let k = 1; k < processedPreds.length; k++) {
        newIdom = intersect(processedPreds[k], newIdom);
      }
      if (idom.get(id) !== newIdom) {
        idom.set(id, newIdom);
        changed = true;
      }
    }
  }

  void n;
  return idom;
}

// ── Dominance frontier computation ────────────────────────────────────────────

function computeDomFrontier(blocks: BasicBlock[], idom: Map<number, number>): Map<number, Set<number>> {
  const df = new Map<number, Set<number>>();
  for (const blk of blocks) df.set(blk.id, new Set());

  for (const blk of blocks) {
    if (blk.preds.length < 2) continue;
    for (const pred of blk.preds) {
      let runner = pred;
      while (runner !== (idom.get(blk.id) ?? runner)) {
        df.get(runner)?.add(blk.id);
        runner = idom.get(runner) ?? runner;
        if (runner === idom.get(runner)) break; // at entry
      }
    }
  }

  return df;
}

// ── φ-function insertion ──────────────────────────────────────────────────────

function insertPhis(blocks: BasicBlock[], df: Map<number, Set<number>>): PhiNode[] {
  // Collect all variable names defined in any block
  const defsPerBlock = new Map<number, Set<string>>();
  for (const blk of blocks) {
    const defs = new Set<string>();
    for (const instr of blk.instructions) {
      if (instr.def) defs.add(instr.def);
    }
    defsPerBlock.set(blk.id, defs);
  }

  const phis: PhiNode[] = [];
  const phiVersions = new Map<string, number>(); // variable → next version

  // For each variable, if it has multiple defs, insert phi at dominance frontiers
  const allVars = new Set<string>();
  for (const [, defs] of Array.from(defsPerBlock.entries())) {
    for (const v of Array.from(defs)) allVars.add(v);
  }

  for (const varName of Array.from(allVars)) {
    const workList = new Set<number>();
    for (const [blockId, defs] of Array.from(defsPerBlock.entries())) {
      if (defs.has(varName)) workList.add(blockId);
    }
    const hasPhiAt = new Set<number>();
    for (const blockId of Array.from(workList)) {
      for (const frontId of Array.from(df.get(blockId) ?? [])) {
        if (!hasPhiAt.has(frontId)) {
          hasPhiAt.add(frontId);
          const version = (phiVersions.get(varName) ?? 0) + 1;
          phiVersions.set(varName, version);
          phis.push({ blockId: frontId, variable: varName, operands: [], version });
        }
      }
    }
  }

  return phis;
}

// ── SSA rename pass ───────────────────────────────────────────────────────────

interface RenameState {
  counters: Map<string, number>;
  stacks:   Map<string, number[]>;
}

function renameBlock(
  blockId:  number,
  blocks:   BasicBlock[],
  phis:     PhiNode[],
  idom:     Map<number, number>,
  state:    RenameState,
  variables: Map<string, SSAVariable>,
): void {
  const blk = blocks.find(b => b.id === blockId);
  if (!blk) return;

  const pushed = new Map<string, number>(); // var → how many versions we pushed this block

  const newVersion = (varName: string, defLine: number, tainted: boolean): string => {
    const cnt = (state.counters.get(varName) ?? 0) + 1;
    state.counters.set(varName, cnt);
    const stack = state.stacks.get(varName) ?? [];
    stack.push(cnt);
    state.stacks.set(varName, stack);
    pushed.set(varName, (pushed.get(varName) ?? 0) + 1);
    const ssaName = `${varName}_${cnt}`;
    variables.set(ssaName, { name: varName, version: cnt, defBlock: blockId, defLine, tainted, uses: [] });
    return ssaName;
  };

  const topVersion = (varName: string): string => {
    const stack = state.stacks.get(varName) ?? [];
    const v = stack[stack.length - 1] ?? 0;
    return `${varName}_${v}`;
  };

  // Rename phi defs for this block
  for (const phi of phis) {
    if (phi.blockId === blockId) {
      newVersion(phi.variable, -1, false);
    }
  }

  // Rename instructions
  for (const instr of blk.instructions) {
    // Rename uses first (using current top-of-stack for each variable)
    instr.uses = instr.uses.map(u => topVersion(u));
    // Then rename the definition
    if (instr.def) {
      instr.def = newVersion(instr.def, instr.line, instr.tainted);
    }
  }

  // Fill in phi operands for successor blocks
  for (const succId of blk.succs) {
    if (succId < 0) continue;
    for (const phi of phis) {
      if (phi.blockId === succId) {
        const stack = state.stacks.get(phi.variable) ?? [];
        phi.operands.push({ version: stack[stack.length - 1] ?? 0, fromBlock: blockId });
      }
    }
  }

  // Recurse into dominated children (blocks whose idom is this block)
  for (const child of blocks) {
    if (idom.get(child.id) === blockId && child.id !== blockId) {
      renameBlock(child.id, blocks, phis, idom, state, variables);
    }
  }

  // Pop pushed versions off stacks
  for (const [varName, count] of Array.from(pushed.entries())) {
    const stack = state.stacks.get(varName) ?? [];
    for (let k = 0; k < count; k++) stack.pop();
    state.stacks.set(varName, stack);
  }
}

// ── Taint propagation through SSA ─────────────────────────────────────────────

function propagateTaint(
  blocks:    BasicBlock[],
  variables: Map<string, SSAVariable>,
): TaintPath[] {
  const paths: TaintPath[] = [];

  // Build def-use chains: for each ssaVar, record all instructions that use it
  for (const blk of blocks) {
    for (const instr of blk.instructions) {
      for (const use of instr.uses) {
        const v = variables.get(use);
        if (v) v.uses.push({ block: blk.id, line: instr.line });
      }
    }
  }

  // BFS from tainted sources
  const taintedQueue: string[] = Array.from(variables.entries())
    .filter(([, v]) => v.tainted)
    .map(([k]) => k);
  const visited = new Set<string>(taintedQueue);

  // Propagate taint through assignments
  let changed = true;
  while (changed) {
    changed = false;
    for (const blk of blocks) {
      for (const instr of blk.instructions) {
        if (instr.kind !== "assign" || !instr.def) continue;
        const anyUseTainted = instr.uses.some(u => {
          const base = u.replace(/_\d+$/, "");
          return visited.has(u) || [...visited].some(v => v.replace(/_\d+$/, "") === base);
        });
        if (anyUseTainted && instr.def && !visited.has(instr.def)) {
          visited.add(instr.def);
          const v = variables.get(instr.def);
          if (v) v.tainted = true;
          changed = true;
        }
      }
    }
  }

  // Check for tainted values reaching sinks
  for (const blk of blocks) {
    for (const instr of blk.instructions) {
      for (const [sinkRe, sinkKind] of SINK_PATTERNS) {
        if (!sinkRe.test(instr.text)) continue;
        const taintedUsed = instr.uses.filter(u => visited.has(u) || [...visited].some(v => v.replace(/_\d+$/, "") === u.replace(/_\d+$/, "")));
        if (taintedUsed.length > 0) {
          paths.push({
            source:     taintedUsed[0] + "@" + instr.line,
            sink:       sinkKind,
            sinkLine:   instr.line,
            path:       taintedUsed,
            confidence: 0.85,
          });
        }
      }
    }
  }

  return paths;
}

// ── Build def-use map ─────────────────────────────────────────────────────────

function buildDefUse(blocks: BasicBlock[], variables: Map<string, SSAVariable>): Map<string, string[]> {
  const defUse = new Map<string, string[]>();
  for (const blk of blocks) {
    for (const instr of blk.instructions) {
      for (const use of instr.uses) {
        if (!defUse.has(use)) defUse.set(use, []);
        if (instr.def) {
          const list = defUse.get(use)!;
          if (!list.includes(instr.def)) list.push(instr.def);
        }
      }
    }
  }
  void variables;
  return defUse;
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Build SSA form for a function body.
 * @param bodyLines  Lines of the function body (without signature)
 * @param startLine  Absolute line number of the first body line (for diagnostics)
 */
export function buildSSA(bodyLines: string[], startLine: number): SSAResult {
  if (bodyLines.length === 0) {
    return {
      blocks: [], phis: [], variables: new Map(), taintPaths: [],
      idom: new Map(), domFrontier: new Map(), defUse: new Map(),
    };
  }

  const blocks    = extractBlocks(bodyLines, startLine);
  const idom      = computeIDom(blocks);
  const domFront  = computeDomFrontier(blocks, idom);
  const phis      = insertPhis(blocks, domFront);
  const variables = new Map<string, SSAVariable>();
  const state: RenameState = { counters: new Map(), stacks: new Map() };

  if (blocks.length > 0) {
    renameBlock(blocks[0].id, blocks, phis, idom, state, variables);
  }

  const taintPaths = propagateTaint(blocks, variables);
  const defUse     = buildDefUse(blocks, variables);

  return { blocks, phis, variables, taintPaths, idom, domFrontier: domFront, defUse };
}

/**
 * Extract function body lines for a given function (by start/end line).
 * Content is the full file content; startLine and endLine are 1-based.
 */
export function extractFunctionBody(content: string, startLine: number, endLine: number): string[] {
  const lines = content.split("\n");
  return lines.slice(startLine, Math.min(endLine, lines.length));
}
