/**
 * A cache keyed by a tree-sitter node that actually hits.
 *
 * web-tree-sitter builds a NEW JavaScript object every time a node is reached (`tree.rootNode`, `node.parent`, `node.namedChildren`), so a
 * `WeakMap<SyntaxNode, V>` never finds an entry stored under "the same" node: every lookup missed and the work it was meant to save (walking a whole
 * file for its imports, its function definitions, its class hierarchy) was done again for every call site. A node is identified by the tree it
 * belongs to (one stable object) and its id (unique within that tree), which is what this keys on. Entries go when the tree is collected.
 */
interface TsNodeLike { tree: object; id: number }

export class NodeCache<V> {
  private readonly byTree = new WeakMap<object, Map<number, V>>();

  get(node: TsNodeLike): V | undefined { return this.byTree.get(node.tree)?.get(node.id); }
  has(node: TsNodeLike): boolean { return this.byTree.get(node.tree)?.has(node.id) ?? false; }
  set(node: TsNodeLike, value: V): this {
    let m = this.byTree.get(node.tree);
    if (!m) { m = new Map(); this.byTree.set(node.tree, m); }
    m.set(node.id, value);
    return this;
  }
}
