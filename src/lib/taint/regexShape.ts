/**
 * Structural ReDoS check for a CONSTANT regex, shared by engines that see a pattern applied to request input
 * (`/([0-9]+)+#/.test(req.body.x)`). A tainted PATTERN is a separate, simpler sink (`new RegExp(input)`).
 *
 * The shape judged is "star height" above one: a group whose body can itself repeat without bound, repeated
 * without bound again -- `(a+)+`, `(\w*)*`, `(x+){2,}`. On a near-miss input the engine tries every way of
 * splitting the run between the inner and the outer repetition, which is exponential in the input length.
 * Bounded repetition (`?`, `{1,3}`) can't do that and is ignored; so is anything inside a character class.
 */

/** Length of an unbounded quantifier (`+`, `*`, `{n,}`) starting at `i`, or 0. */
function unboundedQuantifierAt(src: string, i: number): number {
  const c = src[i];
  if (c === "+" || c === "*") return 1;
  if (c !== "{") return 0;
  const m = /^\{\d+,\}/.exec(src.slice(i));
  return m ? m[0].length : 0;
}

/** Does `src` (a regex body, no delimiters) repeat a group that itself contains unbounded repetition? */
export function hasNestedQuantifier(src: string): boolean {
  // One entry per open group: does its body so far contain an unbounded quantifier?
  const stack: boolean[] = [];
  let inClass = false;
  // The previous atom was a group whose body repeats without bound.
  let afterRepeatingGroup = false;
  for (let i = 0; i < src.length; ) {
    const c = src[i];
    if (c === "\\") { afterRepeatingGroup = false; i += 2; continue; }
    if (inClass) { if (c === "]") inClass = false; i++; continue; }
    if (c === "[") { inClass = true; afterRepeatingGroup = false; i++; continue; }
    if (c === "(") { stack.push(false); afterRepeatingGroup = false; i++; continue; }
    if (c === ")") {
      const inner = stack.pop() ?? false;
      if (inner && stack.length) stack[stack.length - 1] = true;
      afterRepeatingGroup = inner;
      i++;
      continue;
    }
    const q = unboundedQuantifierAt(src, i);
    if (q) {
      if (afterRepeatingGroup) return true;
      if (stack.length) stack[stack.length - 1] = true;
      afterRepeatingGroup = false;
      i += q;
      continue;
    }
    afterRepeatingGroup = false;
    i++;
  }
  return false;
}
