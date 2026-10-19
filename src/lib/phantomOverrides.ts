/**
 * Phantom-dependency remediation (status + notes) stored in violation_overrides, so it is the same on every device.
 *
 * Id: "phantom::<package>|<repo>" -- the "phantom::" prefix keeps it apart from file violations
 * ("crit::<scan>::<file>"), which every other reader of the overrides parses. Status maps onto the table's values
 * (remediating ↔ in_review); notes are one line each, joined with newlines into the single note column, keeping the
 * newest when they'd exceed its 2000 characters.
 */
import type { OverridePatch, ServerOverride } from "./violationStatuses";

export type RemediationStatus = "open" | "remediating" | "resolved";
export interface PhantomOverride { status?: RemediationStatus; notes?: string[] }

export const PHANTOM_PREFIX = "phantom::";
const NOTE_MAX = 2000;

const toServer = (s: RemediationStatus | undefined) => (s === "remediating" ? "in_review" : s === "resolved" ? "resolved" : "open");
const fromServer = (s: string): RemediationStatus => (s === "in_review" ? "remediating" : s === "resolved" ? "resolved" : "open");

export function joinNotes(notes: readonly string[]): string {
  const lines = notes.map(n => n.replace(/[\r\n]+/g, " ").trim()).filter(Boolean);
  const kept: string[] = [];
  let len = 0;
  for (let i = lines.length - 1; i >= 0; i--) {
    const add = lines[i].length + (kept.length > 0 ? 1 : 0);
    if (len + add > NOTE_MAX) break;
    kept.unshift(lines[i]); len += add;
  }
  if (kept.length === 0 && lines.length > 0) return lines[lines.length - 1].slice(0, NOTE_MAX);
  return kept.join("\n");
}

/** PATCH body for one package's override. */
export function phantomPatch(pkgId: string, o: PhantomOverride): OverridePatch {
  return { violation_id: PHANTOM_PREFIX + pkgId, status: toServer(o.status), note: joinNotes(o.notes ?? []) };
}

/** Overrides keyed by package id ("<package>|<repo>"), from the server's. */
export function phantomFromServer(server: Record<string, ServerOverride>): Record<string, PhantomOverride> {
  const out: Record<string, PhantomOverride> = {};
  for (const [id, v] of Object.entries(server)) {
    if (!id.startsWith(PHANTOM_PREFIX)) continue;
    out[id.slice(PHANTOM_PREFIX.length)] = { status: fromServer(v.status), notes: v.note ? v.note.split("\n").filter(Boolean) : [] };
  }
  return out;
}

/** Browser-held overrides the server has nothing for yet (the server's wins), as PATCH bodies. */
export function phantomUploads(server: Record<string, ServerOverride>, local: Record<string, unknown>): OverridePatch[] {
  const out: OverridePatch[] = [];
  for (const [pkgId, raw] of Object.entries(local)) {
    if (!pkgId || server[PHANTOM_PREFIX + pkgId] || !raw || typeof raw !== "object") continue;
    const o = raw as PhantomOverride;
    const status = o.status === "remediating" || o.status === "resolved" ? o.status : undefined;
    const notes = Array.isArray(o.notes) ? o.notes.filter((n): n is string => typeof n === "string") : [];
    if (!status && notes.length === 0) continue;
    out.push(phantomPatch(pkgId, { status, notes }));
  }
  return out;
}
