/**
 * Evidence-storage keys are `{org_id}/...`. A caller-supplied path is turned into a key inside the caller's own
 * org folder, or rejected: it may name the org folder itself (`{org_id}/a/b`) or be relative to it (`a/b`), but
 * no segment may be empty, `.` or `..`, or contain a backslash, `%` (no encoded traversal) or a control character.
 * Storage keys are not normalized on the way in, so `{org_id}/../other-org/x` must never reach the bucket.
 */

const BAD_SEGMENT = /[\\%\u0000-\u001f\u007f]/;

function cleanSegments(rel: string): string[] | null {
  const parts = rel.split("/");
  for (const p of parts) if (p === "" || p === "." || p === ".." || BAD_SEGMENT.test(p)) return null;
  return parts;
}

/** A full key `{org_id}/...` for an existing file, or null when the path could leave the org's folder. */
export function orgStorageKey(orgId: string, path: string): string | null {
  if (!orgId || !path) return null;
  const rel = path.startsWith(`${orgId}/`) ? path.slice(orgId.length + 1) : path;
  const parts = cleanSegments(rel);
  return parts ? `${orgId}/${parts.join("/")}` : null;
}

/** An upload sub-folder (may be empty) -- the same rules, minus the org prefix. Null when unsafe. */
export function orgStorageFolder(orgId: string, folder: string): string | null {
  if (!folder) return "";
  const rel = folder.startsWith(`${orgId}/`) ? folder.slice(orgId.length + 1) : folder;
  const parts = cleanSegments(rel.replace(/\/+$/, ""));
  return parts ? parts.join("/") : null;
}
