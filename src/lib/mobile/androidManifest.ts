/**
 * Android manifest and network-configuration checks. A manifest is configuration, so every finding here is a fact about the file
 * (no data flow): a component exported with nothing guarding it, backups left on, cleartext traffic allowed or a plain-http base URL.
 */
import type { ScanIndicator } from "../scanner";
import { appsecHit } from "../appsecRules";

const lineOf = (src: string, index: number): number => src.slice(0, index).split("\n").length;
const attr = (tag: string, name: string): string | null => new RegExp(`android:${name}\\s*=\\s*["']([^"']*)["']`).exec(tag)?.[1] ?? null;

export const isAndroidManifest = (filePath: string, content: string): boolean =>
  /(?:^|[\\/])AndroidManifest\.xml$/i.test(filePath) || (/<manifest\b/.test(content) && /xmlns:android\s*=/.test(content));

/** Components whose elements can be exported. An <activity> that is a launcher (MAIN/LAUNCHER) is meant to be reachable. */
const COMPONENT_RE = /<(activity-alias|activity|service|receiver|provider)\b([^>]*?)(\/>|>)/g;

export function findAndroidManifestRisks(filePath: string, content: string): ScanIndicator[] {
  if (!isAndroidManifest(filePath, content)) return [];
  const out: ScanIndicator[] = [];

  const app = /<application\b[^>]*>/.exec(content);
  if (app) {
    const tag = app[0];
    if (attr(tag, "allowBackup") === "true") {
      out.push(appsecHit("android-backup-enabled", lineOf(content, app.index + tag.search(/android:allowBackup/)),
        "android:allowBackup=\"true\": the app's private data can be extracted with adb backup or restored from a cloud backup."));
    }
    if (attr(tag, "usesCleartextTraffic") === "true") {
      out.push(appsecHit("android-cleartext-traffic", lineOf(content, app.index + tag.search(/android:usesCleartextTraffic/)),
        "android:usesCleartextTraffic=\"true\": the app is allowed to use plain http:// connections."));
    }
  }

  let m: RegExpExecArray | null;
  COMPONENT_RE.lastIndex = 0;
  while ((m = COMPONENT_RE.exec(content))) {
    const [, kind, attrs, close] = m;
    if (attr(attrs, "exported") !== "true") continue;
    // the element body (for an intent filter), up to its closing tag
    const body = close === ">" ? content.slice(m.index, content.indexOf(`</${kind}>`, m.index) + 1 || m.index + m[0].length) : m[0];
    if ((kind === "activity" || kind === "activity-alias") && /android\.intent\.action\.MAIN/.test(body)) continue;
    const guarded = attr(attrs, "permission") !== null
      || (kind === "provider" && attr(attrs, "readPermission") !== null && attr(attrs, "writePermission") !== null);
    if (guarded) continue;
    out.push(appsecHit("android-exported-component", lineOf(content, m.index),
      `${kind} ${attr(attrs, "name") ?? ""} is exported (android:exported="true") with no android:permission, so any app on the device can reach it${kind === "provider" ? " and query its data" : ""}.`,
      { severity: kind === "provider" ? "high" : "medium" }));
  }
  return out;
}

/** Kotlin/Java: the server base URL assembled with a plain http:// scheme (Retrofit/OkHttp `baseUrl`), local development hosts excepted. */
const HTTP_BASE_URL_RE = /\b(?:baseUrl|BASE_URL|base_url|serverUrl|SERVER_URL|apiUrl|API_URL)\w*\b[^=\n(]*[=(]\s*"http:\/\/(?!localhost\b|127\.0\.0\.1\b|10\.0\.2\.2\b|192\.168\.)/;

export function findAndroidCleartextBaseUrl(content: string): ScanIndicator[] {
  const out: ScanIndicator[] = [];
  content.split("\n").forEach((l, i) => {
    if (/^\s*(?:\/\/|\*|\/\*)/.test(l)) return;
    if (HTTP_BASE_URL_RE.test(l)) {
      out.push(appsecHit("android-cleartext-traffic", i + 1,
        "The server base URL is built with a plain http:// scheme, so requests (credentials included) cross the network unencrypted."));
    }
  });
  return out;
}
