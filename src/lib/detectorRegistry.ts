/**
 * Detector Registry
 *
 * A plugin point for adding new scan detectors without editing scanner.ts's
 * core orchestration by hand each time. The 30+ existing security/AI
 * detectors in scanner.ts are NOT migrated here -- they're already tested
 * and working, and a wholesale migration would be pure refactor risk with
 * no accuracy benefit. This registry is the on-ramp for what comes next.
 *
 * Usage:
 *   detectorRegistry.register({
 *     id: "my-new-check",
 *     category: "security",
 *     scan: (ctx) => ctx.lines
 *       .map((line, i) => /* ... *\/)
 *       .filter(Boolean),
 *   });
 *
 * scanner.ts calls detectorRegistry.runAll(ctx) once, alongside its
 * existing hardcoded detector calls, and merges the results.
 */

import type { ScanIndicator } from "./scanner";

export interface DetectorContext {
  content:   string;
  lines:     string[];
  file_path: string;
  language:  string;
}

export interface Detector {
  /** Must match risk_indicators / FIX_MAP / SARIF_RULE_META id conventions (kebab-case). */
  id:       string;
  category: "security" | "ai-signal";
  scan(ctx: DetectorContext): ScanIndicator[];
}

class DetectorRegistry {
  private detectors = new Map<string, Detector>();

  register(detector: Detector): void {
    if (this.detectors.has(detector.id)) {
      throw new Error(`Detector already registered: ${detector.id}`);
    }
    this.detectors.set(detector.id, detector);
  }

  unregister(id: string): void {
    this.detectors.delete(id);
  }

  get(id: string): Detector | undefined {
    return this.detectors.get(id);
  }

  getAll(category?: Detector["category"]): Detector[] {
    const all = Array.from(this.detectors.values());
    return category ? all.filter(d => d.category === category) : all;
  }

  /** Runs every registered detector against one file and merges the findings. */
  runAll(ctx: DetectorContext, category?: Detector["category"]): ScanIndicator[] {
    const out: ScanIndicator[] = [];
    for (const detector of this.getAll(category)) {
      try {
        out.push(...detector.scan(ctx));
      } catch (err) {
        // One misbehaving detector must not take down the whole scan.
        console.error(`[detectorRegistry] detector "${detector.id}" threw:`, err);
      }
    }
    return out;
  }

  /** Test-only: clears all registrations so test suites don't leak state across files. */
  _reset(): void {
    this.detectors.clear();
  }
}

export const detectorRegistry = new DetectorRegistry();
