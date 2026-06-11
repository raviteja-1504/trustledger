"use client";

import { useMemo } from "react";
import { attributeCode, MODEL_META, type AttributionResult } from "@/lib/aiAttribution";

interface Props {
  content?: string;
  language?: string;
  attribution?: AttributionResult;
  showBreakdown?: boolean;
}

export default function AIAttributionBadge({ content, language, attribution: propAttribution, showBreakdown = false }: Props) {
  const attribution = useMemo<AttributionResult | null>(() => {
    if (propAttribution) return propAttribution;
    if (!content) return null;
    return attributeCode(content, language ?? "text");
  }, [content, language, propAttribution]);

  if (!attribution || attribution.model === "unknown") return null;

  const meta = MODEL_META[attribution.model];
  const pct  = Math.round(attribution.confidence * 100);

  return (
    <div className="inline-block">
      {/* Main badge */}
      <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-bold border"
        style={{ background: meta.bg, color: meta.color, borderColor: `${meta.color}33` }}>
        <span>{meta.icon}</span>
        <span>{meta.label}</span>
        <span className="opacity-70">{pct}%</span>
      </div>

      {/* Confidence breakdown */}
      {showBreakdown && (
        <div className="mt-2 space-y-1">
          {(Object.entries(attribution.breakdown) as [string, number][])
            .filter(([, v]) => v > 0.05)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 4)
            .map(([model, score]) => {
              const m = MODEL_META[model as keyof typeof MODEL_META] ?? MODEL_META.unknown;
              return (
                <div key={model} className="flex items-center gap-2">
                  <span className="text-[10px] text-gray-500 w-28 shrink-0">{m.icon} {m.label}</span>
                  <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all"
                      style={{ width: `${Math.round(score * 100)}%`, background: m.color }} />
                  </div>
                  <span className="text-[10px] text-gray-500 w-8 text-right">{Math.round(score * 100)}%</span>
                </div>
              );
            })}
          {attribution.signals.length > 0 && (
            <p className="text-[10px] text-gray-400 pt-1 leading-relaxed">
              {attribution.signals[0]}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
