"use client";

import { useEffect, useState } from "react";

interface Props {
  rows?: number;
  cards?: number;
  children: React.ReactNode;
}

/** Renders a loading skeleton for ~350 ms then reveals children. Gives all
 *  pages a consistent initial loading feel without requiring real async data. */
export default function PageSkeleton({ rows = 5, cards = 4, children }: Props) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setReady(true), 80);
    return () => clearTimeout(t);
  }, []);

  if (ready) return <>{children}</>;

  return (
    <div className="space-y-5">
      {/* Summary cards skeleton */}
      <div className={`grid grid-cols-2 sm:grid-cols-${Math.min(cards, 4)} gap-3`}>
        {Array.from({ length: cards }).map((_, i) => (
          <div key={i} className="rounded-2xl h-20 animate-pulse bg-gray-100" />
        ))}
      </div>

      {/* Filter row skeleton */}
      <div className="flex gap-2">
        <div className="h-9 w-52 rounded-xl animate-pulse bg-gray-100" />
        <div className="h-9 w-36 rounded-xl animate-pulse bg-gray-100" />
        <div className="h-9 w-28 rounded-xl animate-pulse bg-gray-100" />
      </div>

      {/* Row skeletons */}
      <div className="section-card overflow-hidden divide-y divide-gray-50">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 px-5 py-4">
            <div className="w-8 h-8 rounded-lg animate-pulse bg-gray-100 shrink-0" />
            <div className="flex-1 space-y-2">
              <div className="h-3 w-3/4 rounded animate-pulse bg-gray-100" />
              <div className="h-2.5 w-1/2 rounded animate-pulse bg-gray-100" />
            </div>
            <div className="h-7 w-20 rounded-lg animate-pulse bg-gray-100 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  );
}
