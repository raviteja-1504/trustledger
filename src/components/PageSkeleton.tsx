"use client";

import { LoadingBlock } from "@/components/Loading";

interface Props {
  /** True while the page's data is still being fetched. */
  loading: boolean;
  /** What is loading, as in "Loading {label}…". */
  label: string;
  rows?: number;
  cards?: number;
  children?: React.ReactNode;
}

/**
 * A page's loading state: "Loading {label}…" with a spinner over a skeleton of the page, for as long as `loading`
 * is true -- then the page. (It used to reveal the page after a fixed 80 ms whatever the data was doing, so a slow
 * page showed its empty state -- or a blank screen -- while still fetching.)
 */
export default function PageSkeleton({ loading, label, rows = 5, cards = 4, children }: Props) {
  if (!loading) return <>{children}</>;
  return <LoadingBlock label={label} rows={rows} cards={cards} />;
}
