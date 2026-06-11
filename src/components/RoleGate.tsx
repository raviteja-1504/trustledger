"use client";

import { type ReactNode } from "react";
import { useRole, type RolePermissions } from "@/lib/roles";

interface Props {
  requires: keyof RolePermissions;
  children: ReactNode;
  /** Rendered when the permission is NOT granted. Defaults to null. */
  fallback?: ReactNode;
}

/**
 * Renders `children` only when the current user's role grants `requires`.
 * Pass `fallback` to show an alternative (e.g. a locked/disabled version).
 */
export default function RoleGate({ requires, children, fallback = null }: Props) {
  const { permissions } = useRole();
  return permissions[requires] ? <>{children}</> : <>{fallback}</>;
}
