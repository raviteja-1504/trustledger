"use client";

import { useState, useEffect, useCallback } from "react";
import { useAuth } from "@/lib/auth";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

export type UserRole = "developer" | "security_reviewer" | "admin";

export interface RolePermissions {
  canAttest: boolean;
  canScan: boolean;
  canViewReports: boolean;
  canManageSettings: boolean;
  canManageUsers: boolean;
  canExportData: boolean;
}

export const ROLE_LABELS: Record<UserRole, string> = {
  developer:          "Developer",
  security_reviewer:  "Security Reviewer",
  admin:              "Admin",
};

export const ROLE_COLORS: Record<UserRole, { bg: string; text: string; ring: string; dot: string }> = {
  developer:         { bg: "bg-sky-50",    text: "text-sky-700",    ring: "ring-sky-200",    dot: "bg-sky-400"    },
  security_reviewer: { bg: "bg-amber-50",  text: "text-amber-700",  ring: "ring-amber-200",  dot: "bg-amber-400"  },
  admin:             { bg: "bg-violet-50", text: "text-violet-700", ring: "ring-violet-200", dot: "bg-violet-400" },
};

export const ROLE_DESCRIPTIONS: Record<UserRole, string> = {
  developer:         "Read-only: can view scans and reports. Cannot attest or change settings.",
  security_reviewer: "Can view all repos, attest high-risk files, and export compliance reports.",
  admin:             "Full access — settings, team management, attestation, and all operations.",
};

export const PERMISSIONS: Record<UserRole, RolePermissions> = {
  developer: {
    canAttest:         false,
    canScan:           true,
    canViewReports:    true,
    canManageSettings: false,
    canManageUsers:    false,
    canExportData:     false,
  },
  security_reviewer: {
    canAttest:         true,
    canScan:           true,
    canViewReports:    true,
    canManageSettings: false,
    canManageUsers:    false,
    canExportData:     true,
  },
  admin: {
    canAttest:         true,
    canScan:           true,
    canViewReports:    true,
    canManageSettings: true,
    canManageUsers:    true,
    canExportData:     true,
  },
};

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

function storageKey(uid?: string | null): string {
  return SKIP_AUTH ? "tl_role_dev" : `tl_role_${uid ?? "anon"}`;
}

export function useRole() {
  const { user } = useAuth();
  // SKIP_AUTH defaults to admin so local dev sees everything immediately
  const [role, setRoleState] = useState<UserRole>(SKIP_AUTH ? "admin" : "developer");

  useEffect(() => {
    if (typeof window === "undefined") return;
    const stored = localStorage.getItem(storageKey(user?.id));
    if (stored && stored in PERMISSIONS) setRoleState(stored as UserRole);
  }, [user]);

  const setRole = useCallback(
    (newRole: UserRole) => {
      if (typeof window !== "undefined") {
        localStorage.setItem(storageKey(user?.id), newRole);
        // In demo/SKIP_AUTH mode, also update the demo role key so the
        // auth profile name/email reflects the new role on next reload.
        if (SKIP_AUTH) localStorage.setItem("tl_demo_role", newRole);
      }
      setRoleState(newRole);
    },
    [user],
  );

  return { role, permissions: PERMISSIONS[role], setRole };
}

// ── Team roster (localStorage-backed for demo; swap for API call in production) ─

export interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatarInitials: string;
}

const TEAM_KEY = "tl_team_members";

const SEED_MEMBERS: TeamMember[] = [
  { id: "1", name: "Alice Chen",    email: `alice@${ORG}.io`,   role: "admin",             avatarInitials: "AC" },
  { id: "2", name: "Bob Martinez",  email: `bob@${ORG}.io`,     role: "security_reviewer", avatarInitials: "BM" },
  { id: "3", name: "Carol Patel",   email: `carol@${ORG}.io`,   role: "security_reviewer", avatarInitials: "CP" },
  { id: "4", name: "Dave Kim",      email: `dave@${ORG}.io`,    role: "developer",          avatarInitials: "DK" },
  { id: "5", name: "Eve Johnson",   email: `eve@${ORG}.io`,     role: "developer",          avatarInitials: "EJ" },
  { id: "6", name: "Frank Torres",  email: `frank@${ORG}.io`,   role: "developer",          avatarInitials: "FT" },
];

export function useTeamMembers() {
  const [members, setMembers] = useState<TeamMember[]>([]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const stored = localStorage.getItem(TEAM_KEY);
    if (stored) {
      try { setMembers(JSON.parse(stored)); return; } catch {/* fall through */}
    }
    setMembers(SEED_MEMBERS);
    localStorage.setItem(TEAM_KEY, JSON.stringify(SEED_MEMBERS));
  }, []);

  function persist(updated: TeamMember[]) {
    setMembers(updated);
    localStorage.setItem(TEAM_KEY, JSON.stringify(updated));
  }

  function setMemberRole(id: string, role: UserRole) {
    persist(members.map(m => m.id === id ? { ...m, role } : m));
  }

  function addMember(m: Omit<TeamMember, "id">) {
    if (members.some(x => x.email === m.email)) return;
    persist([...members, { ...m, id: Date.now().toString() }]);
  }

  function removeMember(id: string) {
    persist(members.filter(m => m.id !== id));
  }

  return { members, setMemberRole, addMember, removeMember };
}
