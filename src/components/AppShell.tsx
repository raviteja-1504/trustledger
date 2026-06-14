"use client";

import { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import Sidebar from "@/components/Sidebar";
import Nav from "@/components/Nav";
import GlobalSearch from "@/components/GlobalSearch";
import StatusBar from "@/components/StatusBar";
import { SidebarProvider } from "@/lib/sidebar";
import { KeyboardShortcutsProvider } from "@/components/keyboard/KeyboardShortcuts";
import { SkipNav, LiveRegion } from "@/components/Accessibility";
import { useAuth } from "@/lib/auth";

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname   = usePathname() ?? "/";
  const isPublic   = pathname === "/" || pathname === "/login" || pathname === "/onboarding" || pathname === "/status" || pathname === "/docs" || pathname === "/auth/callback";
  const [mobileNav, setMobileNav] = useState(false);
  const { user, loading } = useAuth();

  // Close mobile nav on route change
  useEffect(() => { setMobileNav(false); }, [pathname]);

  if (isPublic) {
    return <>{children}</>;
  }

  // Not signed in (or still resolving) — show the page's AuthGuard prompt
  // full-screen, without the sidebar/nav chrome of an authenticated session.
  if (!SKIP_AUTH && (loading || !user)) {
    return <div className="flex h-screen overflow-hidden">{children}</div>;
  }

  return (
    <SidebarProvider>
      <SkipNav />
      <LiveRegion />
      {/* Mobile overlay */}
      {mobileNav && (
        <div
          className="fixed inset-0 z-30 bg-black/50 md:hidden"
          onClick={() => setMobileNav(false)}
        />
      )}

      <div className="flex h-screen overflow-hidden flex-col">
        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar — hidden on mobile unless mobileNav is open */}
          <div className={`
            fixed inset-y-0 left-0 z-40 md:static md:z-auto
            transition-transform duration-300 md:h-full flex-shrink-0
            ${mobileNav ? "translate-x-0" : "-translate-x-full md:translate-x-0"}
          `}>
            <Sidebar />
          </div>

          <div className="flex flex-col flex-1 overflow-hidden min-w-0">
            <Nav onMobileMenuToggle={() => setMobileNav(v => !v)} mobileNavOpen={mobileNav} />
            <main id="main-content" className="flex-1 overflow-y-auto px-3 sm:px-5 md:px-6 py-4 sm:py-5" tabIndex={-1} style={{ contain: "layout" }}>
              {children}
            </main>
          </div>
        </div>
        <StatusBar />
      </div>
      <GlobalSearch />
      <KeyboardShortcutsProvider />
    </SidebarProvider>
  );
}
