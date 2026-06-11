"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { useNotifications, type Notification } from "@/lib/notifications";

const LEVEL_META: Record<string, { dot:string; bg:string; text:string; label:string }> = {
  critical: { dot:"#7c3aed", bg:"rgba(237,233,254,0.6)", text:"#6d28d9", label:"Critical" },
  high:     { dot:"#f97316", bg:"rgba(255,237,213,0.5)", text:"#c2410c", label:"High"     },
  warning:  { dot:"#f59e0b", bg:"rgba(254,243,199,0.5)", text:"#b45309", label:"Warning"  },
  info:     { dot:"#6366f1", bg:"rgba(238,242,255,0.5)", text:"#4338ca", label:"Info"     },
  success:  { dot:"#10b981", bg:"rgba(209,250,229,0.5)", text:"#065f46", label:"Success"  },
};

function timeAgo(ms: number): string {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60)   return "just now";
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400)return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

export default function NotificationsPage() {
  const { notifications, markRead, markAllRead, dismiss, dismissAll } = useNotifications();
  const [filter, setFilter] = useState<"all"|"unread"|"critical"|"high">("all");
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    let list = [...notifications];
    if (filter === "unread")   list = list.filter(n => !n.read);
    if (filter === "critical") list = list.filter(n => n.level === "critical");
    if (filter === "high")     list = list.filter(n => n.level === "high");
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(n => n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q));
    }
    return list;
  }, [notifications, filter, search]);

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <AuthGuard>
      <div className="max-w-3xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900 flex items-center gap-2">
              Notifications
              {unreadCount > 0 && (
                <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">{unreadCount}</span>
              )}
            </h1>
            <p className="text-sm text-gray-400 mt-0.5">{notifications.length} total · {unreadCount} unread</p>
          </div>
          <div className="flex items-center gap-2">
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search notifications…"
              className="text-sm border border-gray-200 rounded-xl px-3.5 py-2 w-48 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
            {unreadCount > 0 && (
              <button onClick={markAllRead}
                className="px-4 py-2 text-sm font-semibold rounded-xl border border-gray-200 text-gray-600 hover:border-indigo-300 hover:text-indigo-600 transition-colors">
                Mark all read
              </button>
            )}
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 flex-wrap">
          {([
            { key:"all",      label:`All (${notifications.length})` },
            { key:"unread",   label:`Unread (${unreadCount})` },
            { key:"critical", label:`Critical (${notifications.filter(n=>n.level==="critical").length})` },
            { key:"high",     label:`High (${notifications.filter(n=>n.level==="high").length})` },
          ] as const).map(f => (
            <button key={f.key} onClick={() => setFilter(f.key)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${filter===f.key?"bg-indigo-600 text-white":"bg-gray-100 text-gray-600 hover:bg-gray-200"}`}>
              {f.label}
            </button>
          ))}
        </div>

        {/* Notifications list */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
          {filtered.length === 0 ? (
            <div className="py-16 text-center">
              <p className="text-3xl mb-3">🔔</p>
              <p className="text-sm font-bold text-gray-700">
                {filter === "unread" ? "All caught up!" : "No notifications"}
              </p>
              <p className="text-xs text-gray-400 mt-1">
                {filter === "unread" ? "You've read all your notifications." : "Notifications will appear here when triggered."}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {filtered.map((n: Notification) => {
                const meta = LEVEL_META[n.level] ?? LEVEL_META.info;
                return (
                  <div
                    key={n.id}
                    className="flex items-start gap-4 px-5 py-4 transition-colors hover:bg-gray-50 group"
                    style={{ background: !n.read ? meta.bg : undefined }}
                    onClick={() => markRead(n.id)}
                  >
                    {/* Level dot */}
                    <div className="mt-1 shrink-0">
                      <span className="w-2.5 h-2.5 rounded-full block" style={{ background: meta.dot }} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          {n.href ? (
                            <Link href={n.href} onClick={e => e.stopPropagation()}
                              className="text-sm font-bold text-gray-900 hover:text-indigo-600 block truncate transition-colors">
                              {n.title}
                            </Link>
                          ) : (
                            <p className="text-sm font-bold text-gray-900 truncate">{n.title}</p>
                          )}
                          <p className="text-xs text-gray-500 mt-0.5 leading-relaxed line-clamp-2">{n.body}</p>
                        </div>
                        <div className="shrink-0 flex items-center gap-2">
                          <span className="text-[10px] text-gray-400 whitespace-nowrap">{timeAgo(n.time)}</span>
                          {!n.read && (
                            <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 mt-1.5">
                        <span className="text-[9px] font-bold px-2 py-0.5 rounded-full"
                          style={{ background:`${meta.dot}18`, color:meta.text }}>
                          {meta.label}
                        </span>
                        {n.href && (
                          <Link href={n.href} onClick={e => e.stopPropagation()}
                            className="text-[10px] text-indigo-500 hover:text-indigo-700 font-semibold">
                            View →
                          </Link>
                        )}
                      </div>
                    </div>

                    {/* Dismiss */}
                    <button
                      onClick={e => { e.stopPropagation(); dismiss(n.id); }}
                      className="opacity-0 group-hover:opacity-100 transition-opacity text-gray-400 hover:text-gray-600 shrink-0 mt-0.5 p-0.5 rounded"
                      aria-label="Dismiss">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                      </svg>
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {notifications.length > 0 && (
          <p className="text-center text-xs text-gray-400">
            <button onClick={dismissAll}
              className="hover:text-rose-500 transition-colors">
              Clear all notifications
            </button>
          </p>
        )}

      </div>
    </AuthGuard>
  );
}
