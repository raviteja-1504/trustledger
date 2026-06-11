import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center px-4"
      style={{ background:"linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%)" }}>
      <div className="text-center space-y-6 max-w-md">
        <div className="text-8xl font-black text-white/10 select-none">404</div>
        <div>
          <h1 className="text-2xl font-black text-white">Page not found</h1>
          <p className="text-white/50 mt-2 text-sm">
            The page you&apos;re looking for doesn&apos;t exist or has been moved.
          </p>
        </div>
        <div className="flex items-center justify-center gap-3">
          <Link href="/dashboard"
            className="px-5 py-2.5 rounded-xl font-bold text-sm text-white transition-all"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
            Go to dashboard
          </Link>
          <Link href="/"
            className="px-5 py-2.5 rounded-xl font-semibold text-sm text-white/60 hover:text-white border border-white/10 hover:border-white/20 transition-all">
            Home
          </Link>
        </div>
      </div>
    </div>
  );
}
