import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import {
  Shield,
  Globe,
  Ban,
  FileCode2,
  ScrollText,
  Network,
  LogOut,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { useState } from "react";
import { Toaster } from "@/components/ui/sonner";

const navItems = [
  { to: "/sites", label: "Sites", icon: Globe },
  { to: "/ip-management", label: "IP Management", icon: Ban },
  { to: "/patterns", label: "Patterns", icon: FileCode2 },
  { to: "/logs", label: "Logs", icon: ScrollText },
];

const adminItems = [
  { to: "/forward-proxy", label: "Outbound Proxy", icon: Network },
];

export default function AppLayout() {
  const { role, logout } = useAuth();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="flex h-screen bg-zinc-950 text-zinc-50">
      {/* Sidebar */}
      <aside
        className={cn(
          "flex flex-col border-r border-zinc-800/70 bg-zinc-950/80 backdrop-blur transition-all duration-300",
          collapsed ? "w-16" : "w-60"
        )}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-5">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-zinc-800/70 bg-zinc-900/50 shadow-[0_0_0_1px_rgba(16,185,129,0.18),0_0_20px_rgba(16,185,129,0.08)]">
            <Shield className="h-5 w-5 text-emerald-400" />
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <div className="text-sm font-semibold tracking-tight">MuWAF</div>
              <div className="text-[11px] text-zinc-500">Admin Console</div>
            </div>
          )}
        </div>

        <Separator className="bg-zinc-800/70" />

        {/* Nav links */}
        <nav className="flex-1 space-y-1 px-2 py-3">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150",
                  isActive
                    ? "bg-emerald-500/10 text-emerald-400 shadow-[inset_0_0_0_1px_rgba(16,185,129,0.2)]"
                    : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                )
              }
            >
              <item.icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          ))}

          {role === "super_admin" && (
            <>
              <Separator className="my-2 bg-zinc-800/50" />
              <div className={cn("px-3 py-1", collapsed && "hidden")}>
                <span className="text-[10px] font-semibold uppercase tracking-wider text-zinc-600">
                  Admin
                </span>
              </div>
              {adminItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-150",
                      isActive
                        ? "bg-emerald-500/10 text-emerald-400 shadow-[inset_0_0_0_1px_rgba(16,185,129,0.2)]"
                        : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-200"
                    )
                  }
                >
                  <item.icon className="h-4 w-4 shrink-0" />
                  {!collapsed && <span>{item.label}</span>}
                </NavLink>
              ))}
            </>
          )}
        </nav>

        {/* Bottom section */}
        <div className="mt-auto space-y-2 px-2 pb-4">
          <Separator className="bg-zinc-800/50" />

          {/* Status indicator */}
          {!collapsed && (
            <div className="flex items-center gap-2 px-3 py-2 text-xs text-zinc-500">
              <span className="inline-flex h-2 w-2 animate-pulse rounded-full bg-emerald-400/80" />
              <span>System Online</span>
            </div>
          )}

          <Button
            variant="ghost"
            size="sm"
            onClick={handleLogout}
            className="w-full justify-start gap-3 text-zinc-400 hover:bg-red-500/10 hover:text-red-400"
          >
            <LogOut className="h-4 w-4 shrink-0" />
            {!collapsed && <span>Çıkış Yap</span>}
          </Button>

          <Button
            variant="ghost"
            size="icon"
            onClick={() => setCollapsed(!collapsed)}
            className="w-full text-zinc-500 hover:text-zinc-300"
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </Button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>

      <Toaster />
    </div>
  );
}
