"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  Server,
  Activity,
  AlertTriangle,
  Flame,
  Radio,
  Sliders,
  Building,
  FileText,
  Lock,
  Terminal,
  Cpu,
  BarChart3,
  LogOut
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { label: "Dashboard", href: "/dashboard", icon: BarChart3 },
  { label: "Fleet Triage", href: "/fleet", icon: Server },
  { label: "Assets", href: "/assets", icon: Server },
  { label: "Alerts", href: "/alerts", icon: AlertTriangle },
  { label: "Behavior", href: "/behavior", icon: Activity },
  { label: "Exposure / PRI", href: "/exposure", icon: Sliders },
  { label: "Vulnerabilities", href: "/vulnerabilities", icon: Flame },
  { label: "Containment", href: "/containment", icon: Lock },
  { label: "Collectors", href: "/collectors", icon: Radio },
  { label: "Sites", href: "/sites", icon: Building },
  { label: "Reports", href: "/reports", icon: FileText },
  { label: "Pilot Validation", href: "/pilot", icon: ShieldAlert },
  { label: "Onboarding", href: "/onboarding", icon: Cpu },
  { label: "System Health", href: "/system", icon: Terminal },
  { label: "Audit Log", href: "/audit", icon: FileText },
];

export function Sidebar() {
  const pathname = usePathname();

  const handleSignOut = () => {
    if (window.confirm("Are you sure you want to sign out of the SOC session?")) {
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = "/login";
    }
  };

  return (
    <aside className="w-56 h-screen bg-surface-primary border-r border-surface-border flex flex-col justify-between select-none fixed left-0 top-0 z-30">
      {/* Brand Header */}
      <div>
        <div className="h-14 flex items-center px-4 border-b border-surface-border gap-2.5">
          <div className="w-7 h-7 rounded bg-accent/10 border border-accent/40 flex items-center justify-center text-accent">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <div className="font-mono font-bold text-xs text-text-primary tracking-wider flex items-center gap-1.5">
              PRIVIOT <span className="text-accent">SHIELD</span>
            </div>
            <div className="text-[9px] font-mono text-text-muted">CONTINUOUS SOC v4.0</div>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="p-2 space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
            const Icon = item.icon;

            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2.5 px-3 py-2 rounded text-xs font-mono transition-colors",
                  isActive
                    ? "bg-accent/10 text-accent font-semibold border-l-2 border-accent"
                    : "text-text-secondary hover:text-text-primary hover:bg-surface-elevated"
                )}
              >
                <Icon className={cn("w-4 h-4", isActive ? "text-accent" : "text-text-muted")} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Footer Section */}
      <div>
        <div className="p-2 border-t border-surface-border">
          <button
            onClick={handleSignOut}
            className="w-full flex items-center gap-2.5 px-3 py-1.5 rounded text-xs font-mono text-text-muted hover:text-security-critical hover:bg-security-critical/10 transition-colors text-left"
          >
            <LogOut className="w-4 h-4" />
            <span>Sign Out</span>
          </button>
        </div>

        {/* Engine Footer */}
        <div className="p-3 border-t border-surface-border bg-surface-primary/80">
          <div className="flex items-center justify-between text-[10px] font-mono text-text-muted mb-1">
            <span>PRI-v2 ENGINE</span>
            <span className="text-security-verified font-bold">ONLINE</span>
          </div>
          <div className="flex items-center justify-between text-[10px] font-mono text-text-muted">
            <span>48h MUD BASELINE</span>
            <span className="text-accent font-bold">ACTIVE</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
