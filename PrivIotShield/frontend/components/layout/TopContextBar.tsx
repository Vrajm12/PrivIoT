"use client";

import React from "react";
import { Search, Building, Network, Shield, User, AlertOctagon, LogOut } from "lucide-react";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { useRealtimeSOC } from "@/hooks/use-realtime-soc";

export function TopContextBar() {
  const { status, lastEvent } = useRealtimeSOC();

  const handleSignOut = () => {
    if (window.confirm("Are you sure you want to sign out of the SOC session?")) {
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = "/login";
    }
  };

  return (
    <header className="h-14 bg-surface-primary border-b border-surface-border flex items-center justify-between px-6 sticky top-0 z-20">
      {/* Operational Context Hierarchy */}
      <div className="flex items-center gap-6 text-xs font-mono">
        <div className="flex items-center gap-2">
          <Building className="w-3.5 h-3.5 text-text-muted" />
          <span className="text-text-muted">CUSTOMER:</span>
          <span className="text-text-primary font-semibold">ABC Manufacturing</span>
        </div>

        <div className="h-3 w-px bg-surface-border" />

        <div className="flex items-center gap-2">
          <Network className="w-3.5 h-3.5 text-text-muted" />
          <span className="text-text-muted">SITE:</span>
          <span className="text-text-primary font-semibold">Pune Plant (Site 01)</span>
        </div>

        <div className="h-3 w-px bg-surface-border" />

        <div className="flex items-center gap-2">
          <span className="text-text-muted">SCOPE:</span>
          <span className="px-1.5 py-0.5 rounded bg-surface-elevated text-accent border border-surface-border text-[10px]">
            10.10.1.0/24
          </span>
        </div>

        <div className="h-3 w-px bg-surface-border" />

        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-accent/10 border border-accent/30 text-accent text-[11px] font-bold tracking-wider">
          <Shield className="w-3 h-3 text-accent" />
          <span>PILOT MODE</span>
          <span className="text-[9px] text-text-muted font-normal">| REQUIRE_APPROVAL</span>
        </div>
      </div>

      {/* Global Search & Operator Status */}
      <div className="flex items-center gap-4">
        {/* Real-Time Security Incident Banner */}
        {lastEvent && lastEvent.severity === "critical" && (
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded bg-security-critical/15 border border-security-critical/40 text-[11px] font-mono text-security-critical animate-pulse">
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>LIVE INCIDENT: {lastEvent.event_type} (Asset #{lastEvent.asset_id || 0})</span>
          </div>
        )}

        {/* Search */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-text-muted" />
          <input
            type="text"
            placeholder="Search IP, MAC, CVE, Vendor..."
            className="w-52 pl-8 pr-3 py-1 bg-surface-secondary border border-surface-border rounded text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent font-mono"
          />
        </div>

        <div className="h-4 w-px bg-surface-border" />

        {/* Live Status Indicator */}
        <StatusIndicator
          status={status === "LIVE" ? "healthy" : status === "RECONNECTING" ? "drift" : "offline"}
          label={`SOC ${status}`}
          pulse={status === "LIVE" || status === "RECONNECTING"}
        />

        {/* Operator Profile & Sign Out */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-2.5 py-1 bg-surface-elevated rounded border border-surface-border text-xs font-mono">
            <div className="w-5 h-5 rounded-full bg-accent/20 text-accent flex items-center justify-center font-bold text-[10px]">
              A
            </div>
            <span className="text-text-primary font-medium">secops_admin</span>
            <span className="text-[10px] text-accent uppercase font-bold px-1 bg-accent/10 rounded">ADMIN</span>
          </div>

          <button
            onClick={handleSignOut}
            title="Sign Out of SOC Session"
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-surface-elevated border border-surface-border text-text-muted hover:text-security-critical hover:border-security-critical/40 hover:bg-security-critical/10 text-xs font-mono transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        </div>
      </div>
    </header>
  );
}

