import React from "react";
import { cn } from "@/lib/utils";

interface StatusIndicatorProps {
  status: "active" | "healthy" | "learning" | "drift" | "critical" | "offline" | "contained";
  label?: string;
  pulse?: boolean;
}

export function StatusIndicator({ status, label, pulse = false }: StatusIndicatorProps) {
  const colorMap = {
    active: "bg-security-verified",
    healthy: "bg-security-verified",
    learning: "bg-security-low",
    drift: "bg-security-high",
    critical: "bg-security-critical",
    offline: "bg-security-unknown",
    contained: "bg-security-medium"
  };

  const colorClass = colorMap[status] || "bg-security-unknown";

  return (
    <div className="inline-flex items-center gap-2">
      <span className="relative flex h-2 w-2">
        {pulse && (
          <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-75", colorClass)} />
        )}
        <span className={cn("relative inline-flex rounded-full h-2 w-2", colorClass)} />
      </span>
      {label && <span className="text-xs font-mono text-text-secondary">{label}</span>}
    </div>
  );
}
