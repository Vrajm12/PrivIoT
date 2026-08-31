import React from "react";
import { cn, getSeverityColor } from "@/lib/utils";

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "critical" | "high" | "medium" | "low" | "verified" | "unknown" | "outline" | "accent";
  size?: "sm" | "md";
}

export function Badge({ children, variant = "default", size = "md", className, ...props }: BadgeProps) {
  let colorClasses = "bg-surface-elevated text-text-secondary border-surface-border";

  if (variant === "accent") {
    colorClasses = "bg-accent/10 text-accent border-accent/30";
  } else if (["critical", "high", "medium", "low", "verified", "unknown"].includes(variant)) {
    const c = getSeverityColor(variant);
    colorClasses = `${c.bg} ${c.text} ${c.border}`;
  }

  return (
    <span
      className={cn(
        "inline-flex items-center font-mono font-medium rounded border uppercase tracking-wider",
        size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-0.5 text-xs",
        colorClasses,
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
