import React from "react";
import { cn, getSeverityColor } from "@/lib/utils";

interface RiskScoreProps {
  score: number;
  level?: string;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
}

export function RiskScore({ score, level, size = "md", showLabel = true }: RiskScoreProps) {
  const rounded = Number(score).toFixed(1);
  const derivedLevel = level || (score >= 8.0 ? "critical" : score >= 6.0 ? "high" : score >= 3.5 ? "medium" : "low");
  const colors = getSeverityColor(derivedLevel);

  const sizeClasses = {
    sm: "text-xs px-1.5 py-0.5",
    md: "text-sm px-2.5 py-1",
    lg: "text-xl px-4 py-2 font-bold"
  };

  return (
    <div className="inline-flex items-center gap-2">
      <div className={cn("font-mono font-bold rounded border", sizeClasses[size], colors.bg, colors.text, colors.border)}>
        {rounded}
      </div>
      {showLabel && (
        <span className={cn("font-mono text-xs uppercase tracking-wider font-semibold", colors.text)}>
          {derivedLevel}
        </span>
      )}
    </div>
  );
}
