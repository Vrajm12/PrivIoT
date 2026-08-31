import React from "react";
import { cn } from "@/lib/utils";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  elevated?: boolean;
}

export function Card({ children, elevated = false, className, ...props }: CardProps) {
  return (
    <div
      className={cn(
        "rounded-lg border border-surface-border p-4 transition-colors",
        elevated ? "bg-surface-elevated" : "bg-surface-primary",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("flex items-center justify-between pb-3 border-b border-surface-border mb-3", className)} {...props}>
      {children}
    </div>
  );
}

export function CardTitle({ children, className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3 className={cn("text-sm font-semibold text-text-primary uppercase tracking-wider", className)} {...props}>
      {children}
    </h3>
  );
}
