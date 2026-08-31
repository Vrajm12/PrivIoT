import React from "react";
import { cn } from "@/lib/utils";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline" | "ghost";
  size?: "sm" | "md" | "lg";
  isLoading?: boolean;
}

export function Button({
  children,
  variant = "primary",
  size = "md",
  isLoading = false,
  className,
  disabled,
  ...props
}: ButtonProps) {
  const baseClasses = "inline-flex items-center justify-center font-medium transition-all duration-150 rounded border focus:outline-none focus:ring-1 disabled:opacity-50 disabled:cursor-not-allowed";

  const sizeClasses = {
    sm: "px-2.5 py-1 text-xs gap-1.5",
    md: "px-3.5 py-1.5 text-sm gap-2",
    lg: "px-5 py-2.5 text-base gap-2.5"
  };

  const variantClasses = {
    primary: "bg-accent text-background border-accent hover:bg-accent-hover font-semibold shadow-sm focus:ring-accent",
    secondary: "bg-surface-elevated text-text-primary border-surface-border hover:bg-surface-border hover:text-white focus:ring-surface-border",
    danger: "bg-security-critical/10 text-security-critical border-security-critical/40 hover:bg-security-critical hover:text-white focus:ring-security-critical",
    outline: "bg-transparent text-text-secondary border-surface-border hover:text-text-primary hover:border-text-muted focus:ring-surface-border",
    ghost: "bg-transparent text-text-secondary border-transparent hover:bg-surface-elevated hover:text-text-primary focus:ring-surface-border"
  };

  return (
    <button
      className={cn(baseClasses, sizeClasses[size], variantClasses[variant], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin mr-1.5" />
      ) : null}
      {children}
    </button>
  );
}
