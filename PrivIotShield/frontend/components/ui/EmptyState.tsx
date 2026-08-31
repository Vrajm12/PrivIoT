import React from "react";
import { AlertTriangle, ShieldCheck, Inbox } from "lucide-react";
import { Button } from "./Button";

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: "inbox" | "shield" | "alert";
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ title, description, icon = "inbox", actionLabel, onAction }: EmptyStateProps) {
  const IconComponent = icon === "shield" ? ShieldCheck : icon === "alert" ? AlertTriangle : Inbox;

  return (
    <div className="flex flex-col items-center justify-center p-8 text-center border border-dashed border-surface-border rounded-lg bg-surface-primary/50">
      <div className="w-10 h-10 rounded-full bg-surface-elevated flex items-center justify-center text-text-muted mb-3">
        <IconComponent className="w-5 h-5" />
      </div>
      <h4 className="text-sm font-semibold text-text-primary mb-1 uppercase tracking-wider">{title}</h4>
      <p className="text-xs text-text-secondary max-w-sm mb-4 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <Button variant="secondary" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
