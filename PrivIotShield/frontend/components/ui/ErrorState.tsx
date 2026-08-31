import React from "react";
import { AlertOctagon, RotateCcw } from "lucide-react";
import { Button } from "./Button";

interface ErrorStateProps {
  title?: string;
  message: string;
  requestId?: string;
  onRetry?: () => void;
}

export function ErrorState({ title = "Operation Error", message, requestId, onRetry }: ErrorStateProps) {
  return (
    <div className="p-4 rounded-lg border border-security-critical/30 bg-security-critical/5">
      <div className="flex items-start gap-3">
        <AlertOctagon className="w-5 h-5 text-security-critical flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <h4 className="text-sm font-semibold text-security-critical uppercase tracking-wider mb-1">{title}</h4>
          <p className="text-xs text-text-secondary leading-relaxed mb-2">{message}</p>
          {requestId && (
            <div className="text-[11px] font-mono text-text-muted mb-3">
              Request ID: <span className="text-text-secondary">{requestId}</span>
            </div>
          )}
          {onRetry && (
            <Button variant="danger" size="sm" onClick={onRetry}>
              <RotateCcw className="w-3.5 h-3.5 mr-1" /> Retry Request
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
