import React from "react";

interface LoadingStateProps {
  stateText?: "DISCOVERING" | "CORRELATING" | "LEARNING" | "ANALYZING" | "APPLYING" | "VERIFYING" | "LOADING";
  message?: string;
}

export function LoadingState({ stateText = "LOADING", message = "Executing operation..." }: LoadingStateProps) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center bg-surface-primary/30 border border-surface-border rounded-lg">
      <div className="relative flex items-center justify-center w-12 h-12 mb-4">
        <div className="absolute w-full h-full border-2 border-surface-border rounded-full" />
        <div className="absolute w-full h-full border-2 border-accent border-t-transparent rounded-full animate-spin" />
      </div>
      <div className="font-mono text-xs font-semibold text-accent uppercase tracking-widest mb-1">
        {stateText}
      </div>
      <p className="text-xs text-text-muted">{message}</p>
    </div>
  );
}
