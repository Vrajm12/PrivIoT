import React from "react";
import { cn } from "@/lib/utils";

interface TabsProps {
  tabs: { id: string; label: string; count?: number }[];
  activeTab: string;
  onChange: (id: string) => void;
}

export function Tabs({ tabs, activeTab, onChange }: TabsProps) {
  return (
    <div className="flex border-b border-surface-border space-x-1 overflow-x-auto">
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={cn(
              "flex items-center gap-2 py-2 px-3 text-xs font-mono uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap",
              isActive
                ? "border-accent text-accent font-semibold bg-accent/5"
                : "border-transparent text-text-secondary hover:text-text-primary hover:border-surface-border"
            )}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span
                className={cn(
                  "px-1.5 py-0.2 text-[10px] rounded-full",
                  isActive ? "bg-accent/20 text-accent" : "bg-surface-elevated text-text-muted"
                )}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
