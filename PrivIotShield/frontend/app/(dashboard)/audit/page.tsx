"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { FileText, Shield, Terminal, User } from "lucide-react";
import { api } from "@/lib/api-client";
import { AuditEvent } from "@/types/models";
import { DataTable } from "@/components/ui/DataTable";
import { Badge } from "@/components/ui/Badge";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function AuditPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["audit-logs"],
    queryFn: () => api.getAuditLogs({ limit: 100 })
  });

  const logs = data?.items || [];

  const columns = [
    {
      header: "TIMESTAMP",
      cell: (item: AuditEvent) => (
        <span className="font-mono text-xs text-text-muted">{formatDate(item.timestamp)}</span>
      )
    },
    {
      header: "ACTION & RESULT",
      cell: (item: AuditEvent) => (
        <div className="flex items-center gap-2">
          <Badge variant={item.result === "success" ? "verified" : "critical"} size="sm">
            {item.result}
          </Badge>
          <span className="font-mono text-xs font-semibold text-text-primary uppercase">{item.action}</span>
        </div>
      )
    },
    {
      header: "ACTOR / TENANT",
      cell: (item: AuditEvent) => (
        <div className="font-mono text-xs">
          <div className="text-text-primary">{item.actor || "system"}</div>
          <div className="text-[10px] text-text-muted">{item.tenant_id}</div>
        </div>
      )
    },
    {
      header: "TARGET",
      cell: (item: AuditEvent) => (
        <span className="font-mono text-xs text-text-secondary">{item.target_type || "N/A"} #{item.target_id || "0"}</span>
      )
    },
    {
      header: "REQUEST ID",
      cell: (item: AuditEvent) => (
        <span className="font-mono text-[11px] text-accent">{item.request_id || "direct_engine"}</span>
      )
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <FileText className="w-5 h-5 text-accent" />
          IMMUTABLE COMPLIANCE AUDIT TRAIL
        </h1>
        <p className="text-xs text-text-secondary">
          Complete non-repudiable log of operator actions, containment state transitions, and collector operations.
        </p>
      </div>

      {isLoading ? (
        <LoadingState stateText="ANALYZING" message="Querying audit trail..." />
      ) : error ? (
        <ErrorState
          title="Failed to Load Audit Logs"
          message="Unable to communicate with audit service."
          onRetry={() => refetch()}
        />
      ) : (
        <DataTable
          columns={columns}
          data={logs}
          emptyMessage="No audit records registered for current tenant scope."
        />
      )}
    </div>
  );
}
