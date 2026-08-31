"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Filter, Search, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api-client";
import { Alert } from "@/types/models";
import { Badge } from "@/components/ui/Badge";
import { DataTable } from "@/components/ui/DataTable";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function AlertsPage() {
  const router = useRouter();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["alerts", severityFilter, statusFilter],
    queryFn: () => api.getAlerts({
      severity: severityFilter === "all" ? undefined : severityFilter,
      status: statusFilter === "all" ? undefined : statusFilter
    })
  });

  const alerts = data?.items || [];

  const columns = [
    {
      header: "SEVERITY",
      cell: (item: Alert) => (
        <Badge variant={item.severity}>{item.severity}</Badge>
      )
    },
    {
      header: "ALERT TITLE & SUMMARY",
      cell: (item: Alert) => (
        <div>
          <div className="font-semibold text-text-primary">{item.title}</div>
          <div className="text-[11px] text-text-secondary line-clamp-1">{item.description}</div>
        </div>
      )
    },
    {
      header: "ALERT TYPE",
      cell: (item: Alert) => (
        <span className="font-mono text-xs text-accent uppercase tracking-wider">{item.alert_type}</span>
      )
    },
    {
      header: "STATUS",
      cell: (item: Alert) => (
        <Badge variant={item.status === "OPEN" ? "critical" : "verified"} size="sm">
          {item.status}
        </Badge>
      )
    },
    {
      header: "TRIGGERED AT",
      cell: (item: Alert) => (
        <span className="font-mono text-xs text-text-muted">{formatDate(item.created_at)}</span>
      )
    }
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-security-critical" />
          DETERMINISTIC SECURITY ALERTS
        </h1>
        <p className="text-xs text-text-secondary">
          Continuous threat intelligence indicators, DGA entropy anomalies, and behavioral drift detections.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center justify-between gap-4 bg-surface-primary p-3 rounded-lg border border-surface-border">
        {/* Status Filters */}
        <div className="flex items-center gap-1.5 text-xs font-mono">
          <span className="text-text-muted mr-1">STATUS:</span>
          {["all", "OPEN", "ACKNOWLEDGED", "RESOLVED"].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded border uppercase transition-colors ${
                statusFilter === st
                  ? "bg-accent/15 border-accent text-accent font-semibold"
                  : "bg-surface-elevated border-surface-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Severity Filters */}
        <div className="flex items-center gap-1.5 text-xs font-mono">
          <span className="text-text-muted mr-1">SEVERITY:</span>
          {["all", "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded border uppercase transition-colors ${
                severityFilter === sev
                  ? "bg-accent/15 border-accent text-accent font-semibold"
                  : "bg-surface-elevated border-surface-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <LoadingState stateText="ANALYZING" message="Querying alert registry..." />
      ) : error ? (
        <ErrorState
          title="Failed to Load Alerts"
          message="Unable to communicate with the FastAPI alert engine."
          onRetry={() => refetch()}
        />
      ) : (
        <DataTable
          columns={columns}
          data={alerts}
          onRowClick={(alert) => router.push(`/alerts/${alert.id}`)}
          emptyMessage="No active alerts matching criteria."
        />
      )}
    </div>
  );
}
