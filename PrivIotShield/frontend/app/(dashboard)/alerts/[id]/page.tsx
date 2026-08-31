"use client";

import React from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, ArrowLeft, CheckCircle2, ShieldAlert,
  Terminal, Activity, Clock, Zap, ArrowRight, ShieldCheck,
  Server, Network, FileText, AlertOctagon, HelpCircle
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { RiskScore } from "@/components/ui/RiskScore";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function AlertDetailPage() {
  const params = useParams();
  const router = useRouter();
  const alertId = Number(params.id);
  const queryClient = useQueryClient();

  const { data: alert, isLoading, error } = useQuery({
    queryKey: ["alert", alertId],
    queryFn: () => api.getAlertById(alertId)
  });

  const { data: assetData } = useQuery({
    queryKey: ["asset", alert?.asset_id],
    queryFn: () => (alert?.asset_id ? api.getAssetById(alert.asset_id) : null),
    enabled: !!alert?.asset_id
  });

  const ackMutation = useMutation({
    mutationFn: () => api.acknowledgeAlert(alertId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alert", alertId] })
  });

  const resolveMutation = useMutation({
    mutationFn: () => api.resolveAlert(alertId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alert", alertId] })
  });

  if (isLoading) {
    return <LoadingState stateText="ANALYZING" message="Loading comprehensive forensic evidence..." />;
  }

  if (error || !alert) {
    return (
      <ErrorState
        title="Alert Not Found"
        message={`Unable to load Alert ID ${alertId}.`}
        onRetry={() => router.push("/alerts")}
      />
    );
  }

  const evidence = alert.evidence || {};
  const isC2 = alert.alert_type === "threat_intel_dns_match" || alert.severity === "critical";

  return (
    <div className="space-y-6">
      {/* Back Navigation */}
      <div>
        <Link href="/alerts" className="inline-flex items-center gap-1.5 text-xs font-mono text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Security Alerts
        </Link>
      </div>

      {/* Header & Quick Action Card */}
      <Card className="border-security-critical/40 bg-surface-primary">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-surface-border">
          <div className="flex items-start gap-3">
            <div className="w-12 h-12 rounded-lg bg-security-critical/10 border border-security-critical/40 flex items-center justify-center text-security-critical">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-text-primary font-mono">{alert.title}</h1>
                <Badge variant={alert.severity}>{alert.severity}</Badge>
                <Badge variant={alert.status === "OPEN" ? "critical" : "verified"}>{alert.status}</Badge>
              </div>
              <div className="text-xs font-mono text-text-muted mt-1 flex flex-wrap items-center gap-3">
                <span>ALERT ID: <strong className="text-text-primary">#{alert.id}</strong></span>
                <span>•</span>
                <span>UUID: <strong className="text-text-secondary">{alert.alert_uuid || "alt-01"}</strong></span>
                <span>•</span>
                <span>CATEGORY: <strong className="text-accent">{alert.alert_type}</strong></span>
                <span>•</span>
                <span>OBSERVED: <strong className="text-text-primary">{formatDate(alert.created_at)}</strong></span>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            {alert.status === "OPEN" && (
              <Button
                variant="secondary"
                size="sm"
                isLoading={ackMutation.isPending}
                onClick={() => ackMutation.mutate()}
              >
                Acknowledge
              </Button>
            )}
            {alert.status !== "RESOLVED" && (
              <Button
                variant="primary"
                size="sm"
                isLoading={resolveMutation.isPending}
                onClick={() => resolveMutation.mutate()}
              >
                <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> Mark Resolved
              </Button>
            )}
            <Link href={`/assets/${alert.asset_id}`}>
              <Button variant="outline" size="sm">
                <Server className="w-3.5 h-3.5 mr-1" /> Device Profile
              </Button>
            </Link>
          </div>
        </div>

        {/* 1. Summary Narrative */}
        <div className="pt-4 space-y-1">
          <div className="text-[11px] font-mono text-text-muted uppercase">Incident Summary</div>
          <p className="text-xs font-mono text-text-secondary leading-relaxed bg-surface-secondary p-3 rounded border border-surface-border">
            {alert.description}
          </p>
        </div>
      </Card>

      {/* 2. Flagship Evidence Chain: "WHY DID THIS ALERT FIRE?" */}
      <Card className="border-accent/40 bg-surface-elevated/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-accent">
            <HelpCircle className="w-4 h-4 text-accent" />
            WHY DID THIS ALERT FIRE? (FORENSIC EVIDENCE CHAIN)
          </CardTitle>
          <span className="text-[11px] font-mono text-text-muted">
            Deterministic rule evaluation based on continuous network observations
          </span>
        </CardHeader>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Baseline Expected */}
          <div className="p-3.5 rounded bg-surface-primary border border-surface-border space-y-2">
            <div className="text-[11px] font-mono text-security-verified font-bold uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" /> 1. Normal Baseline
            </div>
            <div className="text-xs font-mono text-text-secondary space-y-1">
              <div>Allowed Port: <strong className="text-text-primary">554 (RTSP), 443 (HTTPS)</strong></div>
              <div>Approved Host: <strong className="text-text-primary">hik-connect.com</strong></div>
              <div>Normal Flow: <strong className="text-text-primary">Local NVR & Gateway</strong></div>
            </div>
          </div>

          {/* Observed Deviation */}
          <div className="p-3.5 rounded bg-surface-primary border border-security-critical/30 space-y-2">
            <div className="text-[11px] font-mono text-security-critical font-bold uppercase flex items-center gap-1.5">
              <AlertOctagon className="w-3.5 h-3.5" /> 2. Observed Flow
            </div>
            <div className="text-xs font-mono text-text-secondary space-y-1">
              <div>Destination IP: <strong className="text-security-critical">203.0.113.99</strong></div>
              <div>Destination Port: <strong className="text-security-critical">6667 (IRC/C2)</strong></div>
              <div>Resolved Domain: <strong className="text-security-critical">dark-iot-c2.net</strong></div>
            </div>
          </div>

          {/* Difference & PRI Impact */}
          <div className="p-3.5 rounded bg-surface-primary border border-accent/30 space-y-2">
            <div className="text-[11px] font-mono text-accent font-bold uppercase flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" /> 3. Difference & Impact
            </div>
            <div className="text-xs font-mono text-text-secondary space-y-1">
              <div>Behavioral Penalty: <strong className="text-accent">+2.5</strong></div>
              <div>Threat Intel Match: <strong className="text-security-critical">DarkIoT C2 Node</strong></div>
              <div>PRI Escalation: <strong className="text-security-critical">1.9 → 4.4 (Medium)</strong></div>
            </div>
          </div>
        </div>

        {/* Structured Evidence Payload */}
        <div className="mt-4 pt-3 border-t border-surface-border">
          <div className="text-[11px] font-mono text-text-muted uppercase mb-1">Authoritative Sensor Evidence</div>
          <pre className="text-xs font-mono text-accent bg-background p-3 rounded border border-surface-border overflow-x-auto">
            {JSON.stringify(evidence, null, 2)}
          </pre>
        </div>
      </Card>

      {/* 3. Device Context & Containment Recommendation */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Device Profile Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="w-4 h-4 text-text-primary" />
              Target Device Context
            </CardTitle>
          </CardHeader>

          {assetData ? (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-surface-border">
                <span className="text-text-muted">Device Identity:</span>
                <span className="text-text-primary font-semibold">{assetData.vendor} {assetData.model}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-surface-border">
                <span className="text-text-muted">IP Address:</span>
                <span className="text-accent">{assetData.ip_address}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-surface-border">
                <span className="text-text-muted">MAC Address:</span>
                <span className="text-text-primary">{assetData.mac_address}</span>
              </div>
              <div className="flex items-center justify-between pb-2 border-b border-surface-border">
                <span className="text-text-muted">Device Category:</span>
                <Badge variant="outline">{assetData.device_type}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-text-muted">Current PRI:</span>
                <RiskScore score={assetData.current_pri_score} level={assetData.pri_risk_level} size="sm" />
              </div>
            </div>
          ) : (
            <div className="text-xs font-mono text-text-muted py-4">Loading target device profile...</div>
          )}
        </Card>

        {/* Recommended Action & Containment Impact */}
        <Card className="border-l-2 border-l-security-critical">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-security-critical">
              <Zap className="w-4 h-4" />
              Recommended Containment Policy
            </CardTitle>
          </CardHeader>

          <div className="space-y-3 text-xs font-mono">
            <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1.5">
              <div className="text-[11px] text-text-muted font-bold uppercase">Safety Policy: REQUIRE_APPROVAL</div>
              <p className="text-[11px] text-text-secondary leading-relaxed">
                Autonomous blocking is locked. Human approval is required to isolate rogue C2 flows while preserving critical operational traffic.
              </p>
            </div>

            <div className="space-y-1.5 pt-1">
              <div className="text-[11px] text-text-muted uppercase">Operational Impact Preview:</div>
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded bg-security-verified/10 border border-security-verified/30 text-security-verified">
                  ✓ PRESERVED: NTP (123), DNS (53), Local NVR (554)
                </div>
                <div className="p-2 rounded bg-security-critical/10 border border-security-critical/30 text-security-critical">
                  ✗ BLOCKED: Outbound TCP 6667 to 203.0.113.99
                </div>
              </div>
            </div>

            <div className="pt-2">
              <Link href="/containment">
                <Button variant="danger" size="sm" className="w-full">
                  <Zap className="w-3.5 h-3.5 mr-1" /> Review Containment Preview & Approve
                </Button>
              </Link>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
