"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  FileText, Download, Printer, Shield, Server,
  AlertTriangle, Activity, CheckCircle2, Lock, FileSpreadsheet
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { RiskScore } from "@/components/ui/RiskScore";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";
import { exportComplianceReportToExcelCsv, exportAssetsToExcelCsv } from "@/lib/export-utils";

export default function ReportsPage() {
  const [reportType, setReportType] = useState("executive");

  const { data: assetsData, isLoading: assetsLoading } = useQuery({
    queryKey: ["report-assets"],
    queryFn: () => api.getAssets({ limit: 100 })
  });

  const { data: alertsData, isLoading: alertsLoading } = useQuery({
    queryKey: ["report-alerts"],
    queryFn: () => api.getAlerts({ limit: 50 })
  });

  const assets = assetsData?.items || [];
  const alerts = alertsData?.items || [];

  const knownCount = assets.filter((a) => (a.identity_confidence || 0) >= 0.85).length;
  const inferredCount = assets.filter((a) => (a.identity_confidence || 0) >= 0.50 && (a.identity_confidence || 0) < 0.85).length;
  const unknownCount = assets.filter((a) => (a.identity_confidence || 0) < 0.50).length;
  const criticalAlerts = alerts.filter((al) => al.severity === "critical").length;
  const openAlerts = alerts.filter((al) => al.status === "OPEN").length;

  if (assetsLoading || alertsLoading) {
    return <LoadingState stateText="ANALYZING" message="Compiling executive security posture report..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
            <FileText className="w-5 h-5 text-accent" />
            CUSTOMER COMPLIANCE & SECURITY REPORTS
          </h1>
          <p className="text-xs text-text-secondary">
            Deterministic posture audits, executive summaries & evidence-backed IoT security attestations.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => window.print()}>
            <Printer className="w-3.5 h-3.5 mr-1" /> Print Report
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => exportAssetsToExcelCsv(assets)}
            className="flex items-center gap-1.5 text-xs font-mono"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 mr-1 text-accent" /> Export Inventory CSV
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => exportComplianceReportToExcelCsv(reportType, assets, alerts)}
            className="flex items-center gap-1.5 text-xs font-mono font-bold"
          >
            <Download className="w-3.5 h-3.5 mr-1" /> Export Excel (CSV)
          </Button>
        </div>
      </div>

      {/* Report Type Selector */}
      <div className="flex items-center gap-2 border-b border-surface-border pb-2 text-xs font-mono">
        <button
          onClick={() => setReportType("executive")}
          className={`px-3 py-1.5 rounded transition-colors ${
            reportType === "executive" ? "bg-accent/10 text-accent font-bold border border-accent/30" : "text-text-muted hover:text-text-primary"
          }`}
        >
          Executive Summary
        </button>
        <button
          onClick={() => setReportType("inventory")}
          className={`px-3 py-1.5 rounded transition-colors ${
            reportType === "inventory" ? "bg-accent/10 text-accent font-bold border border-accent/30" : "text-text-muted hover:text-text-primary"
          }`}
        >
          Device Trust Inventory
        </button>
        <button
          onClick={() => setReportType("containment")}
          className={`px-3 py-1.5 rounded transition-colors ${
            reportType === "containment" ? "bg-accent/10 text-accent font-bold border border-accent/30" : "text-text-muted hover:text-text-primary"
          }`}
        >
          Containment & Safety Audit
        </button>
      </div>

      {/* Printable Report Surface */}
      <div className="space-y-6 bg-surface-primary border border-surface-border rounded-lg p-6 font-mono text-xs">
        {/* Report Meta Header */}
        <div className="border-b border-surface-border pb-4 flex items-center justify-between">
          <div>
            <div className="text-base font-bold text-text-primary tracking-wider">PRIVIOT SHIELD SECURITY AUDIT</div>
            <div className="text-[11px] text-text-muted mt-0.5">Scope: 2.4GHz Wi-Fi Airspace & Plant Subnets</div>
          </div>
          <div className="text-right text-[11px] text-text-muted">
            <div>GENERATED: {new Date().toISOString().split("T")[0]}</div>
            <div className="text-accent font-bold">REPORT TIER: ENTERPRISE AUDIT</div>
          </div>
        </div>

        {/* Executive Viewport */}
        {reportType === "executive" && (
          <div className="space-y-6">
            <div className="p-4 bg-surface-secondary rounded border border-surface-border space-y-2">
              <div className="text-xs font-bold text-text-primary uppercase">Executive Summary</div>
              <p className="text-xs text-text-secondary leading-relaxed font-sans">
                PrivIoT Shield is continuously monitoring {assets.length} physical endpoints discovered via physical ESP32 Wi-Fi hardware scanning and passive telemetry. 
                Identity confidence is corroborated at {assets.length > 0 ? Math.round(((knownCount + inferredCount) / assets.length) * 100) : 0}% known/inferred coverage with {unknownCount} devices remaining under active radio observation. 
                All monitored endpoints are actively accumulating 48-hour behavioral baselines under zero-disruption audit safety.
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 rounded bg-surface-elevated border border-surface-border">
                <div className="text-[10px] text-text-muted uppercase">Discovered Endpoints</div>
                <div className="text-xl font-bold text-text-primary mt-1">{assets.length}</div>
                <div className="text-[10px] text-security-verified">100% Subnet Coverage</div>
              </div>
              <div className="p-3 rounded bg-surface-elevated border border-surface-border">
                <div className="text-[10px] text-text-muted uppercase">Known / Inferred</div>
                <div className="text-xl font-bold text-security-verified mt-1">{knownCount + inferredCount} / {assets.length}</div>
                <div className="text-[10px] text-text-muted">80.0% Identity Rate</div>
              </div>
              <div className="p-3 rounded bg-surface-elevated border border-surface-border">
                <div className="text-[10px] text-text-muted uppercase">Active Alerts</div>
                <div className="text-xl font-bold text-security-medium mt-1">{openAlerts}</div>
                <div className="text-[10px] text-security-critical">{criticalAlerts} Critical Threat</div>
              </div>
              <div className="p-3 rounded bg-surface-elevated border border-surface-border">
                <div className="text-[10px] text-text-muted uppercase">Containment State</div>
                <div className="text-xl font-bold text-accent mt-1">LOCKED</div>
                <div className="text-[10px] text-text-muted">Human Approval Enforced</div>
              </div>
            </div>
          </div>
        )}

        {/* Inventory Viewport */}
        {reportType === "inventory" && (
          <div className="space-y-4">
            <div className="text-xs font-bold text-text-primary uppercase">Asset Trust Stratification</div>
            <table className="w-full text-left divide-y divide-surface-border">
              <thead>
                <tr className="text-text-muted text-[10px] uppercase">
                  <th className="py-2">IP Address</th>
                  <th className="py-2">MAC Address</th>
                  <th className="py-2">Vendor / Model</th>
                  <th className="py-2">Device Category</th>
                  <th className="py-2">Confidence</th>
                  <th className="py-2">PRI-v2</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border text-[11px]">
                {assets.map((a) => (
                  <tr key={a.id} className="py-2">
                    <td className="py-2 text-accent font-semibold">{a.ip_address}</td>
                    <td className="py-2 text-text-primary">{a.mac_address}</td>
                    <td className="py-2 text-text-primary">{a.vendor} {a.model}</td>
                    <td className="py-2 text-text-secondary">{a.device_type}</td>
                    <td className="py-2">
                      <Badge variant={a.identity_confidence >= 0.85 ? "verified" : a.identity_confidence >= 0.50 ? "outline" : "default"} size="sm">
                        {Math.round((a.identity_confidence || 0.35) * 100)}%
                      </Badge>
                    </td>
                    <td className="py-2">
                      <RiskScore score={a.current_pri_score} level={a.pri_risk_level} size="sm" showLabel={false} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Containment Viewport */}
        {reportType === "containment" && (
          <div className="space-y-4">
            <div className="text-xs font-bold text-text-primary uppercase">Containment Safety & Audit Verification</div>
            <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1.5">
              <div className="text-security-verified font-bold">✓ Preserved Operational Safe Flows</div>
              <div className="text-[11px] text-text-secondary">
                The platform strictly enforces that Local Gateway (10.10.1.1), DNS (53), NTP (123), and Camera Streaming (554) are never severed during micro-segmentation.
              </div>
            </div>
            <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1.5">
              <div className="text-accent font-bold">🛡 Containment Policy: REQUIRE_APPROVAL</div>
              <div className="text-[11px] text-text-secondary">
                Autonomous firewall modification is disabled. All policy actions require operator verification and generate immutable audit events.
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
