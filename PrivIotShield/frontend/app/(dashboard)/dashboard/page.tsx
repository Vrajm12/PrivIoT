"use client";

import React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldAlert,
  Server,
  Activity,
  AlertTriangle,
  Radio,
  ArrowUpRight,
  ShieldCheck,
  Zap
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { RiskScore } from "@/components/ui/RiskScore";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function DashboardPage() {
  const { data: assetsData, isLoading: assetsLoading, error: assetsError, refetch: refetchAssets } = useQuery({
    queryKey: ["assets"],
    queryFn: () => api.getAssets({ limit: 100 })
  });

  const { data: alertsData, isLoading: alertsLoading, error: alertsError, refetch: refetchAlerts } = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api.getAlerts({ limit: 10 })
  });

  const { data: driftData, isLoading: driftLoading } = useQuery({
    queryKey: ["drifts"],
    queryFn: () => api.getDriftFeed({ limit: 5 })
  });

  const { data: collectorsData, isLoading: collectorsLoading } = useQuery({
    queryKey: ["collectors"],
    queryFn: () => api.getCollectors()
  });

  if (assetsLoading || alertsLoading) {
    return <LoadingState stateText="ANALYZING" message="Aggregating continuous IoT security posture..." />;
  }

  if (assetsError || alertsError) {
    return (
      <ErrorState
        title="Failed to Load SOC Telemetry"
        message="Unable to communicate with the FastAPI control plane. Ensure the backend is active."
        onRetry={() => {
          refetchAssets();
          refetchAlerts();
        }}
      />
    );
  }

  const assets = assetsData?.items || [];
  const alerts = alertsData?.items || [];
  const drifts = driftData?.items || [];
  const collectors = collectorsData?.items || [];

  const criticalCount = assets.filter((a) => a.pri_risk_level === "critical").length;
  const highCount = assets.filter((a) => a.pri_risk_level === "high").length;
  const openAlerts = alerts.filter((a) => a.status === "OPEN").length;
  const driftCount = drifts.length;
  const unhealthyCollectors = collectors.filter((c) => c.status !== "ACTIVE" && c.status !== "online").length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
            SECURITY OPERATIONS DASHBOARD
          </h1>
          <p className="text-xs text-text-secondary">
            Continuous posture monitoring, telemetry ingestion & real-time containment control.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/containment">
            <Button variant="danger" size="sm">
              <Zap className="w-3.5 h-3.5 mr-1" /> Active Containment
            </Button>
          </Link>
          <Link href="/assets">
            <Button variant="secondary" size="sm">
              View All Assets ({assets.length})
            </Button>
          </Link>
        </div>
      </div>

      {/* Pilot Mode Operational Truth Banner */}
      <div className="p-3 bg-surface-elevated border border-surface-border rounded flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <span className="text-text-muted">OBSERVATION STATE:</span>
            <span className="text-accent font-semibold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-accent animate-ping" />
              TRUE PILOT MODE
            </span>
          </div>
          <div className="h-3 w-px bg-surface-border hidden sm:block" />
          <div>
            <span className="text-text-muted">BASELINE: </span>
            <span className="text-text-primary font-semibold">48h Learning Window Active</span>
          </div>
          <div className="h-3 w-px bg-surface-border hidden sm:block" />
          <div>
            <span className="text-text-muted">CONTAINMENT: </span>
            <span className="text-security-high font-semibold">LOCKED (REQUIRE_APPROVAL)</span>
          </div>
        </div>
        <div className="text-[11px] text-text-muted">
          Continuous Network Observation | Zero Autonomous Blocking
        </div>
      </div>

      {/* Critical Actions Viewport */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="border-l-2 border-l-text-muted">
          <div className="text-[11px] font-mono text-text-secondary uppercase">Monitored Assets</div>
          <div className="text-2xl font-mono font-bold text-text-primary mt-1">{assets.length}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">100% Active Fingerprint</div>
        </Card>

        <Card className="border-l-2 border-l-security-critical">
          <div className="text-[11px] font-mono text-text-secondary uppercase">Critical Risk (PRI ≥ 8.0)</div>
          <div className="text-2xl font-mono font-bold text-security-critical mt-1">{criticalCount}</div>
          <div className="text-[10px] text-security-critical mt-1 font-mono">Action Required</div>
        </Card>

        <Card className="border-l-2 border-l-security-high">
          <div className="text-[11px] font-mono text-text-secondary uppercase">High Risk (PRI ≥ 6.0)</div>
          <div className="text-2xl font-mono font-bold text-security-high mt-1">{highCount}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">Elevated Exposure</div>
        </Card>

        <Card className="border-l-2 border-l-security-medium">
          <div className="text-[11px] font-mono text-text-secondary uppercase">Open Security Alerts</div>
          <div className="text-2xl font-mono font-bold text-security-medium mt-1">{openAlerts}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">Deterministic Triggers</div>
        </Card>

        <Card className="border-l-2 border-l-accent">
          <div className="text-[11px] font-mono text-text-secondary uppercase">Behavioral Drifts</div>
          <div className="text-2xl font-mono font-bold text-accent mt-1">{driftCount}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">48h Baseline Deviations</div>
        </Card>
      </div>

      {/* Main Grid: Live Alerts & Behavioral Drift */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Recent Security Alerts */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-security-critical" />
                Active Security Alerts
              </CardTitle>
              <Link href="/alerts" className="text-xs font-mono text-accent hover:underline flex items-center gap-1">
                View All <ArrowUpRight className="w-3 h-3" />
              </Link>
            </CardHeader>

            {alerts.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-text-muted">
                <ShieldCheck className="w-8 h-8 text-security-verified mx-auto mb-2 opacity-80" />
                ZERO ACTIVE SECURITY ALERTS. ENVIRONMENT HEALTHY.
              </div>
            ) : (
              <div className="divide-y divide-surface-border">
                {alerts.slice(0, 5).map((alert) => (
                  <Link
                    key={alert.id}
                    href={`/alerts/${alert.id}`}
                    className="py-3 px-2 flex items-center justify-between hover:bg-surface-elevated/60 transition-colors rounded block"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <Badge variant={alert.severity}>{alert.severity}</Badge>
                        <span className="text-xs font-semibold text-text-primary">{alert.title}</span>
                      </div>
                      <p className="text-[11px] text-text-secondary line-clamp-1">{alert.description}</p>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] font-mono text-text-muted block">
                        {formatDate(alert.created_at)}
                      </span>
                      <span className="text-[10px] font-mono uppercase font-bold text-accent">
                        {alert.status}
                      </span>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>

          {/* High Risk Asset Inventory Snippet */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-security-high" />
                Highest Risk Devices (PRI-v2)
              </CardTitle>
              <Link href="/assets" className="text-xs font-mono text-accent hover:underline flex items-center gap-1">
                Full Inventory <ArrowUpRight className="w-3 h-3" />
              </Link>
            </CardHeader>

            <div className="divide-y divide-surface-border">
              {assets.slice(0, 4).map((asset) => (
                <Link
                  key={asset.id}
                  href={`/assets/${asset.id}`}
                  className="py-2.5 px-2 flex items-center justify-between hover:bg-surface-elevated/60 transition-colors rounded block"
                >
                  <div className="flex items-center gap-3">
                    <div className="space-y-0.5">
                      <div className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                        {asset.vendor} {asset.model}
                        {asset.discovery_source === "esp32_wifi_scan" || asset.discovery_source === "esp32_ble_scan" ? (
                          <span className="px-1.5 py-0.2 rounded bg-security-verified/15 text-security-verified border border-security-verified/40 text-[8px] font-mono font-bold">
                            REAL SENSOR
                          </span>
                        ) : null}
                      </div>
                      <div className="text-[11px] font-mono text-text-muted">
                        {asset.ip_address === "0.0.0.0" ? "Radio/L2" : asset.ip_address} • {asset.mac_address}
                        {asset.hostname && asset.hostname !== "Unknown" && ` • SSID: ${asset.hostname}`}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusIndicator status={asset.behavioral_state === "STABLE" ? "healthy" : "drift"} label={asset.behavioral_state} />
                    <RiskScore score={asset.current_pri_score} level={asset.pri_risk_level} size="sm" />
                  </div>
                </Link>
              ))}
            </div>
          </Card>

            {/* "WHAT CHANGED?" Chronological Operational Feed */}
          <Card className="border-accent/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-accent">
                <Activity className="w-4 h-4 text-accent" />
                WHAT CHANGED? (LIVE OPERATIONAL EVENT FEED)
              </CardTitle>
              <span className="text-[11px] font-mono text-text-muted">
                Authoritative real-time audit trail of all physical sensor security state transitions
              </span>
            </CardHeader>

            <div className="divide-y divide-surface-border font-mono text-xs">
              {alerts.length === 0 && assets.length === 0 ? (
                <div className="py-4 text-center text-xs text-text-muted font-mono">
                  No security events recorded. Physical ESP32 sensor scanning airspace.
                </div>
              ) : (
                <>
                  {alerts.slice(0, 3).map((alert) => (
                    <Link
                      key={alert.id}
                      href={`/alerts/${alert.id}`}
                      className="py-2.5 px-2 flex items-center justify-between hover:bg-surface-elevated/60 transition-colors rounded block"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <Badge variant={alert.severity} size="sm">
                            {alert.alert_type === "open_unencrypted_wifi" ? "AIRSPACE THREAT" : "ALERT"}
                          </Badge>
                          <span className="font-semibold text-text-primary">{alert.title}</span>
                        </div>
                        <div className="text-[11px] text-text-muted">{alert.description}</div>
                      </div>
                      <div className="text-right text-[10px] text-text-muted">
                        <span>{formatDate(alert.created_at)} →</span>
                      </div>
                    </Link>
                  ))}

                  {assets.slice(0, 2).map((asset) => (
                    <Link
                      key={asset.id}
                      href={`/assets/${asset.id}`}
                      className="py-2.5 px-2 flex items-center justify-between hover:bg-surface-elevated/60 transition-colors rounded block"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <Badge variant="verified" size="sm">DISCOVERY</Badge>
                          <span className="font-semibold text-text-primary">
                            Discovered: {asset.hostname || asset.mac_address} ({asset.vendor})
                          </span>
                        </div>
                        <div className="text-[11px] text-text-muted">
                          {asset.mac_address} • RSSI: {asset.rssi ?? -50} dBm • {asset.observation_count ?? 1} Observations
                        </div>
                      </div>
                      <div className="text-right text-[10px] text-text-muted">
                        <span>View Asset →</span>
                      </div>
                    </Link>
                  ))}
                </>
              )}
            </div>
          </Card>
        </div>

        {/* Right Column: Behavioral Drift & Collector Health */}
        <div className="space-y-4">
          {/* Behavioral Drift Feed */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-accent" />
                48h Behavioral Drifts
              </CardTitle>
              <Link href="/behavior" className="text-xs font-mono text-accent hover:underline flex items-center gap-1">
                Live Feed <ArrowUpRight className="w-3 h-3" />
              </Link>
            </CardHeader>

            {drifts.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-text-muted">
                No active behavioral drifts detected in last 48 hours.
              </div>
            ) : (
              <div className="space-y-2.5">
                {drifts.map((d) => (
                  <div key={d.id} className="p-2.5 rounded bg-surface-secondary border border-surface-border text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <Badge variant={d.severity} size="sm">{d.drift_type}</Badge>
                      <span className="text-[10px] font-mono text-text-muted">{formatDate(d.created_at)}</span>
                    </div>
                    <p className="text-[11px] text-text-secondary leading-relaxed">{d.difference}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Collector Sensors */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-accent" />
                Edge Collector Nodes
              </CardTitle>
              <Link href="/collectors" className="text-xs font-mono text-accent hover:underline flex items-center gap-1">
                Manage <ArrowUpRight className="w-3 h-3" />
              </Link>
            </CardHeader>

            <div className="space-y-2">
              {collectors.length === 0 ? (
                <div className="py-4 text-center text-xs font-mono text-text-muted">
                  No collectors registered.
                </div>
              ) : (
                collectors.map((c) => (
                  <div key={c.id} className="flex items-center justify-between p-2 rounded bg-surface-secondary border border-surface-border text-xs font-mono">
                    <div>
                      <div className="text-text-primary font-semibold">{c.collector_name}</div>
                      <div className="text-[10px] text-text-muted">{c.site_id}</div>
                    </div>
                    <div className="text-right">
                      <StatusIndicator
                        status={c.status === "ACTIVE" || c.status === "online" ? "healthy" : "offline"}
                        label={c.status}
                      />
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
