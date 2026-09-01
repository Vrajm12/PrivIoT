"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Server, Shield, Filter, Search, ArrowRight,
  ShieldAlert, Activity, CheckCircle2, HelpCircle, Download, FileSpreadsheet
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
import { exportAssetsToExcelCsv } from "@/lib/export-utils";

export default function FleetPage() {
  const [siteFilter, setSiteFilter] = useState("all");
  const [identityFilter, setIdentityFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");

  const { data: assetsData, isLoading, error, refetch } = useQuery({
    queryKey: ["fleet-assets"],
    queryFn: () => api.getAssets({ limit: 100 })
  });

  const assets = assetsData?.items || [];

  const filteredAssets = assets.filter((a) => {
    if (siteFilter !== "all" && (a as any).site_id !== siteFilter) return false;
    if (identityFilter === "known" && (a.identity_confidence || 0) < 0.85) return false;
    if (identityFilter === "inferred" && ((a.identity_confidence || 0) >= 0.85 || (a.identity_confidence || 0) < 0.50)) return false;
    if (identityFilter === "unknown" && (a.identity_confidence || 0) >= 0.50) return false;
    if (riskFilter === "critical" && a.pri_risk_level !== "critical") return false;
    if (riskFilter === "high" && a.pri_risk_level !== "high" && a.pri_risk_level !== "critical") return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const match =
        a.ip_address.toLowerCase().includes(q) ||
        a.mac_address.toLowerCase().includes(q) ||
        (a.vendor || "").toLowerCase().includes(q) ||
        (a.model || "").toLowerCase().includes(q) ||
        (a.device_type || "").toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const knownCount = assets.filter((a) => (a.identity_confidence || 0) >= 0.85).length;
  const inferredCount = assets.filter((a) => (a.identity_confidence || 0) >= 0.50 && (a.identity_confidence || 0) < 0.85).length;
  const unknownCount = assets.filter((a) => (a.identity_confidence || 0) < 0.50).length;
  const criticalCount = assets.filter((a) => a.pri_risk_level === "critical" || a.pri_risk_level === "high").length;

  if (isLoading) {
    return <LoadingState stateText="ANALYZING" message="Loading enterprise fleet telemetry..." />;
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to Load Fleet"
        message="Unable to communicate with the FastAPI control plane."
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
            <Server className="w-5 h-5 text-accent" />
            ENTERPRISE FLEET OPERATIONS & TRIAGE
          </h1>
          <p className="text-xs text-text-secondary">
            Multi-site asset inventory, identity confidence stratification & cross-fleet risk filtering.
          </p>
        </div>

        <div>
          <Button
            variant="primary"
            size="sm"
            onClick={() => exportAssetsToExcelCsv(assets)}
            disabled={assets.length === 0}
            className="flex items-center gap-1.5 font-mono text-xs font-bold"
          >
            <Download className="w-3.5 h-3.5 mr-1" /> Export Fleet (CSV)
          </Button>
        </div>
      </div>

      {/* Fleet Metrics Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card className="border-l-2 border-l-text-muted">
          <div className="text-[11px] font-mono text-text-muted uppercase">Total Fleet Size</div>
          <div className="text-2xl font-mono font-bold text-text-primary mt-1">{assets.length}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">Continuous Auto-Discovery</div>
        </Card>

        <Card className="border-l-2 border-l-security-verified">
          <div className="text-[11px] font-mono text-text-muted uppercase">Known Devices (≥85%)</div>
          <div className="text-2xl font-mono font-bold text-security-verified mt-1">{knownCount}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">Multi-Signal Corroborated</div>
        </Card>

        <Card className="border-l-2 border-l-accent">
          <div className="text-[11px] font-mono text-text-muted uppercase">Inferred Devices</div>
          <div className="text-2xl font-mono font-bold text-accent mt-1">{inferredCount}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">Behavioral Heuristics</div>
        </Card>

        <Card className="border-l-2 border-l-security-critical">
          <div className="text-[11px] font-mono text-text-muted uppercase">High/Critical Risk</div>
          <div className="text-2xl font-mono font-bold text-security-critical mt-1">{criticalCount}</div>
          <div className="text-[10px] text-text-muted mt-1 font-mono">Actionable Exposure</div>
        </Card>
      </div>

      {/* Filter Toolbar */}
      <Card className="p-3 bg-surface-primary">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs font-mono">
          <div>
            <label className="block text-text-muted mb-1">SEARCH ASSETS</label>
            <input
              type="text"
              placeholder="Filter IP, MAC, Vendor, Type..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
            />
          </div>

          <div>
            <label className="block text-text-muted mb-1">IDENTITY STATE</label>
            <select
              value={identityFilter}
              onChange={(e) => setIdentityFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
            >
              <option value="all">All Identities ({assets.length})</option>
              <option value="known">Known Only ({knownCount})</option>
              <option value="inferred">Inferred Only ({inferredCount})</option>
              <option value="unknown">Unknown Only ({unknownCount})</option>
            </select>
          </div>

          <div>
            <label className="block text-text-muted mb-1">RISK TIER</label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical (PRI ≥ 8.0)</option>
              <option value="high">High & Critical (PRI ≥ 6.0)</option>
            </select>
          </div>

          <div>
            <label className="block text-text-muted mb-1">SITE SCOPE</label>
            <select
              value={siteFilter}
              onChange={(e) => setSiteFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
            >
              <option value="all">All Plant Sites</option>
              <option value="site_plant_pune">Pune Plant (Site 01)</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Fleet Inventory Table */}
      <Card>
        <CardHeader>
          <CardTitle>Matching Fleet Endpoints ({filteredAssets.length})</CardTitle>
        </CardHeader>

        <div className="divide-y divide-surface-border font-mono text-xs">
          {filteredAssets.length === 0 ? (
            <div className="py-12 text-center text-text-muted">
              NO REAL ASSETS DISCOVERED — Start the ESP32 scanner to begin discovery.
            </div>
          ) : (
            filteredAssets.map((asset) => {
              const isEsp32 = asset.discovery_source === "esp32_wifi_scan" || asset.discovery_source === "esp32_ble_scan" || asset.reconciliation_method === "esp32_hardware_scanner" || asset.reconciliation_method === "esp32_ble_scanner";
              return (
                <Link
                  key={asset.id}
                  href={`/assets/${asset.id}`}
                  className="py-3 px-3 flex items-center justify-between hover:bg-surface-elevated/60 transition-colors block"
                >
                  <div className="flex items-center gap-4">
                    <div className="w-8 h-8 rounded bg-surface-elevated flex items-center justify-center text-accent">
                      <Server className="w-4 h-4" />
                    </div>
                    <div className="space-y-0.5">
                      <div className="font-semibold text-text-primary flex items-center gap-2">
                        <span>{asset.vendor} {asset.model}</span>
                        {isEsp32 && (
                          <span className="px-1.5 py-0.5 rounded bg-security-verified/15 text-security-verified border border-security-verified/40 text-[9px] font-mono font-bold">
                            REAL SENSOR
                          </span>
                        )}
                        <Badge variant={asset.identity_confidence >= 0.85 ? "verified" : asset.identity_confidence >= 0.50 ? "outline" : "default"} size="sm">
                          {asset.identity_confidence >= 0.85 ? "KNOWN" : asset.identity_confidence >= 0.50 ? "INFERRED" : "UNKNOWN"} ({Math.round((asset.identity_confidence || 0.35) * 100)}%)
                        </Badge>
                      </div>
                      <div className="text-[11px] text-text-muted flex flex-wrap items-center gap-1.5">
                        <span>{asset.ip_address === "0.0.0.0" ? "L2/Radio AP" : asset.ip_address}</span>
                        <span>•</span>
                        <span className="text-text-secondary font-mono">{asset.mac_address}</span>
                        <span>•</span>
                        <span>{asset.device_type}</span>
                        {asset.hostname && asset.hostname !== "Unknown" && (
                          <>
                            <span>•</span>
                            <span className="text-accent font-semibold">SSID: {asset.hostname}</span>
                          </>
                        )}
                        {asset.rssi !== undefined && asset.rssi !== null && (
                          <>
                            <span>•</span>
                            <span className="text-text-primary font-mono font-bold">RSSI: {asset.rssi} dBm</span>
                          </>
                        )}
                        {asset.channel !== undefined && asset.channel !== null && (
                          <>
                            <span>•</span>
                            <span className="text-text-muted font-mono">Ch {asset.channel}</span>
                          </>
                        )}
                        {asset.observation_count !== undefined && asset.observation_count > 0 && (
                          <>
                            <span>•</span>
                            <span className="text-accent font-mono">{asset.observation_count} Obs</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-right">
                    <div>
                      <div className="text-[10px] text-text-muted uppercase">48h Baseline</div>
                      <StatusIndicator status={asset.behavioral_state === "STABLE" ? "healthy" : "drift"} label={asset.behavioral_state} />
                    </div>
                    <div>
                      <div className="text-[10px] text-text-muted uppercase">PRI-v2</div>
                      <RiskScore score={asset.current_pri_score} level={asset.pri_risk_level} size="sm" />
                    </div>
                  </div>
                </Link>
              );
            })
          )}
        </div>
      </Card>
    </div>
  );
}
