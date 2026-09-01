"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Server, Filter, Search, ShieldAlert, Zap, FileSpreadsheet, Download } from "lucide-react";
import { api } from "@/lib/api-client";
import { Asset } from "@/types/models";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { RiskScore } from "@/components/ui/RiskScore";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { DataTable } from "@/components/ui/DataTable";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";
import { exportAssetsToExcelCsv } from "@/lib/export-utils";

export default function AssetsPage() {
  const router = useRouter();
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["assets", severityFilter, searchQuery],
    queryFn: () => api.getAssets({ severity: severityFilter === "all" ? undefined : severityFilter, search: searchQuery || undefined })
  });

  const assets = data?.items || [];

  const columns = [
    {
      header: "DEVICE / VENDOR",
      cell: (item: Asset) => {
        const isEsp32 = item.discovery_source === "esp32_wifi_scan" || item.discovery_source === "esp32_ble_scan" || item.reconciliation_method === "esp32_hardware_scanner" || item.reconciliation_method === "esp32_ble_scanner";
        return (
          <div>
            <div className="font-semibold text-text-primary flex items-center gap-1.5">
              {item.vendor} {item.model}
              {isEsp32 && (
                <span className="px-1.5 py-0.5 rounded bg-security-verified/15 text-security-verified border border-security-verified/40 text-[9px] font-mono font-bold">
                  REAL SENSOR
                </span>
              )}
              {item.first_seen && new Date(item.first_seen).getTime() > Date.now() - 24 * 3600 * 1000 && (
                <Badge variant="accent" size="sm">NEW</Badge>
              )}
            </div>
            <div className="text-[10px] text-text-muted font-mono flex items-center gap-1.5">
              <span>{item.device_type}</span>
              {item.hostname && item.hostname !== "Unknown" && (
                <span className="text-accent font-semibold">({item.hostname})</span>
              )}
            </div>
          </div>
        );
      }
    },
    {
      header: "IP ADDRESS",
      cell: (item: Asset) => (
        <span className="font-mono text-text-primary font-medium">
          {item.ip_address === "0.0.0.0" ? <span className="text-text-muted">Unassigned (L2/Radio)</span> : item.ip_address}
        </span>
      )
    },
    {
      header: "MAC / BSSID",
      cell: (item: Asset) => (
        <div className="font-mono text-[11px] text-text-secondary">
          <div className="font-bold text-text-primary">{item.mac_address}</div>
          <div className="text-[10px] text-text-muted">
            {item.discovery_source === "esp32_wifi_scan" ? "Wi-Fi Scan (ESP32)" : item.discovery_source === "esp32_ble_scan" ? "BLE Scan (ESP32)" : item.network_scope}
          </div>
        </div>
      )
    },
    {
      header: "IDENTITY CONFIDENCE",
      cell: (item: Asset) => {
        const pct = Math.round((item.identity_confidence || 0.5) * 100);
        return (
          <div className="flex items-center gap-2">
            <div className="w-12 bg-surface-elevated rounded-full h-1.5 overflow-hidden border border-surface-border">
              <div
                className={`h-full ${pct >= 80 ? "bg-security-verified" : pct >= 50 ? "bg-security-medium" : "bg-security-critical"}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="font-mono text-[11px] text-text-secondary">{pct}%</span>
          </div>
        );
      }
    },
    {
      header: "PRI-v2 RISK",
      cell: (item: Asset) => (
        <RiskScore score={item.current_pri_score} level={item.pri_risk_level} size="sm" />
      )
    },
    {
      header: "BEHAVIOR",
      cell: (item: Asset) => (
        <StatusIndicator
          status={item.behavioral_state === "STABLE" ? "healthy" : item.behavioral_state === "DRIFT_DETECTED" ? "drift" : "learning"}
          label={item.behavioral_state}
        />
      )
    },
    {
      header: "CONTAINMENT",
      cell: (item: Asset) => (
        <Badge
          variant={item.active_containment_state === "CONTAINED" || item.active_containment_state === "VERIFIED" ? "critical" : "default"}
          size="sm"
        >
          {item.active_containment_state}
        </Badge>
      )
    },
    {
      header: "RADIO / SIGNAL",
      cell: (item: Asset) => (
        <div className="font-mono text-[11px]">
          {item.rssi !== undefined && item.rssi !== null ? (
            <>
              <div className="text-text-primary font-bold">{item.rssi} dBm</div>
              <div className="text-[10px] text-text-muted">Ch {item.channel ?? 1} • {item.observation_count ?? 1} Obs</div>
            </>
          ) : (
            <span className="text-text-muted">N/A</span>
          )}
        </div>
      )
    },
    {
      header: "LAST SEEN",
      cell: (item: Asset) => (
        <span className="font-mono text-[11px] text-text-muted">{formatDate(item.last_seen)}</span>
      )
    }
  ];


  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
            <Server className="w-5 h-5 text-accent" />
            LIVE SECURITY INVENTORY
          </h1>
          <p className="text-xs text-text-secondary">
            Continuous passive discovery, cryptographic fingerprinting and real-time posture index.
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
            <Download className="w-3.5 h-3.5 mr-1" /> Export Excel (CSV)
          </Button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center justify-between gap-4 bg-surface-primary p-3 rounded-lg border border-surface-border">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 absolute left-2.5 top-2 text-text-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter by IP, MAC, Vendor, Model or Type..."
            className="w-full pl-8 pr-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent font-mono"
          />
        </div>

        {/* Severity Filter Pills */}
        <div className="flex items-center gap-1.5 text-xs font-mono">
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

      {/* Table / Content */}
      {isLoading ? (
        <LoadingState stateText="DISCOVERING" message="Querying live asset inventory..." />
      ) : error ? (
        <ErrorState
          title="Error Loading Inventory"
          message="Failed to retrieve devices from FastAPI control plane."
          onRetry={() => refetch()}
        />
      ) : (
        <DataTable
          columns={columns}
          data={assets}
          onRowClick={(asset) => router.push(`/assets/${asset.id}`)}
          emptyMessage="NO REAL ASSETS DISCOVERED — Start the ESP32 scanner to begin discovery."
        />
      )}
    </div>
  );
}
