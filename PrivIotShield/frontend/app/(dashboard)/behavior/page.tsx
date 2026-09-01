"use client";

import React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, ShieldCheck, AlertTriangle, ArrowRight, Server,
  Clock, Shield, Eye, HelpCircle, Network, Radio, Zap
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function BehaviorPage() {
  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ["behavior-stats"],
    queryFn: () => api.getBehaviorStats(),
    refetchInterval: 10000
  });

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["behavior-drifts"],
    queryFn: () => api.getDriftFeed({ limit: 50 }),
    refetchInterval: 10000
  });

  const { data: assetsData } = useQuery({
    queryKey: ["assets"],
    queryFn: () => api.getAssets({ limit: 100 })
  });

  const drifts = data?.items || [];
  const assets = assetsData?.items || [];
  const stats = statsData || {
    total_real_observations: 0,
    total_assets_monitored: assets.length,
    observation_window_formatted: "0.0 minutes",
    maturity_distribution: { PRELIMINARY: assets.length, DEVELOPING: 0, ESTABLISHED: 0, MATURE: 0 },
    open_drifts_count: drifts.length,
    profile_type: "ESP32 Physical 2.4GHz Airspace Scanner",
    safe_flows_status: "NTP / Gateway Airspace Preserved"
  };

  // Group assets by proximity
  const immediateCount = assets.filter(a => (a.rssi || -100) >= -50).length;
  const nearCount = assets.filter(a => (a.rssi || -100) < -50 && (a.rssi || -100) >= -70).length;
  const distantCount = assets.filter(a => (a.rssi || -100) < -70).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Activity className="w-5 h-5 text-accent" />
          RESEARCH-GRADE RADIO BEHAVIORAL BASELINE & DRIFT PROFILER
        </h1>
        <p className="text-xs text-text-secondary">
          Continuous physical ESP32 2.4GHz radio telemetry learning, signal-strength variance, and explainable anomaly detection.
        </p>
      </div>

      {/* 1. Baseline Maturity Truth Card */}
      <Card className="border-accent/40 bg-surface-primary">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-accent">
            <Clock className="w-4 h-4 text-accent" />
            EVIDENCE-BASED BASELINE MATURITY (OBSERVED PHYSICAL TIME)
          </CardTitle>
          <span className="text-[11px] font-mono text-text-muted">
            Continuous real observation clock | {stats.observation_window_formatted} of accumulated physical telemetry
          </span>
        </CardHeader>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Evidence Duration</div>
            <div className="text-sm font-mono font-bold text-accent flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
              {stats.observation_window_formatted}
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              {stats.total_assets_monitored} active radio endpoints
            </div>
          </div>

          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Telemetry Density</div>
            <div className="text-sm font-mono font-bold text-text-primary">
              {stats.total_real_observations} Ingested Observations
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              Physical ESP32 2.4GHz 802.11 beacons
            </div>
          </div>

          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Maturity Progression</div>
            <div className="text-sm font-mono font-bold text-text-primary flex items-center gap-2">
              <span className="text-accent">{stats.maturity_distribution?.DEVELOPING || 0} Dev</span>
              <span className="text-text-muted">•</span>
              <span className="text-text-secondary">{stats.maturity_distribution?.PRELIMINARY || 0} Prelim</span>
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              Scientific confidence calibrated
            </div>
          </div>

          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Safe Flow Protection</div>
            <div className="text-sm font-mono font-bold text-security-verified flex items-center gap-1">
              <ShieldCheck className="w-4 h-4" /> Airspace Preserved
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              Zero false positives on standard gateways
            </div>
          </div>
        </div>
      </Card>

      {/* 2. Visual Comparison: Radio Telemetry Profile */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-accent" />
            PHYSICAL RADIO-LEVEL BEHAVIORAL PROFILE & PROXIMITY ZONES
          </CardTitle>
          <span className="text-[11px] font-mono text-text-muted">
            Empirical signal-strength and channel distribution derived from physical ESP32 scans
          </span>
        </CardHeader>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Immediate Proximity</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">RSSI &ge; -50 dBm</span>
              <span className="text-lg font-bold text-accent">{immediateCount}</span>
            </div>
            <div className="text-[10px] text-accent font-semibold">&lt; 3m physical range</div>
          </div>

          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Near Range</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">-50 to -70 dBm</span>
              <span className="text-lg font-bold text-text-primary">{nearCount}</span>
            </div>
            <div className="text-[10px] text-text-muted font-semibold">3m - 10m perimeter</div>
          </div>

          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Distant / Border</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">RSSI &lt; -70 dBm</span>
              <span className="text-lg font-bold text-text-secondary">{distantCount}</span>
            </div>
            <div className="text-[10px] text-text-muted font-semibold">&gt; 10m airspace boundary</div>
          </div>

          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Detected Drifts</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">Anomalies</span>
              <span className="text-lg font-bold text-security-high">{drifts.length}</span>
            </div>
            <div className="text-[10px] text-security-high font-semibold">{drifts.length > 0 ? "Explainable events" : "Stable baseline"}</div>
          </div>
        </div>
      </Card>

      {/* 3. Drift Event Log */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-security-high" />
            Behavioral Drift & Radio Anomaly Event Log ({drifts.length})
          </CardTitle>
          <span className="text-[11px] font-mono text-text-muted">
            Explainable deviations: RSSI location shifts, channel hopping, SSID spoofing, encryption downgrades
          </span>
        </CardHeader>

        {isLoading ? (
          <LoadingState stateText="CORRELATING" message="Analyzing telemetry drift stream..." />
        ) : error ? (
          <ErrorState
            title="Failed to Load Drift Events"
            message="Unable to communicate with behavioral engine."
            onRetry={() => refetch()}
          />
        ) : drifts.length === 0 ? (
          <div className="py-8 text-center text-xs font-mono text-text-muted">
            <ShieldCheck className="w-8 h-8 text-security-verified mx-auto mb-2 opacity-80" />
            ZERO ACTIVE BEHAVIORAL DRIFTS DETECTED. ALL WIRELESS ENDPOINTS OPERATING WITHIN ESTABLISHED BASELINES.
          </div>
        ) : (
          <div className="divide-y divide-surface-border">
            {drifts.map((d) => (
              <div key={d.id} className="py-3 px-2 flex items-start justify-between hover:bg-surface-elevated/40 transition-colors">
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2">
                    <Badge variant={d.severity}>{d.severity}</Badge>
                    <span className="text-xs font-mono font-bold text-text-primary uppercase">{d.drift_type.replace('_', ' ')}</span>
                    <Link href={`/assets/${d.asset_id}`} className="text-xs font-mono text-accent hover:underline">
                      Asset #{d.asset_id}
                    </Link>
                  </div>
                  <p className="text-xs font-mono text-text-secondary leading-relaxed bg-surface-secondary p-2 rounded border border-surface-border">
                    {d.difference}
                  </p>
                </div>
                <div className="text-right font-mono text-[11px] text-text-muted">
                  <div>{formatDate(d.created_at)}</div>
                  <div className="text-accent mt-1">CONFIDENCE {Math.round(d.confidence * 100)}%</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
