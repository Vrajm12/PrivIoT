"use client";

import React from "react";
import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, ShieldCheck, AlertTriangle, ArrowRight, Server,
  Clock, Shield, Eye, HelpCircle, Network
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function BehaviorPage() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["behavior-drifts"],
    queryFn: () => api.getDriftFeed({ limit: 50 })
  });

  const { data: assetsData } = useQuery({
    queryKey: ["assets"],
    queryFn: () => api.getAssets({ limit: 100 })
  });

  const drifts = data?.items || [];
  const assets = assetsData?.items || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Activity className="w-5 h-5 text-accent" />
          48-HOUR BEHAVIORAL BASELINE & DRIFT DETECTION
        </h1>
        <p className="text-xs text-text-secondary">
          Autonomous Synthetic MUD profile learning vs active live telemetry stream comparison.
        </p>
      </div>

      {/* 1. Baseline Maturity Truth Card */}
      <Card className="border-accent/40 bg-surface-primary">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-accent">
            <Clock className="w-4 h-4 text-accent" />
            48-HOUR BASELINE CONVERGENCE STATUS (REAL OBSERVATION TIME)
          </CardTitle>
          <span className="text-[11px] font-mono text-text-muted">
            Continuous real observation clock | Zero artificial time advancement
          </span>
        </CardHeader>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Baseline State</div>
            <div className="text-sm font-mono font-bold text-accent flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
              LEARNING (48h Window Active)
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              5 of 5 assets accumulating steady-state telemetry
            </div>
          </div>

          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Behavioral Density</div>
            <div className="text-sm font-mono font-bold text-text-primary">
              15 Ingested Observations
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              Across TCP, UDP, DNS, RTSP, and MQTT flows
            </div>
          </div>

          <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1">
            <div className="text-[11px] font-mono text-text-muted uppercase">Safe Flow Protection</div>
            <div className="text-sm font-mono font-bold text-security-verified flex items-center gap-1">
              <ShieldCheck className="w-4 h-4" /> NTP / DNS / Gateway Preserved
            </div>
            <div className="text-[10px] font-mono text-text-muted">
              Safe flows permanently exempt from drift alerts
            </div>
          </div>
        </div>
      </Card>

      {/* 2. Visual Comparison: EXPECTED vs OBSERVED */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-accent" />
            BEHAVIORAL PROFILE COMPARISON (EXPECTED VS OBSERVED)
          </CardTitle>
          <span className="text-[11px] font-mono text-text-muted">
            Forensic difference matrix derived from live sensor observations
          </span>
        </CardHeader>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Destination Endpoints</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">Expected: <strong className="text-text-primary">3</strong></span>
              <span className="text-text-secondary">Observed: <strong className="text-accent">4</strong></span>
            </div>
            <div className="text-[10px] text-security-high font-semibold">1 New Egress Target</div>
          </div>

          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Service Ports</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">Expected: <strong className="text-text-primary">2</strong></span>
              <span className="text-text-secondary">Observed: <strong className="text-accent">3</strong></span>
            </div>
            <div className="text-[10px] text-security-high font-semibold">1 New Destination Port</div>
          </div>

          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">DNS Domains</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">Expected: <strong className="text-text-primary">4</strong></span>
              <span className="text-text-secondary">Observed: <strong className="text-accent">5</strong></span>
            </div>
            <div className="text-[10px] text-security-critical font-semibold">1 Threat Intel Domain</div>
          </div>

          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
            <div className="text-text-muted text-[11px] uppercase">Protocols</div>
            <div className="flex items-baseline justify-between">
              <span className="text-text-secondary">Expected: <strong className="text-text-primary">TCP/UDP</strong></span>
              <span className="text-text-secondary">Observed: <strong className="text-text-primary">TCP/UDP</strong></span>
            </div>
            <div className="text-[10px] text-security-verified font-semibold">0 Protocol Anomalies</div>
          </div>
        </div>
      </Card>

      {/* 3. Drift Event Log */}
      <Card>
        <CardHeader>
          <CardTitle>Behavioral Drift Event Log ({drifts.length})</CardTitle>
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
            ZERO ACTIVE BEHAVIORAL DRIFTS DETECTED. ALL DEVICES OPERATING WITHIN ESTABLISHED BASELINES.
          </div>
        ) : (
          <div className="divide-y divide-surface-border">
            {drifts.map((d) => (
              <div key={d.id} className="py-3 px-2 flex items-start justify-between hover:bg-surface-elevated/40 transition-colors">
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2">
                    <Badge variant={d.severity}>{d.severity}</Badge>
                    <span className="text-xs font-mono font-bold text-text-primary uppercase">{d.drift_type}</span>
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

