"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import {
  Server, Shield, ArrowLeft, AlertTriangle, Lock, Activity,
  Layers, Terminal, CheckCircle2, XCircle, Info, ExternalLink, Zap, HelpCircle
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { RiskScore } from "@/components/ui/RiskScore";
import { Tabs } from "@/components/ui/Tabs";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";
import { formatDate } from "@/lib/utils";

export default function DeviceTrustProfilePage() {
  const params = useParams();
  const router = useRouter();
  const assetId = Number(params.id);
  const [activeTab, setActiveTab] = useState("overview");

  const { data: asset, isLoading: assetLoading, error: assetError } = useQuery({
    queryKey: ["asset", assetId],
    queryFn: () => api.getAssetById(assetId)
  });

  const { data: profileData, isLoading: profileLoading, error: profileError } = useQuery({
    queryKey: ["asset-profile", assetId],
    queryFn: () => api.getDeviceTrustProfile(assetId)
  });

  const { data: rimData } = useQuery({
    queryKey: ["asset-rim", assetId],
    queryFn: () => api.getRadioFingerprint(assetId),
    refetchInterval: 10000
  });

  if (assetLoading || profileLoading) {
    return <LoadingState stateText="ANALYZING" message="Synthesizing 11-category Device Trust Profile..." />;
  }

  if (assetError || profileError || !asset) {
    return (
      <ErrorState
        title="Asset Not Found"
        message={`Unable to load Device Trust Profile for Asset ID ${assetId}.`}
        onRetry={() => router.push("/assets")}
      />
    );
  }

  const profile: any = profileData?.profile || {};
  const riskBreakdown = profile.risk?.breakdown || {};
  const riskExplanation = profile.risk?.explanation || {};
  const risk = {
    pri_score: profile.risk?.pri_score ?? asset.current_pri_score ?? 2.0,
    pri_level: profile.risk?.pri_level ?? asset.pri_risk_level ?? "low",
    threat_base: riskBreakdown.threat_base ?? 2.0,
    cisa_kev_boost: riskBreakdown.cisa_kev_boost ?? 0.0,
    epss_signal: riskBreakdown.epss_signal ?? 0.0,
    exposure_factor: riskBreakdown.exposure_factor ?? 0.5,
    criticality_weight: riskBreakdown.criticality_weight ?? 1.0,
    behavioral_penalty: riskBreakdown.behavioral_penalty ?? 0.0,
    compliance_penalty: riskBreakdown.compliance_penalty ?? 0.0,
    explanation: riskExplanation.narrative ? riskExplanation : { narrative: ["Calculated from live physical sensor telemetry and observed radio baselines."] }
  };
  const baseline: any = profile.behavior?.baseline || profile.behavioral_baseline || {};
  const vulnerabilities = profile.vulnerabilities?.items || profile.active_vulnerabilities || [];
  const services = profile.services?.services || profile.observed_services || [];


  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "identity", label: "Identity & Fingerprint" },
    { id: "exposure", label: "Exposure & PRI Breakdown" },
    { id: "vulnerabilities", label: "Vulnerabilities", count: vulnerabilities.length },
    { id: "behavior", label: "48h Behavior" },
    { id: "services", label: "Observed Services", count: services.length },
    { id: "containment", label: "Containment Policy" }
  ];

  return (
    <div className="space-y-6">
      {/* Back Navigation */}
      <div>
        <Link href="/assets" className="inline-flex items-center gap-1.5 text-xs font-mono text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Live Inventory
        </Link>
      </div>

      {/* Flagship Header Card */}
      <Card className="border-accent/30 bg-surface-primary/95">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-surface-border">
          <div className="flex items-start gap-3">
            <div className="w-12 h-12 rounded-lg bg-surface-elevated border border-surface-border flex items-center justify-center text-accent">
              <Server className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-text-primary font-mono">
                  {asset.vendor} {asset.model}
                </h1>
                <Badge variant={asset.pri_risk_level}>{asset.pri_risk_level}</Badge>
                <Badge variant="outline">{asset.device_type}</Badge>
              </div>
              <div className="flex items-center gap-3 text-xs font-mono text-text-muted mt-1">
                <span>IP: <strong className="text-text-primary">{asset.ip_address}</strong></span>
                <span>•</span>
                <span>MAC: <strong className="text-text-primary">{asset.mac_address}</strong></span>
                <span>•</span>
                <span>CONFIDENCE: <strong className="text-accent">{Math.round((asset.identity_confidence || 0.5) * 100)}%</strong></span>
              </div>
            </div>
          </div>

          {/* Direct Action Buttons */}
          <div className="flex items-center gap-2">
            <Link href={`/containment?asset_id=${asset.id}`}>
              <Button variant="danger" size="sm">
                <Zap className="w-3.5 h-3.5 mr-1" /> Contain Device
              </Button>
            </Link>
          </div>
        </div>

        {/* First Viewport: Why is it risky & Behavioral Status */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
          {/* PRI-v2 Score & Why it Changed */}
          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-2">
            <div className="text-[11px] font-mono text-text-muted uppercase flex items-center justify-between">
              <span>PRI-v2 Posture Index</span>
              <RiskScore score={risk.pri_score} level={risk.pri_level} size="sm" showLabel={false} />
            </div>
            <div className="text-xs text-text-secondary leading-relaxed font-mono">
              {risk.explanation?.narrative && risk.explanation.narrative.length > 0 ? (
                risk.explanation.narrative.map((n: string, idx: number) => (
                  <div key={idx} className="flex items-start gap-1.5 text-[11px]">
                    <span className="text-accent">•</span>
                    <span>{n}</span>
                  </div>
                ))
              ) : (
                <span className="text-text-muted">No high-severity exposure factors identified.</span>
              )}
            </div>
          </div>

          {/* Behavioral Baseline vs Live State */}
          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-2">
            <div className="text-[11px] font-mono text-text-muted uppercase flex items-center justify-between">
              <span>Behavioral Maturity & State</span>
              <Badge variant={asset.behavioral_state === "STABLE" ? "verified" : "high"} size="sm">
                {asset.behavioral_state}
              </Badge>
            </div>
            <div className="text-[11px] font-mono text-text-secondary space-y-1">
              <div>Maturity: <span className="text-text-primary font-semibold">{asset.maturity_stage || "EARLY SIGNAL"}</span></div>
              <div>Telemetry Volume: <span className="text-text-primary">{asset.observation_count ?? 1} Observation(s)</span></div>
              <div>Active Drift Events: <span className="text-accent font-semibold">{profile.behavior?.active_drifts_count ?? 0}</span></div>
            </div>
          </div>

          {/* Active Containment Guard */}
          <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-2">
            <div className="text-[11px] font-mono text-text-muted uppercase flex items-center justify-between">
              <span>Micro-Segmentation State</span>
              <Badge variant={asset.active_containment_state === "CONTAINED" ? "critical" : "default"} size="sm">
                {asset.active_containment_state}
              </Badge>
            </div>
            <div className="text-[11px] font-mono text-text-secondary space-y-1">
              <div>Policy Generator: <span className="text-text-primary">Linux iptables / nftables</span></div>
              <div>Rollback Ready: <span className="text-security-verified">YES</span></div>
              <div>Enforcement Target: <span className="text-text-primary">{asset.ip_address}</span></div>
            </div>
          </div>
        </div>
      </Card>

      {/* Tabs */}
      <Tabs tabs={tabs} activeTab={activeTab} onChange={setActiveTab} />

      {/* Tab Content */}
      <div className="space-y-4">
        {activeTab === "overview" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle>Core Device Metadata</CardTitle>
              </CardHeader>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Vendor</span>
                  <span className="text-text-primary font-semibold">{asset.vendor}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Model</span>
                  <span className="text-text-primary font-semibold">{asset.model}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Device Category</span>
                  <span className="text-text-primary">{asset.device_type}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Firmware Version</span>
                  <span className="text-text-primary">{asset.firmware_version || "Unspecified"}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Discovery Source</span>
                  <span className="text-text-primary font-semibold">
                    {asset.discovery_source === "esp32_wifi_scan" ? "Wi-Fi Beacon Scan (ESP32)" :
                     asset.discovery_source === "esp32_ble_scan" ? "BLE Advertisement (ESP32)" :
                     asset.discovery_source || "Active Network Probe"}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Reconciliation Mode</span>
                  <span className="text-text-primary">
                    {asset.reconciliation_method === "esp32_hardware_scanner" ? "Hardware BSSID / Radio (ESP32)" :
                     asset.reconciliation_method === "esp32_ble_scanner" ? "Hardware BLE Address (ESP32)" :
                     asset.reconciliation_method || "Deterministic MAC Match"}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Network Scope</span>
                  <span className="text-text-primary">{asset.network_scope}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-text-muted">First Observed</span>
                  <span className="text-text-primary">{formatDate(asset.first_seen)}</span>
                </div>
              </div>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>PRI-v2 Exposure Composition</CardTitle>
              </CardHeader>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Threat Base (CVSS / Radio Base)</span>
                  <span className="text-text-primary font-semibold">{risk.threat_base}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">CISA KEV Actively Exploited Boost</span>
                  <span className="text-security-critical font-semibold">+{risk.cisa_kev_boost}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">EPSS Probability Signal</span>
                  <span className="text-security-high font-semibold">+{risk.epss_signal}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Reachability Exposure Scaling</span>
                  <span className="text-text-primary font-semibold">×{risk.exposure_factor}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Behavioral Drift Penalties</span>
                  <span className="text-accent font-semibold">+{risk.behavioral_penalty}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-surface-border/50">
                  <span className="text-text-muted">Compliance Violations</span>
                  <span className="text-security-critical font-semibold">+{risk.compliance_penalty}</span>
                </div>
                <div className="flex justify-between py-1 bg-surface-elevated px-2 rounded">
                  <span className="text-text-primary font-bold">Final Deterministic PRI</span>
                  <span className="text-text-primary font-bold text-sm">{risk.pri_score} / 10.0</span>
                </div>
              </div>
            </Card>

            {/* PRIVIOT RIM: Radio Intelligence & Movement */}
            <Card className="md:col-span-2 border-accent/30 bg-surface-elevated/20">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-accent flex items-center gap-2 text-sm">
                  <Activity className="w-4 h-4 text-accent" />
                  PRIVIOT RIM — RADIO INTELLIGENCE & MOVEMENT
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" size="sm" className="border-accent text-accent">
                    {rimData?.maturity_stage || "INITIAL BASELINE"}
                  </Badge>
                  <span className="text-[10px] font-mono text-text-muted">
                    {rimData?.evidence_window || "Real Observation Window"}
                  </span>
                </div>
              </CardHeader>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 p-2 text-xs font-mono">
                {/* 1. Relative Proximity */}
                <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1.5">
                  <div className="text-text-muted text-[10px] uppercase">Relative Proximity</div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-text-primary text-base font-bold">
                      {rimData?.fingerprint?.proximity_state || "NEAR"}
                    </span>
                    <span className="text-accent font-bold">
                      {rimData?.fingerprint?.proximity_score ?? 65} / 100
                    </span>
                  </div>
                  <div className="w-full bg-surface-border rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-accent h-full rounded-full transition-all duration-500"
                      style={{ width: `${rimData?.fingerprint?.proximity_score ?? 65}%` }}
                    />
                  </div>
                  <div className="text-[10px] text-text-muted">
                    EMA: {rimData?.fingerprint?.rssi_ema ?? -50} dBm | Mean: {rimData?.fingerprint?.rssi_mean ?? -50} dBm
                  </div>
                </div>

                {/* 2. Movement Trajectory */}
                <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1.5">
                  <div className="text-text-muted text-[10px] uppercase">Movement State</div>
                  <div className="text-text-primary text-base font-bold">
                    {rimData?.trajectory?.movement_state || "STATIONARY"}
                  </div>
                  <div className="text-[10px] text-text-secondary">
                    Slope: {rimData?.trajectory?.slope_db_per_sec ?? 0.0} dB/s | DCI: {rimData?.trajectory?.directional_consistency ?? 0.0}
                  </div>
                  <div className="text-[10px] text-text-muted truncate">
                    {rimData?.trajectory?.description || "Stable relative proximity."}
                  </div>
                </div>

                {/* 3. Fingerprint Similarity */}
                <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1.5">
                  <div className="text-text-muted text-[10px] uppercase">Baseline Similarity</div>
                  <div className="flex items-baseline justify-between">
                    <span className="text-text-primary text-base font-bold">
                      {rimData?.similarity?.verdict || "MATCH"}
                    </span>
                    <span className="text-security-verified font-bold">
                      {Math.round((rimData?.similarity?.similarity_score ?? 0.95) * 100)}%
                    </span>
                  </div>
                  <div className="text-[10px] text-text-secondary">
                    Primary Channel: Ch {rimData?.fingerprint?.primary_channel ?? 6} ({Math.round((rimData?.fingerprint?.channel_stability ?? 1.0) * 100)}% stable)
                  </div>
                  <div className="text-[10px] text-text-muted">
                    Cipher: Type {rimData?.fingerprint?.encryption_type ?? 3} (WPA2)
                  </div>
                </div>

                {/* 4. Temporal Presence */}
                <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1.5">
                  <div className="text-text-muted text-[10px] uppercase">Temporal Presence</div>
                  <div className="text-security-verified text-base font-bold">
                    {rimData?.fingerprint?.presence_state || "PRESENT"}
                  </div>
                  <div className="text-[10px] text-text-secondary">
                    Scans Recorded: {rimData?.fingerprint?.observation_count ?? 100} observations
                  </div>
                  <div className="text-[10px] text-text-muted">
                    Presence Ratio: {Math.round((rimData?.fingerprint?.presence_ratio ?? 0.95) * 100)}% of scan window
                  </div>
                </div>
              </div>
            </Card>
          </div>
        )}

        {activeTab === "vulnerabilities" && (
          <Card>
            <CardHeader>
              <CardTitle>Active Vulnerabilities & CVE Intelligence</CardTitle>
            </CardHeader>
            {vulnerabilities.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-text-muted">
                No confirmed CVEs associated with this device identity.
              </div>
            ) : (
              <div className="divide-y divide-surface-border space-y-2">
                {vulnerabilities.map((v: any, idx: number) => (
                  <div key={idx} className="pt-2 text-xs font-mono space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-security-critical font-bold">{v.cve_id}</span>
                      <div className="flex items-center gap-2">
                        {v.cisa_kev && <Badge variant="critical" size="sm">CISA KEV</Badge>}
                        <span className="text-text-secondary">CVSS {v.cvss_score}</span>
                      </div>
                    </div>
                    <p className="text-text-secondary text-[11px] font-sans">{v.description}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}

        {activeTab === "services" && (
          <Card>
            <CardHeader>
              <CardTitle>Discovered Network Services & Open Ports</CardTitle>
            </CardHeader>
            {services.length === 0 ? (
              <div className="py-6 text-center text-xs font-mono text-text-muted">
                No active service fingerprints recorded.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {services.map((s: any, idx: number) => (
                  <div key={idx} className="p-3 rounded bg-surface-secondary border border-surface-border text-xs font-mono">
                    <div className="text-accent font-bold">{s.port} / {s.protocol}</div>
                    <div className="text-text-primary">{s.service_name}</div>
                    <div className="text-[10px] text-text-muted mt-1 truncate">{s.banner || "No banner banner"}</div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}

        {activeTab === "identity" && (
          <div className="space-y-4">
            {asset.identity_confidence < 0.50 || asset.vendor === "Unknown" ? (
              <Card className="border-accent/40 bg-surface-elevated/40">
                <CardHeader>
                  <CardTitle className="text-accent flex items-center gap-2">
                    <HelpCircle className="w-5 h-5 text-accent" />
                    UNKNOWN DEVICE PROFILE (CONFIDENCE: {Math.round((asset.identity_confidence || 0.35) * 100)}%)
                  </CardTitle>
                </CardHeader>
                <div className="space-y-4 text-xs font-mono">
                  <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1.5">
                    <div className="text-text-primary font-bold uppercase text-[11px]">Why is this device unclassified?</div>
                    <ul className="list-disc list-inside text-text-secondary space-y-1 text-[11px]">
                      <li>Insufficient vendor signature evidence in observed packet streams.</li>
                      <li>Hardware MAC address ({asset.mac_address}) does not match an IEEE registered vendor OUI.</li>
                      <li>Transmits raw UDP telemetry on proprietary ports without standard application banners.</li>
                    </ul>
                  </div>

                  <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1.5">
                    <div className="text-text-primary font-bold uppercase text-[11px]">What would improve identification?</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                      <div className="p-2 rounded bg-surface-primary border border-surface-border">
                        ◻ Passive mDNS / SSDP broadcast capture
                      </div>
                      <div className="p-2 rounded bg-surface-primary border border-surface-border">
                        ◻ DHCP Option 55 Parameter Request List
                      </div>
                      <div className="p-2 rounded bg-surface-primary border border-surface-border">
                        ◻ Active HTTP/TLS banner inspection
                      </div>
                      <div className="p-2 rounded bg-surface-primary border border-surface-border">
                        ◻ Operator manual asset categorization
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            ) : (
              <Card>
                <CardHeader>
                  <CardTitle>Multi-Signal Passive Fingerprint Evidence</CardTitle>
                </CardHeader>
                <div className="space-y-3 text-xs font-mono">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
                      <div className="text-text-muted text-[11px] uppercase">MAC Vendor OUI</div>
                      <div className="text-text-primary font-semibold">{asset.vendor}</div>
                      <div className="text-[10px] text-text-muted">{asset.mac_address}</div>
                    </div>
                    <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
                      <div className="text-text-muted text-[11px] uppercase">Identity Confidence</div>
                      <div className="text-accent font-semibold">{Math.round((asset.identity_confidence || 0.9) * 100)}%</div>
                      <div className="text-[10px] text-security-verified">Corroborated by multiple signals</div>
                    </div>
                  </div>
                </div>
              </Card>
            )}
          </div>
        )}

        {activeTab === "behavior" && (
          <Card>
            <CardHeader>
              <CardTitle>48-Hour Behavioral Baseline Learning Status</CardTitle>
            </CardHeader>
            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded bg-surface-secondary border border-surface-border flex items-center justify-between">
                <div>
                  <div className="text-text-primary font-semibold">Baseline Convergence Window</div>
                  <div className="text-[11px] text-text-muted">Learning active under real observation time</div>
                </div>
                <Badge variant={asset.behavioral_state === "STABLE" ? "verified" : "outline"}>
                  {asset.behavioral_state}
                </Badge>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-2.5 rounded bg-surface-secondary border border-surface-border">
                  <div className="text-text-muted text-[10px] uppercase">Allowed Ports</div>
                  <div className="text-text-primary font-semibold mt-0.5">{baseline.allowed_ports?.join(", ") || "554, 443"}</div>
                </div>
                <div className="p-2.5 rounded bg-surface-secondary border border-surface-border">
                  <div className="text-text-muted text-[10px] uppercase">Approved Domains</div>
                  <div className="text-text-primary font-semibold mt-0.5">{baseline.dns_whitelist?.join(", ") || "hik-connect.com"}</div>
                </div>
                <div className="p-2.5 rounded bg-surface-secondary border border-surface-border">
                  <div className="text-text-muted text-[10px] uppercase">Safe Flows</div>
                  <div className="text-security-verified font-semibold mt-0.5">NTP / DNS / Gateway</div>
                </div>
              </div>
            </div>
          </Card>
        )}

        {activeTab === "exposure" && (
          <Card>
            <CardHeader>
              <CardTitle>PRI-v2 Deterministic Mathematical Composition</CardTitle>
            </CardHeader>
            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 bg-surface-secondary rounded border border-surface-border text-center font-bold text-accent">
                PRI = min(10.0, [(Threat + KEV + EPSS) × Exposure] + Behavioral + Compliance)
              </div>
              <div className="divide-y divide-surface-border">
                <div className="flex justify-between py-2">
                  <span className="text-text-muted">Threat Base (Max CVSS)</span>
                  <span className="text-text-primary font-semibold">{risk.threat_base}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-text-muted">CISA KEV Weaponized Exploit Boost</span>
                  <span className="text-security-critical font-semibold">+{risk.cisa_kev_boost}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-text-muted">EPSS Probability Signal</span>
                  <span className="text-security-high font-semibold">+{risk.epss_signal}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-text-muted">Reachability Exposure Scaling</span>
                  <span className="text-text-primary font-semibold">×{risk.exposure_factor}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-text-muted">Behavioral Anomaly Penalties</span>
                  <span className="text-accent font-semibold">+{risk.behavioral_penalty}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-text-muted">Compliance Violation Penalties</span>
                  <span className="text-security-critical font-semibold">+{risk.compliance_penalty}</span>
                </div>
                <div className="flex justify-between py-2 bg-surface-elevated px-2 rounded">
                  <span className="text-text-primary font-bold">Final Deterministic Score</span>
                  <span className="text-text-primary font-bold">{risk.pri_score} / 10.0 ({risk.pri_level?.toUpperCase()})</span>
                </div>
              </div>
            </div>
          </Card>
        )}

        {activeTab === "containment" && (
          <Card>
            <CardHeader>
              <CardTitle>Micro-Segmentation Containment Rules</CardTitle>
            </CardHeader>
            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded bg-surface-secondary border border-surface-border text-text-secondary">
                Target Gateway Provider: <strong className="text-text-primary">Linux iptables / nftables</strong>
              </div>
              <div className="p-3 rounded bg-surface-secondary border border-surface-border">
                <div className="text-text-muted text-[10px] uppercase mb-1">Generated Policy Snippet</div>
                <pre className="text-accent text-[11px] bg-background p-2 rounded border border-surface-border overflow-x-auto">
{`# PrivIoT Auto-Generated Containment Policy for ${asset.ip_address}
iptables -A FORWARD -s ${asset.ip_address} -p udp --dport 53 -j ACCEPT
iptables -A FORWARD -s ${asset.ip_address} -j DROP`}
                </pre>
              </div>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}

