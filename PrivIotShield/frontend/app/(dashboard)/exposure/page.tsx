"use client";

import React, { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Sliders, Shield, Calculator, Info, Zap } from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { RiskScore } from "@/components/ui/RiskScore";
import { Badge } from "@/components/ui/Badge";
import { PriCalculationResult } from "@/types/api";

export default function ExposurePage() {
  const [vendor, setVendor] = useState("Hikvision");
  const [deviceType, setDeviceType] = useState("IP Camera");
  const [cisaKev, setCisaKev] = useState(true);
  const [cvssScore, setCvssScore] = useState(9.8);
  const [epssScore, setEpssScore] = useState(0.85);
  const [exposureFactor, setExposureFactor] = useState("direct_internet");
  const [behavioralPenalty, setBehavioralPenalty] = useState(1.5);

  const priMutation = useMutation({
    mutationFn: () =>
      api.calculatePri({
        vendor,
        device_type: deviceType,
        network_placement: exposureFactor,
        vulnerabilities: [
          {
            cve_id: "CVE-2021-36260",
            cvss_score: cvssScore,
            cisa_kev: cisaKev,
            epss_score: epssScore
          }
        ],
        behavioral_penalties: behavioralPenalty,
        compliance_penalties: 0.0
      })
  });

  const result = priMutation.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Sliders className="w-5 h-5 text-accent" />
          PRI-v2 MATHEMATICAL EXPOSURE SIMULATOR
        </h1>
        <p className="text-xs text-text-secondary">
          Explainable IoT Risk Index: PRI = min(10.0, [(Threat + KEV + EPSS) × E] + B + C).
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Input Parameters Form */}
        <Card className="md:col-span-2 space-y-4">
          <CardHeader>
            <CardTitle>Configurable Risk Multipliers</CardTitle>
          </CardHeader>

          <div className="grid grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="block text-text-muted mb-1">DEVICE VENDOR</label>
              <input
                type="text"
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>
            <div>
              <label className="block text-text-muted mb-1">DEVICE CATEGORY</label>
              <input
                type="text"
                value={deviceType}
                onChange={(e) => setDeviceType(e.target.value)}
                className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>

            <div>
              <label className="block text-text-muted mb-1">CVSS BASE SCORE ({cvssScore})</label>
              <input
                type="range"
                min="0"
                max="10"
                step="0.1"
                value={cvssScore}
                onChange={(e) => setCvssScore(parseFloat(e.target.value))}
                className="w-full accent-accent"
              />
            </div>

            <div>
              <label className="block text-text-muted mb-1">EPSS PROBABILITY ({epssScore})</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={epssScore}
                onChange={(e) => setEpssScore(parseFloat(e.target.value))}
                className="w-full accent-accent"
              />
            </div>

            <div>
              <label className="block text-text-muted mb-1">BEHAVIORAL PENALTY (+{behavioralPenalty})</label>
              <input
                type="range"
                min="0"
                max="3"
                step="0.5"
                value={behavioralPenalty}
                onChange={(e) => setBehavioralPenalty(parseFloat(e.target.value))}
                className="w-full accent-accent"
              />
            </div>

            <div className="flex items-center gap-3 pt-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={cisaKev}
                  onChange={(e) => setCisaKev(e.target.checked)}
                  className="accent-security-critical w-4 h-4 rounded"
                />
                <span className="text-text-primary font-bold">CISA KEV Actively Exploited</span>
              </label>
            </div>
          </div>

          <div className="pt-2">
            <Button
              variant="primary"
              size="md"
              isLoading={priMutation.isPending}
              onClick={() => priMutation.mutate()}
            >
              <Calculator className="w-4 h-4 mr-1.5" /> Execute Deterministic PRI-v2 Formula
            </Button>
          </div>
        </Card>

        {/* Real-time Calculation Result */}
        <Card className="border-accent/40 bg-surface-primary flex flex-col justify-between">
          <div>
            <CardHeader>
              <CardTitle>Calculated PRI Score</CardTitle>
            </CardHeader>

            {result ? (
              <div className="space-y-4 pt-2">
                <div className="text-center p-4 bg-surface-secondary rounded border border-surface-border">
                  <div className="text-4xl font-mono font-bold text-accent">{result.pri_score}</div>
                  <Badge variant={result.risk_level as any} className="mt-2 text-xs">
                    {result.risk_level}
                  </Badge>
                </div>

                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-surface-border/50">
                    <span className="text-text-muted">Threat Base</span>
                    <span className="text-text-primary font-bold">{result.threat_base}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-surface-border/50">
                    <span className="text-text-muted">CISA KEV Boost</span>
                    <span className="text-security-critical font-bold">+{result.cisa_kev_boost}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-surface-border/50">
                    <span className="text-text-muted">EPSS Boost</span>
                    <span className="text-security-high font-bold">+{result.epss_signal}</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-text-muted">Behavioral Penalty</span>
                    <span className="text-accent font-bold">+{result.behavioral_penalties}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-12 text-center text-xs font-mono text-text-muted">
                Click Calculate to trigger mathematical exposure scoring.
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
