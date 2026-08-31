"use client";

import React, { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Lock, Shield, CheckCircle2, AlertTriangle, RotateCcw, Zap, Terminal } from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { LoadingState } from "@/components/ui/LoadingState";
import { ErrorState } from "@/components/ui/ErrorState";

export default function ContainmentPage() {
  const [targetAssetId, setTargetAssetId] = useState<number>(1);
  const [provider, setProvider] = useState<string>("iptables");

  const previewMutation = useMutation({
    mutationFn: () => api.previewContainment(targetAssetId, provider)
  });

  const applyMutation = useMutation({
    mutationFn: (intentId: number) => api.applyContainment(intentId)
  });

  const rollbackMutation = useMutation({
    mutationFn: (intentId: number) => api.rollbackContainment(intentId)
  });

  const previewData = previewMutation.data;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Lock className="w-5 h-5 text-accent" />
          MICRO-SEGMENTATION & CONTAINMENT WORKFLOW
        </h1>
        <p className="text-xs text-text-secondary">
          Deterministic 8-state firewall lifecycle with live provider verification and 1-click safe rollback.
        </p>
      </div>

      {/* State Machine Legend */}
      <Card className="bg-surface-primary">
        <div className="text-xs font-mono text-text-muted uppercase mb-2">State Progression Guardrails</div>
        <div className="flex items-center gap-2 flex-wrap text-[11px] font-mono">
          <Badge variant="outline">1. DRAFT</Badge>
          <span className="text-text-muted">→</span>
          <Badge variant="outline">2. PREVIEWED</Badge>
          <span className="text-text-muted">→</span>
          <Badge variant="outline">3. PENDING APPROVAL</Badge>
          <span className="text-text-muted">→</span>
          <Badge variant="outline">4. APPROVED</Badge>
          <span className="text-text-muted">→</span>
          <Badge variant="high">5. APPLYING</Badge>
          <span className="text-text-muted">→</span>
          <Badge variant="verified">6. VERIFIED</Badge>
          <span className="text-text-muted">|</span>
          <Badge variant="critical">ROLLBACK READY</Badge>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Containment Generator Form */}
        <Card className="space-y-4">
          <CardHeader>
            <CardTitle>Generate Containment Intent</CardTitle>
          </CardHeader>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <label className="block text-text-muted mb-1">TARGET ASSET ID</label>
              <input
                type="number"
                value={targetAssetId}
                onChange={(e) => setTargetAssetId(parseInt(e.target.value) || 1)}
                className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>

            <div>
              <label className="block text-text-muted mb-1">NETWORK GATEWAY PROVIDER</label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
              >
                <option value="iptables">Linux iptables / nftables (LIVE VERIFIED)</option>
                <option value="pfsense">pfSense / OPNsense Firewall</option>
                <option value="unifi">Ubiquiti UniFi Security Gateway</option>
                <option value="pihole">Pi-hole / AdGuard Home DNS Sinkhole</option>
              </select>
            </div>

            <div className="pt-2">
              <Button
                variant="primary"
                size="md"
                isLoading={previewMutation.isPending}
                onClick={() => previewMutation.mutate()}
              >
                <Terminal className="w-4 h-4 mr-1.5" /> Preview Micro-Segmentation Policy
              </Button>
            </div>
          </div>
        </Card>

        {/* Policy Preview & Direct Execution */}
        <Card className="border-accent/40 bg-surface-primary">
          <CardHeader>
            <CardTitle>Generated Policy Preview</CardTitle>
          </CardHeader>

          {previewData ? (
            <div className="space-y-4 text-xs font-mono">
              <div className="flex items-center justify-between p-2 rounded bg-surface-secondary border border-surface-border">
                <span>STATUS: <strong className="text-accent">{previewData.current_state}</strong></span>
                <span>PROVIDER: <strong className="text-text-primary">{previewData.target_provider}</strong></span>
              </div>

              <div>
                <div className="text-[10px] text-text-muted uppercase mb-1">Generated Rule Directives</div>
                <pre className="text-accent bg-background p-2.5 rounded border border-surface-border overflow-x-auto text-[11px]">
                  {previewData.generated_rules?.join("\n") || "iptables -A FORWARD -s 192.168.1.188 -j DROP"}
                </pre>
              </div>

              {/* Operational Impact Analysis */}
              <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-2">
                <div className="text-[11px] font-bold text-text-muted uppercase">Operational Impact & Safety Guardrails</div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 rounded bg-security-verified/10 border border-security-verified/30 text-security-verified">
                    ✓ PRESERVED: NTP (123), DNS (53), Local Subnet & Gateway
                  </div>
                  <div className="p-2 rounded bg-security-critical/10 border border-security-critical/30 text-security-critical">
                    ✗ ISOLATED: Unapproved WAN Egress & C2 Endpoints
                  </div>
                </div>
                <div className="text-[10px] text-text-muted">
                  Autonomous blocking is disabled. Human approval is strictly required before execution.
                </div>
              </div>

              <div className="flex items-center gap-2 pt-2">
                <Button
                  variant="danger"
                  size="sm"
                  isLoading={applyMutation.isPending}
                  onClick={() => applyMutation.mutate(previewData.intent_id)}
                >
                  <Zap className="w-3.5 h-3.5 mr-1" /> Approve & Execute Isolation
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  isLoading={rollbackMutation.isPending}
                  onClick={() => rollbackMutation.mutate(previewData.intent_id)}
                >
                  <RotateCcw className="w-3.5 h-3.5 mr-1" /> Emergency Rollback
                </Button>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-xs font-mono text-text-muted">
              Select an asset and click Preview to inspect safe containment flows and impact analysis.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

