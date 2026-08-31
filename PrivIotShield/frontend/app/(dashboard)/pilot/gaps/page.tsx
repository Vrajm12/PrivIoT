"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  AlertTriangle, ArrowLeft, Plus, CheckCircle2,
  Shield, Layers, Filter, Clock, Terminal
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function ProductGapsPage() {
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const gapItems = [
    {
      id: "GAP-01",
      title: "Passive mDNS / SSDP Broadcast Ingestion Module",
      severity: "P3",
      category: "DISCOVERY & IDENTITY",
      description: "Generic IoT device classification can be accelerated by capturing local subnet multicast discovery broadcasts.",
      customerImpact: "Enhances initial confidence on unmanaged smart displays and streaming hubs from 35% to > 80%.",
      frequency: "Occurs on ~20% of unmanaged corporate smart office hardware.",
      evidence: "Asset #10 (Generic IoT @ 35% confidence on VLAN 10).",
      status: "TRIAGED",
      owner: "Identity Engine Team"
    },
    {
      id: "GAP-02",
      title: "Third-Party Firewall API Adapter for FortiGate & Palo Alto",
      severity: "P3",
      category: "CONTAINMENT & INTEGRATION",
      description: "Extend micro-segmentation rule dispatching beyond iptables/pfSense to native enterprise next-gen firewalls.",
      customerImpact: "Eliminates manual rule copy-pasting for customers utilizing FortiOS and PAN-OS edge gateways.",
      frequency: "High demand in enterprise multi-site architectures.",
      evidence: "Integration backlog item for Phase H.",
      status: "ROADMAP",
      owner: "Integrations Lead"
    }
  ];

  const filteredGaps = gapItems.filter((g) => {
    if (severityFilter !== "ALL" && g.severity !== severityFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6 max-w-4xl mx-auto font-mono text-xs">
      {/* Back Navigation */}
      <div>
        <Link href="/pilot" className="inline-flex items-center gap-1.5 text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Pilot Command Center
        </Link>
      </div>

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-text-primary tracking-wide flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-accent" />
            PRODUCT GAP & CUSTOMER DEFECT REGISTER
          </h1>
          <p className="text-xs text-text-secondary">
            Rigorous tracking of friction points, missing integrations, and customer-driven product enhancements.
          </p>
        </div>

        <Button variant="secondary" size="sm" onClick={() => alert("New gap entry modal initialized.")}>
          <Plus className="w-3.5 h-3.5 mr-1" /> Log Product Gap
        </Button>
      </div>

      {/* Severity Triage Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="border-l-2 border-l-security-critical">
          <div className="text-[10px] text-text-muted uppercase">P0 Critical Defects</div>
          <div className="text-xl font-bold text-security-verified mt-1">0 Open</div>
          <div className="text-[10px] text-text-muted">Zero Security Flaws</div>
        </Card>

        <Card className="border-l-2 border-l-security-high">
          <div className="text-[10px] text-text-muted uppercase">P1 Pilot Blockers</div>
          <div className="text-xl font-bold text-security-verified mt-1">0 Open</div>
          <div className="text-[10px] text-text-muted">Zero Ingestion Blockers</div>
        </Card>

        <Card className="border-l-2 border-l-accent">
          <div className="text-[10px] text-text-muted uppercase">P2 Workflow Friction</div>
          <div className="text-xl font-bold text-security-verified mt-1">0 Open</div>
          <div className="text-[10px] text-text-muted">Zero Alert Noise Flaws</div>
        </Card>

        <Card className="border-l-2 border-l-text-muted">
          <div className="text-[10px] text-text-muted uppercase">P3 Enhancements</div>
          <div className="text-xl font-bold text-text-primary mt-1">2 Logged</div>
          <div className="text-[10px] text-text-muted">Strategic Roadmap</div>
        </Card>
      </div>

      {/* Gap List */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-xs">Identified Product Gaps & Strategic Items ({filteredGaps.length})</CardTitle>
            <div className="flex items-center gap-1.5 text-[11px]">
              {["ALL", "P0", "P1", "P2", "P3"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-0.5 rounded border transition-colors ${
                    severityFilter === sev
                      ? "bg-accent/10 border-accent text-accent font-bold"
                      : "border-surface-border text-text-muted"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>

        <div className="divide-y divide-surface-border text-xs">
          {filteredGaps.map((gap) => (
            <div key={gap.id} className="p-4 space-y-2 hover:bg-surface-elevated/40 transition-colors">
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <Badge variant={gap.severity === "P0" ? "critical" : gap.severity === "P1" ? "high" : "outline"} size="sm">
                      {gap.severity}
                    </Badge>
                    <span className="font-bold text-text-primary text-xs">{gap.title}</span>
                    <span className="text-[10px] text-text-muted">({gap.id})</span>
                  </div>
                  <div className="text-[10px] text-accent uppercase font-semibold">{gap.category}</div>
                </div>

                <Badge variant="outline" size="sm">
                  {gap.status}
                </Badge>
              </div>

              <p className="text-[11px] text-text-secondary font-sans leading-relaxed">
                {gap.description}
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10px] pt-1">
                <div className="p-2 rounded bg-surface-secondary border border-surface-border">
                  <span className="text-text-muted block">CUSTOMER IMPACT:</span>
                  <span className="text-text-secondary">{gap.customerImpact}</span>
                </div>
                <div className="p-2 rounded bg-surface-secondary border border-surface-border">
                  <span className="text-text-muted block">LINKED PILOT EVIDENCE:</span>
                  <span className="text-text-secondary">{gap.evidence}</span>
                </div>
              </div>

              <div className="flex items-center justify-between text-[10px] text-text-muted pt-1">
                <span>ASSIGNED OWNER: <strong className="text-text-primary">{gap.owner}</strong></span>
                <span>FREQUENCY: <strong className="text-text-secondary">{gap.frequency}</strong></span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
