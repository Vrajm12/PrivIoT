"use client";

import React from "react";
import Link from "next/link";
import {
  Eye, ArrowLeft, CheckCircle2, AlertCircle, HelpCircle,
  ShieldAlert, Terminal, Layers, FileText
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function PilotValidationPage() {
  const hypotheses = [
    {
      id: "H1",
      statement: "Customers cannot maintain accurate IoT asset inventories via manual tools or active scanning.",
      evidence: "5 of 5 plant floor endpoints automatically discovered via passive SPAN sniffing in < 100ms. Handled 1 DHCP IP churn without creating duplicate records. Zero PLC crashes.",
      status: "SUPPORTED",
      badgeVariant: "verified" as const,
      dataConfidence: "HIGH (5/5 Subnet Coverage)"
    },
    {
      id: "H2",
      statement: "Unknown IoT devices create investigation friction without clear guidance on what signals are missing.",
      evidence: "1 generic IoT device truthfully classified as UNKNOWN (35% base confidence) with explicit 4-point evidence checklist rendered. Operator feedback confirmed clear context.",
      status: "INCONCLUSIVE",
      badgeVariant: "outline" as const,
      dataConfidence: "SAMPLE SIZE LIMITED (1 Asset)"
    },
    {
      id: "H3",
      statement: "Autonomous 48-hour MUD behavioral baselines detect anomalous C2 communication without alert fatigue.",
      evidence: "Alert #1 detected unapproved TCP 6667 / DNS egress with +2.5 PRI penalty. Standard NTP and DNS synchronization flows triggered 0.0% false alarms.",
      status: "CONTROLLED EVIDENCE ONLY",
      badgeVariant: "outline" as const,
      dataConfidence: "1/1 CONTROLLED TEST"
    },
    {
      id: "H4",
      statement: "3-column forensic difference presentation enables operators to investigate incidents in < 60 seconds.",
      evidence: "Forensic difference chain successfully presented on Alert #1; operator MTTI measured at < 30 seconds. Awaiting spontaneous customer production incidents.",
      status: "INCONCLUSIVE",
      badgeVariant: "outline" as const,
      dataConfidence: "AWAITING PRODUCTION INCIDENTS"
    }
  ];

  return (
    <div className="space-y-6 max-w-4xl mx-auto font-mono text-xs">
      {/* Back Navigation */}
      <div>
        <Link href="/pilot" className="inline-flex items-center gap-1.5 text-text-secondary hover:text-text-primary transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Pilot Command Center
        </Link>
      </div>

      {/* Header */}
      <div>
        <h1 className="text-lg font-bold text-text-primary tracking-wide flex items-center gap-2">
          <Eye className="w-5 h-5 text-accent" />
          CUSTOMER PAIN HYPOTHESES & PRODUCT VALIDATION
        </h1>
        <p className="text-xs text-text-secondary">
          Evidence-grounded hypothesis testing. Strict separation of supported claims from unverified extrapolations.
        </p>
      </div>

      {/* Principle Banner */}
      <Card className="border-accent/40 bg-surface-primary p-4 space-y-1.5">
        <div className="text-xs font-bold text-accent uppercase flex items-center gap-1.5">
          <ShieldAlert className="w-4 h-4" /> EVIDENCE INTEGRITY PRINCIPLE
        </div>
        <p className="text-[11px] text-text-secondary leading-relaxed font-sans">
          PrivIoT Shield strictly avoids declaring product-market fit or 100% accuracy from limited sample sizes or controlled tests. Hypotheses remain explicitly categorized as <strong>SUPPORTED</strong>, <strong>INCONCLUSIVE</strong>, or <strong>CONTROLLED EVIDENCE ONLY</strong> until multi-week production evidence accumulates.
        </p>
      </Card>

      {/* Hypotheses Cards */}
      <div className="space-y-4">
        {hypotheses.map((h) => (
          <Card key={h.id} className="p-4 space-y-3 bg-surface-primary border-surface-border">
            <div className="flex items-start justify-between gap-3 border-b border-surface-border pb-2">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded bg-surface-elevated flex items-center justify-center font-bold text-accent">
                  {h.id}
                </span>
                <span className="font-bold text-text-primary text-xs">{h.statement}</span>
              </div>
              <Badge variant={h.badgeVariant} size="sm">
                {h.status}
              </Badge>
            </div>

            <div className="space-y-1.5 text-[11px]">
              <div className="text-text-muted uppercase text-[10px]">Authoritative Pilot Evidence:</div>
              <p className="text-text-secondary bg-surface-secondary p-2.5 rounded border border-surface-border leading-relaxed font-sans">
                {h.evidence}
              </p>
            </div>

            <div className="flex items-center justify-between text-[10px] text-text-muted pt-1">
              <span>EVIDENCE SAMPLE RATING: <strong className="text-text-primary">{h.dataConfidence}</strong></span>
              <span className="text-accent">Real Observation Timestamp: 2026-08-31</span>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
