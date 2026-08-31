"use client";

import React from "react";
import { Building, Network, Shield, ArrowRight, Server, Activity } from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";

const SITES_DATA = [
  {
    id: "site-01",
    name: "Pune Manufacturing Plant (HQ)",
    scope: "192.168.1.0/24",
    devices: 24,
    critical_risk: 3,
    status: "ACTIVE",
    collectors: 2
  },
  {
    id: "site-02",
    name: "Bengaluru R&D Lab",
    scope: "10.0.1.0/24",
    devices: 15,
    critical_risk: 0,
    status: "ACTIVE",
    collectors: 1
  },
  {
    id: "site-03",
    name: "Mumbai Logistics Hub",
    scope: "172.16.10.0/24",
    devices: 8,
    critical_risk: 1,
    status: "ACTIVE",
    collectors: 1
  }
];

export default function SitesPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Building className="w-5 h-5 text-accent" />
          MULTI-SITE HIERARCHY & POSTURE TRIAGE
        </h1>
        <p className="text-xs text-text-secondary">
          Global enterprise and MSSP tenant hierarchy with localized subnet scopes and risk aggregation.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {SITES_DATA.map((site) => (
          <Card key={site.id} className="hover:border-accent/40 transition-colors">
            <CardHeader>
              <CardTitle className="text-xs">{site.name}</CardTitle>
              <Badge variant="verified" size="sm">{site.status}</Badge>
            </CardHeader>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-surface-border/50">
                <span className="text-text-muted">Network Scope</span>
                <span className="text-text-primary">{site.scope}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-surface-border/50">
                <span className="text-text-muted">Discovered Devices</span>
                <span className="text-text-primary font-bold">{site.devices}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-surface-border/50">
                <span className="text-text-muted">Critical Assets (PRI ≥ 8.0)</span>
                <span className={site.critical_risk > 0 ? "text-security-critical font-bold" : "text-security-verified"}>
                  {site.critical_risk}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-text-muted">Edge Collectors</span>
                <span className="text-accent">{site.collectors} Online</span>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
