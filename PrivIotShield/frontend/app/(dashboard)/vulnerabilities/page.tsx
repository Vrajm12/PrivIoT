"use client";

import React from "react";
import { Flame, ShieldAlert, CheckCircle2, ExternalLink } from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { DataTable } from "@/components/ui/DataTable";

const VULN_CATALOG = [
  {
    id: 1,
    cve_id: "CVE-2021-36260",
    vendor: "Hikvision",
    device: "IP Camera / NVR",
    cvss: 9.8,
    cisa_kev: true,
    epss: 0.94,
    description: "Command injection vulnerability in web server firmware due to unvalidated input.",
    remediation: "Upgrade firmware to version V5.5.800 build 210628 or isolate via micro-segmentation."
  },
  {
    id: 2,
    cve_id: "CVE-2020-25078",
    vendor: "D-Link",
    device: "DCS-2530L / DCS-2670L",
    cvss: 9.8,
    cisa_kev: true,
    epss: 0.89,
    description: "Unauthenticated remote admin password disclosure via /config/getuser.cgi.",
    remediation: "Block external WAN access and replace EOL hardware."
  },
  {
    id: 3,
    cve_id: "CVE-2018-9995",
    vendor: "Dahua / TBK",
    device: "DVR / Surveillance System",
    cvss: 9.8,
    cisa_kev: true,
    epss: 0.91,
    description: "Authentication bypass via cookie spoofing allowing unauthorized video feed extraction.",
    remediation: "Apply vendor patch and restrict management interface to internal subnet."
  }
];

export default function VulnerabilitiesPage() {
  const columns = [
    {
      header: "CVE IDENTIFIER",
      cell: (item: any) => (
        <div className="font-mono">
          <div className="text-security-critical font-bold">{item.cve_id}</div>
          <div className="text-[10px] text-text-muted">{item.vendor} • {item.device}</div>
        </div>
      )
    },
    {
      header: "CVSS / EPSS",
      cell: (item: any) => (
        <div className="font-mono text-xs">
          <div>CVSS: <strong className="text-security-critical">{item.cvss}</strong></div>
          <div className="text-security-high">EPSS: <strong>{Math.round(item.epss * 100)}%</strong></div>
        </div>
      )
    },
    {
      header: "CISA KEV STATUS",
      cell: (item: any) => (
        <Badge variant={item.cisa_kev ? "critical" : "default"}>
          {item.cisa_kev ? "ACTIVELY EXPLOITED" : "MONITORED"}
        </Badge>
      )
    },
    {
      header: "VULNERABILITY SUMMARY & MITIGATION",
      cell: (item: any) => (
        <div className="text-xs space-y-1">
          <p className="text-text-primary line-clamp-1">{item.description}</p>
          <div className="text-[11px] text-accent font-mono">Mitigation: {item.remediation}</div>
        </div>
      )
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Flame className="w-5 h-5 text-security-critical" />
          VULNERABILITY INTELLIGENCE CATALOG
        </h1>
        <p className="text-xs text-text-secondary">
          Integrated CISA Known Exploited Vulnerabilities (KEV), FIRST.org EPSS signals, and device CPE correlation.
        </p>
      </div>

      <DataTable
        columns={columns}
        data={VULN_CATALOG}
      />
    </div>
  );
}
