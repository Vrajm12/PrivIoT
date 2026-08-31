"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Cpu, Building, Radio, Network, Shield, CheckCircle2,
  ArrowRight, ArrowLeft, Terminal, AlertTriangle
} from "lucide-react";
import { api } from "@/lib/api-client";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { StatusIndicator } from "@/components/ui/StatusIndicator";

export default function OnboardingPage() {
  const [currentStep, setCurrentStep] = useState(1);
  const [orgName, setOrgName] = useState("Acme Industrial Corp");
  const [siteName, setSiteName] = useState("Plant Floor Subnet (Site 01)");
  const [networkScope, setNetworkScope] = useState("10.10.1.0/24");
  const [collectorName, setCollectorName] = useState("Plant_Floor_Sensor_01");

  const steps = [
    { num: 1, title: "Organization", icon: Building },
    { num: 2, title: "Site", icon: Network },
    { num: 3, title: "Collector", icon: Radio },
    { num: 4, title: "Network Scope", icon: Terminal },
    { num: 5, title: "Security Policy", icon: Shield },
    { num: 6, title: "Pre-Flight Verification", icon: CheckCircle2 }
  ];

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold font-mono text-text-primary tracking-wide flex items-center gap-2">
          <Cpu className="w-5 h-5 text-accent" />
          CUSTOMER DEPLOYMENT ONBOARDING WIZARD
        </h1>
        <p className="text-xs text-text-secondary">
          Step-by-step enterprise deployment, sensor provisioning & pre-flight network validation.
        </p>
      </div>

      {/* Stepper Progress */}
      <div className="grid grid-cols-6 gap-2 text-xs font-mono">
        {steps.map((s) => {
          const Icon = s.icon;
          const isDone = currentStep > s.num;
          const isCurrent = currentStep === s.num;
          return (
            <div
              key={s.num}
              onClick={() => setCurrentStep(s.num)}
              className={`p-2.5 rounded border flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
                isCurrent
                  ? "bg-accent/10 border-accent text-accent font-bold"
                  : isDone
                  ? "bg-surface-elevated border-security-verified/40 text-security-verified"
                  : "bg-surface-secondary border-surface-border text-text-muted opacity-60"
              }`}
            >
              <Icon className="w-4 h-4 mb-1" />
              <span className="text-[10px] hidden sm:inline">{s.title}</span>
            </div>
          );
        })}
      </div>

      {/* Step Content */}
      <Card className="p-6 font-mono text-xs space-y-6">
        {currentStep === 1 && (
          <div className="space-y-4">
            <div className="text-sm font-bold text-text-primary uppercase">1. Organization & Customer Hierarchy</div>
            <div>
              <label className="block text-text-muted mb-1">ORGANIZATION NAME</label>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>
            <div className="p-3 bg-surface-secondary rounded border border-surface-border text-text-secondary text-[11px]">
              Multi-tenant customer isolation is enforced at the database and memory layers. All assets and telemetry remain strictly scoped.
            </div>
          </div>
        )}

        {currentStep === 2 && (
          <div className="space-y-4">
            <div className="text-sm font-bold text-text-primary uppercase">2. Plant Site Definition</div>
            <div>
              <label className="block text-text-muted mb-1">SITE IDENTIFIER / LOCATION</label>
              <input
                type="text"
                value={siteName}
                onChange={(e) => setSiteName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>
            <div className="p-3 bg-surface-secondary rounded border border-surface-border text-text-secondary text-[11px]">
              Sites allow multi-facility operations without data leakage. Each site maps to dedicated edge sensors.
            </div>
          </div>
        )}

        {currentStep === 3 && (
          <div className="space-y-4">
            <div className="text-sm font-bold text-text-primary uppercase">3. Edge Collector Provisioning</div>
            <div>
              <label className="block text-text-muted mb-1">SENSOR NODE NAME</label>
              <input
                type="text"
                value={collectorName}
                onChange={(e) => setCollectorName(e.target.value)}
                className="w-full px-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>
            <div className="p-3 bg-surface-secondary rounded border border-surface-border space-y-1 text-[11px]">
              <div className="text-accent font-bold">Collector Provisioning Protocol:</div>
              <div className="text-text-secondary">
                Upon enrollment, a single-use SHA-256 pre-shared token is generated. Raw token material is never stored or visible again.
              </div>
            </div>
          </div>
        )}

        {currentStep === 4 && (
          <div className="space-y-4">
            <div className="text-sm font-bold text-text-primary uppercase">4. Network Scope & SPAN Configuration</div>
            <div>
              <label className="block text-text-muted mb-1">MONITORED CIDR SUBNET</label>
              <input
                type="text"
                value={networkScope}
                onChange={(e) => setNetworkScope(e.target.value)}
                className="w-full px-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary"
              />
            </div>
            <div className="p-3 bg-surface-secondary rounded border border-surface-border text-text-secondary text-[11px]">
              The sensor interface connects directly to switch SPAN/mirror ports to ingest passive packets without impacting network latency.
            </div>
          </div>
        )}

        {currentStep === 5 && (
          <div className="space-y-4">
            <div className="text-sm font-bold text-text-primary uppercase">5. Security Policy Defaults</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
                <div className="text-text-muted uppercase">Containment Safety</div>
                <div className="text-security-high font-bold">REQUIRE_APPROVAL</div>
                <div className="text-text-secondary">Zero autonomous blocking permitted</div>
              </div>
              <div className="p-3 rounded bg-surface-secondary border border-surface-border space-y-1">
                <div className="text-text-muted uppercase">Baseline Duration</div>
                <div className="text-text-primary font-bold">48-Hour Learning Window</div>
                <div className="text-text-secondary">Continuous steady-state profiling</div>
              </div>
            </div>
          </div>
        )}

        {currentStep === 6 && (
          <div className="space-y-4">
            <div className="text-sm font-bold text-text-primary uppercase">6. Pre-Flight Visibility Verification</div>
            <div className="space-y-2">
              <div className="flex items-center justify-between p-2.5 rounded bg-surface-secondary border border-surface-border">
                <span>1. Collector Node Connectivity</span>
                <span className="text-security-verified font-bold">PASS (Connected)</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-surface-secondary border border-surface-border">
                <span>2. Switch SPAN Telemetry Ingestion</span>
                <span className="text-security-verified font-bold">PASS (15 events)</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-surface-secondary border border-surface-border">
                <span>3. Asset Auto-Discovery Engine</span>
                <span className="text-security-verified font-bold">PASS (5 assets profiled)</span>
              </div>
              <div className="flex items-center justify-between p-2.5 rounded bg-surface-secondary border border-surface-border">
                <span>4. Safe Flow Preservation Rules</span>
                <span className="text-security-verified font-bold">PASS (NTP/DNS/Gateway protected)</span>
              </div>
            </div>
          </div>
        )}

        {/* Wizard Action Buttons */}
        <div className="flex items-center justify-between pt-4 border-t border-surface-border">
          <Button
            variant="secondary"
            size="sm"
            disabled={currentStep === 1}
            onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
          >
            <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Previous
          </Button>

          {currentStep < 6 ? (
            <Button
              variant="primary"
              size="sm"
              onClick={() => setCurrentStep((prev) => Math.min(6, prev + 1))}
            >
              Next Step <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          ) : (
            <Button
              variant="primary"
              size="sm"
              onClick={() => alert("Customer Onboarding Verified! System is in active continuous observation mode.")}
            >
              <CheckCircle2 className="w-3.5 h-3.5 mr-1" /> Complete & Start Observation
            </Button>
          )}
        </div>
      </Card>
    </div>
  );
}
