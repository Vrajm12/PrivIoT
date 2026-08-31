"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  MessageSquare, ArrowLeft, Send, CheckCircle2,
  Shield, ThumbsUp, Minus, ThumbsDown, HelpCircle
} from "lucide-react";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function PilotFeedbackPage() {
  const [assessment, setAssessment] = useState<"HELPED" | "NEUTRAL" | "HURT">("HELPED");
  const [workflow, setWorkflow] = useState("INVESTIGATION");
  const [screen, setScreen] = useState("/alerts/[id]");
  const [category, setCategory] = useState("ALERTING");
  const [reason, setReason] = useState("BETTER_DEVICE_CONTEXT");
  const [explanation, setExplanation] = useState("The 3-column forensic difference clearly identified unapproved C2 egress without needing raw packet PCAP analysis.");
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
  };

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
          <MessageSquare className="w-5 h-5 text-accent" />
          OPERATOR FEEDBACK & WORKFLOW FRICTION LOG
        </h1>
        <p className="text-xs text-text-secondary">
          Structured operational feedback capturing workflow utility, friction points, and explainability ratings.
        </p>
      </div>

      {submitted ? (
        <Card className="p-8 text-center space-y-3 bg-surface-primary border-security-verified/40">
          <CheckCircle2 className="w-12 h-12 text-security-verified mx-auto" />
          <div className="text-sm font-bold text-text-primary">
            OPERATIONAL FEEDBACK RECORDED & AUDITED
          </div>
          <p className="text-xs text-text-secondary max-w-md mx-auto">
            Your evaluation has been immutably associated with tenant telemetry and forwarded to the product gap queue.
          </p>
          <div className="pt-2">
            <Link href="/pilot">
              <Button variant="primary" size="sm">
                Return to Pilot Command Center
              </Button>
            </Link>
          </div>
        </Card>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* 1. Assessment Selector */}
          <Card className="space-y-4">
            <CardHeader>
              <CardTitle className="text-xs">1. How did PrivIoT Shield impact this investigation or task?</CardTitle>
            </CardHeader>

            <div className="grid grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setAssessment("HELPED")}
                className={`p-3 rounded border text-center transition-all ${
                  assessment === "HELPED"
                    ? "bg-security-verified/10 border-security-verified text-security-verified font-bold"
                    : "bg-surface-secondary border-surface-border text-text-muted"
                }`}
              >
                <ThumbsUp className="w-4 h-4 mx-auto mb-1" />
                <span>HELPED</span>
              </button>

              <button
                type="button"
                onClick={() => setAssessment("NEUTRAL")}
                className={`p-3 rounded border text-center transition-all ${
                  assessment === "NEUTRAL"
                    ? "bg-accent/10 border-accent text-accent font-bold"
                    : "bg-surface-secondary border-surface-border text-text-muted"
                }`}
              >
                <Minus className="w-4 h-4 mx-auto mb-1" />
                <span>NEUTRAL</span>
              </button>

              <button
                type="button"
                onClick={() => setAssessment("HURT")}
                className={`p-3 rounded border text-center transition-all ${
                  assessment === "HURT"
                    ? "bg-security-critical/10 border-security-critical text-security-critical font-bold"
                    : "bg-surface-secondary border-surface-border text-text-muted"
                }`}
              >
                <ThumbsDown className="w-4 h-4 mx-auto mb-1" />
                <span>HURT</span>
              </button>
            </div>
          </Card>

          {/* 2. Context & Categorization */}
          <Card className="space-y-4">
            <CardHeader>
              <CardTitle className="text-xs">2. Operational Context & Categorization</CardTitle>
            </CardHeader>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-text-muted mb-1">OPERATIONAL CATEGORY</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
                >
                  <option value="DISCOVERY">DISCOVERY</option>
                  <option value="IDENTITY">IDENTITY</option>
                  <option value="BEHAVIOR">BEHAVIOR</option>
                  <option value="ALERTING">ALERTING</option>
                  <option value="INVESTIGATION">INVESTIGATION</option>
                  <option value="CONTAINMENT">CONTAINMENT</option>
                  <option value="REPORTING">REPORTING</option>
                  <option value="ONBOARDING">ONBOARDING</option>
                  <option value="PERFORMANCE">PERFORMANCE</option>
                </select>
              </div>

              <div>
                <label className="block text-text-muted mb-1">WORKFLOW STAGE</label>
                <select
                  value={workflow}
                  onChange={(e) => setWorkflow(e.target.value)}
                  className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
                >
                  <option value="TRIAGE">ALERT TRIAGE</option>
                  <option value="INVESTIGATION">FORENSIC INVESTIGATION</option>
                  <option value="CONTAINMENT_PREVIEW">CONTAINMENT PREVIEW</option>
                  <option value="APPROVAL">APPROVAL GATE</option>
                  <option value="VERIFICATION">RULE VERIFICATION</option>
                  <option value="ROLLBACK">EMERGENCY ROLLBACK</option>
                </select>
              </div>

              <div>
                <label className="block text-text-muted mb-1">SOC SCREEN ROUTE</label>
                <input
                  type="text"
                  value={screen}
                  onChange={(e) => setScreen(e.target.value)}
                  className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
                />
              </div>
            </div>

            <div>
              <label className="block text-text-muted mb-1">PRIMARY DRIVER / REASON</label>
              <select
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="w-full px-3 py-1.5 bg-surface-secondary border border-surface-border rounded text-text-primary"
              >
                <option value="FASTER_VISIBILITY">Faster Visibility</option>
                <option value="BETTER_DEVICE_CONTEXT">Better Device Context</option>
                <option value="CLEAR_EVIDENCE">Clear 3-Column Evidence</option>
                <option value="SAFE_CONTAINMENT">Safe Flow Preservation</option>
                <option value="NOISE_REDUCTION">Low False Positives</option>
                <option value="MISSING_INFORMATION">Missing Telemetry Information</option>
                <option value="WORKFLOW_FRICTION">Workflow Friction</option>
              </select>
            </div>

            <div>
              <label className="block text-text-muted mb-1">FREE-TEXT EXPLANATION</label>
              <textarea
                rows={3}
                value={explanation}
                onChange={(e) => setExplanation(e.target.value)}
                className="w-full px-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary leading-relaxed"
              />
            </div>
          </Card>

          {/* Submit */}
          <div className="flex justify-end">
            <Button variant="primary" size="md" type="submit">
              <Send className="w-4 h-4 mr-1.5" /> Submit Structured Feedback
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}
