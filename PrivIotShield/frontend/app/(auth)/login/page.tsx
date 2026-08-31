"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import {
  ShieldAlert, Lock, User, Key, CheckCircle2, ArrowRight,
  ShieldCheck, AlertCircle, Cpu, Radio
} from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("secops_admin");
  const [password, setPassword] = useState("admin123");
  const [role, setRole] = useState("ADMIN");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    setTimeout(() => {
      if (username && password) {
        localStorage.setItem("user", JSON.stringify({ username, role }));
        localStorage.setItem("auth_token", "secops-token-" + Date.now());
        router.push("/dashboard");
      } else {
        setError("Please enter valid credentials.");
        setIsLoading(false);
      }
    }, 600);
  };

  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 font-mono text-xs select-none">
      {/* Background Ambience */}
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-accent/10 border border-accent text-accent mb-2">
            <ShieldAlert className="w-7 h-7" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-text-primary">
            PRIVIOT <span className="text-accent">SHIELD</span>
          </h1>
          <p className="text-xs text-text-muted">
            Continuous IoT Security Operations Platform • Enterprise SOC v4.0
          </p>
        </div>

        {/* Login Form Card */}
        <Card className="p-6 bg-surface-primary border-surface-border space-y-5 shadow-2xl">
          <div className="border-b border-surface-border pb-3 flex items-center justify-between">
            <div className="text-xs font-bold text-text-primary uppercase flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-accent" /> OPERATOR AUTHENTICATION
            </div>
            <Badge variant="verified">SOC ONLINE</Badge>
          </div>

          {error && (
            <div className="p-2.5 rounded bg-security-critical/15 border border-security-critical/40 text-security-critical text-[11px] flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-text-muted mb-1 text-[11px]">OPERATOR USERNAME</label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-2.5 text-text-muted" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary focus:outline-none focus:border-accent font-mono"
                  placeholder="e.g. secops_admin"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-text-muted mb-1 text-[11px]">SECRET PASSKEY / TOKEN</label>
              <div className="relative">
                <Key className="w-4 h-4 absolute left-3 top-2.5 text-text-muted" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary focus:outline-none focus:border-accent font-mono"
                  placeholder="••••••••••••"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-text-muted mb-1 text-[11px]">ASSIGNED RBAC ROLE</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full px-3 py-2 bg-surface-secondary border border-surface-border rounded text-text-primary focus:outline-none focus:border-accent font-mono"
              >
                <option value="ADMIN">ADMIN (Full Control & Containment)</option>
                <option value="APPROVER">APPROVER (Containment Authorization)</option>
                <option value="OPERATOR">OPERATOR (Triage & Monitoring)</option>
                <option value="VIEWER">VIEWER (Read-Only Forensics)</option>
              </select>
            </div>

            <Button
              variant="primary"
              size="md"
              type="submit"
              className="w-full justify-center mt-2 font-bold tracking-wide"
              disabled={isLoading}
            >
              {isLoading ? "AUTHENTICATING..." : "ENTER SOC COMMAND CENTER"}
              {!isLoading && <ArrowRight className="w-4 h-4 ml-1.5" />}
            </Button>
          </form>

          {/* Preset Quick Login Credentials */}
          <div className="pt-2 border-t border-surface-border text-[10px] text-text-muted space-y-1">
            <div className="font-semibold text-text-secondary">DEFAULT TEST CREDENTIALS:</div>
            <div className="grid grid-cols-2 gap-1 text-[9px] font-mono">
              <div className="p-1.5 rounded bg-surface-secondary border border-surface-border">
                <span className="text-accent block">ADMIN:</span> secops_admin / admin123
              </div>
              <div className="p-1.5 rounded bg-surface-secondary border border-surface-border">
                <span className="text-security-verified block">OPERATOR:</span> operator / operator123
              </div>
            </div>
          </div>
        </Card>

        {/* Footer info */}
        <div className="text-center text-[10px] text-text-muted">
          Protected by PrivIoT Multi-Tenant Enclave • PRI-v2 Deterministic Risk Engine
        </div>
      </div>
    </div>
  );
}
