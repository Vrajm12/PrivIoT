import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { SecuritySeverity } from "@/types/models";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(dateString: string | null | undefined): string {
  if (!dateString) return "Never";
  try {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(date);
  } catch {
    return dateString;
  }
}

export function getSeverityColor(severity: string | undefined): {
  bg: string;
  text: string;
  border: string;
  glow: string;
} {
  const sev = (severity || "low").toLowerCase();
  switch (sev) {
    case "critical":
      return {
        bg: "bg-security-critical/10",
        text: "text-security-critical",
        border: "border-security-critical/30",
        glow: "shadow-[0_0_10px_rgba(255,77,95,0.2)]"
      };
    case "high":
      return {
        bg: "bg-security-high/10",
        text: "text-security-high",
        border: "border-security-high/30",
        glow: "shadow-[0_0_10px_rgba(255,138,61,0.2)]"
      };
    case "medium":
      return {
        bg: "bg-security-medium/10",
        text: "text-security-medium",
        border: "border-security-medium/30",
        glow: "shadow-[0_0_10px_rgba(245,196,81,0.2)]"
      };
    case "low":
      return {
        bg: "bg-security-low/10",
        text: "text-security-low",
        border: "border-security-low/30",
        glow: "shadow-[0_0_10px_rgba(127,167,255,0.2)]"
      };
    case "verified":
    case "stable":
    case "active":
      return {
        bg: "bg-security-verified/10",
        text: "text-security-verified",
        border: "border-security-verified/30",
        glow: "shadow-[0_0_10px_rgba(69,212,131,0.2)]"
      };
    default:
      return {
        bg: "bg-security-unknown/10",
        text: "text-security-unknown",
        border: "border-security-unknown/30",
        glow: "none"
      };
  }
}
