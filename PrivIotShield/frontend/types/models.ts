export type SecuritySeverity = "critical" | "high" | "medium" | "low" | "verified" | "unknown";

export interface Asset {
  id: number;
  tenant_id: string;
  ip_address: string;
  mac_address: string;
  hostname: string | null;
  vendor: string;
  model: string;
  device_type: string;
  firmware_version: string | null;
  identity_confidence: number;
  discovery_source?: string;
  reconciliation_method?: string;
  network_scope: string;
  is_managed: boolean;
  current_pri_score: number;
  pri_risk_level: SecuritySeverity;
  behavioral_state: "LEARNING" | "STABLE" | "DRIFT_DETECTED" | "REVIEW_REQUIRED";
  active_containment_state: string;
  first_seen: string | null;
  last_seen: string | null;
  rssi?: number | null;
  channel?: number | null;
  observation_count?: number;
  proximity_zone?: string;
  maturity_stage?: "PRELIMINARY" | "DEVELOPING" | "ESTABLISHED" | "MATURE";
  maturity_confidence?: number;
  evidence_window?: string;
}

export interface DeviceTrustProfile {
  asset_id: number;
  tenant_id: string;
  profile: {
    core_identity?: {
      ip_address: string;
      mac_address: string;
      vendor: string;
      model: string;
      device_type: string;
      firmware_version?: string;
      confidence: number;
      reconciliation_method?: string;
    };
    risk_scoring?: {
      pri_score: number;
      pri_level: string;
      threat_base: number;
      cisa_kev_boost: number;
      epss_signal: number;
      exposure_factor: number;
      behavioral_penalty: number;
      compliance_penalty: number;
      explanation?: {
        narrative?: string[];
      };
    };
    behavioral_baseline?: {
      status: string;
      learning_start?: string;
      learning_end?: string;
      allowed_destinations?: string[];
      allowed_ports?: number[];
      allowed_protocols?: string[];
      dns_whitelist?: string[];
    };
    active_containment?: {
      status: string;
      target_provider?: string;
      generated_policy?: string;
      rollback_ready?: boolean;
    };
    active_vulnerabilities?: Array<{
      cve_id: string;
      severity: string;
      cvss_score: number;
      cisa_kev: boolean;
      epss_score: number;
      description: string;
      remediation: string;
    }>;
    observed_services?: Array<{
      port: number;
      protocol: string;
      service_name: string;
      state: string;
      banner?: string;
    }>;
  };
}

export interface Alert {
  id: number;
  alert_uuid: string;
  tenant_id: string;
  asset_id: number | null;
  alert_type: string;
  severity: SecuritySeverity;
  title: string;
  description: string;
  evidence: Record<string, any> | null;
  status: "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "SUPPRESSED";
  created_at: string | null;
  resolved_at: string | null;
}

export interface BehavioralDrift {
  id: number;
  tenant_id: string;
  asset_id: number;
  drift_type: string;
  severity: SecuritySeverity;
  difference: string;
  confidence: number;
  status: string;
  created_at: string | null;
}

export interface Collector {
  id: number;
  collector_uuid: string;
  tenant_id: string;
  collector_name: string;
  site_id: string;
  status: "ACTIVE" | "online" | "offline" | "degraded" | "revoked";
  ingestion_rate: number;
  last_heartbeat: string | null;
  registered_at: string | null;
}

export interface AuditEvent {
  id: number;
  tenant_id: string;
  actor: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  request_id: string | null;
  details: Record<string, any>;
  result: "success" | "failure";
  timestamp: string | null;
}

export interface OperatorProfile {
  id: number;
  username: string;
  email: string;
  role: "viewer" | "analyst" | "operator" | "approver" | "admin";
  tenant_id: string;
  is_active: boolean;
}
