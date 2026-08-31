import { Asset, Alert, BehavioralDrift, Collector, AuditEvent, DeviceTrustProfile } from "./models";

export interface ApiResponse<T> {
  data?: T;
  error?: {
    code: string;
    message: string;
    request_id: string;
    details?: Record<string, any>;
  };
}

export interface AssetListResponse {
  items: Asset[];
  total_count: number;
}

export interface AlertListResponse {
  items: Alert[];
  total_count: number;
}

export interface DriftFeedResponse {
  items: BehavioralDrift[];
  total_count: number;
}

export interface CollectorListResponse {
  items: Collector[];
  total_count: number;
}

export interface AuditListResponse {
  items: AuditEvent[];
  total_count: number;
}

export interface PriCalculationResult {
  pri_score: number;
  risk_level: string;
  threat_base: number;
  cisa_kev_boost: number;
  epss_signal: number;
  exposure_factor: number;
  behavioral_penalties: number;
  compliance_penalties: number;
  explainability: {
    formula?: string;
    narrative?: string[];
    components?: Record<string, any>;
  };
}

export interface ContainmentPolicyResponse {
  intent_id: number;
  asset_id: number;
  tenant_id: string;
  target_provider: string;
  current_state: string;
  verification_state: string;
  generated_rules: string[];
  safe_flows_preserved: string[];
  rollback_ready: boolean;
  created_at: string | null;
}
