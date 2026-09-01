/**
 * Typed API Client for PrivIoT FastAPI Control Plane
 */
import {
  Asset, DeviceTrustProfile, Alert, BehavioralDrift, Collector,
  AuditEvent, OperatorProfile
} from "@/types/models";
import {
  AssetListResponse, AlertListResponse, DriftFeedResponse,
  CollectorListResponse, AuditListResponse, PriCalculationResult,
  ContainmentPolicyResponse
} from "@/types/api";

const API_BASE = "/api/v2";

class ApiError extends Error {
  code: string;
  requestId?: string;
  details?: Record<string, any>;

  constructor(message: string, code = "API_ERROR", requestId?: string, details?: Record<string, any>) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

async function fetchJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Tenant-ID": "default_tenant",
    ...((options.headers as Record<string, string>) || {})
  };

  const response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const err = data.error || {};
    throw new ApiError(
      err.message || response.statusText || "Request failed",
      err.code || "HTTP_ERROR",
      err.request_id || response.headers.get("X-Request-ID") || undefined,
      err.details
    );
  }

  return data as T;
}

export const api = {
  // Health
  getLiveness: () => fetchJson<{ status: string }>("/../../health/live"),
  getReadiness: () => fetchJson<{ status: string; dependencies?: Record<string, string> }>("/../../health/ready"),

  // Auth & Profile
  getCurrentUser: () => fetchJson<OperatorProfile>("/auth/me"),

  // Assets
  getAssets: (params?: { search?: string; severity?: string; offset?: number; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.search) query.append("search", params.search);
    if (params?.severity) query.append("severity", params.severity);
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());
    return fetchJson<AssetListResponse>(`/assets?${query.toString()}`);
  },
  getAssetById: (id: number) => fetchJson<Asset>(`/assets/${id}`),
  getDeviceTrustProfile: (id: number) => fetchJson<{ profile: DeviceTrustProfile["profile"] }>(`/assets/${id}/trust-profile`),

  // Alerts
  getAlerts: (params?: { status?: string; severity?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.status) query.append("status", params.status);
    if (params?.severity) query.append("severity", params.severity);
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());
    return fetchJson<AlertListResponse>(`/alerts?${query.toString()}`);
  },
  getAlertById: (id: number) => fetchJson<Alert>(`/alerts/${id}`),
  acknowledgeAlert: (id: number) => fetchJson<{ success: boolean }>(`/alerts/${id}/acknowledge`, { method: "POST" }),
  resolveAlert: (id: number) => fetchJson<{ success: boolean }>(`/alerts/${id}/resolve`, { method: "POST" }),

  // Behavioral Drift
  getDriftFeed: (params?: { severity?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.severity) query.append("severity", params.severity);
    if (params?.limit) query.append("limit", params.limit.toString());
    return fetchJson<DriftFeedResponse>(`/behavior/drift?${query.toString()}`);
  },

  // Exposure & PRI-v2 Calculator
  calculatePri: (payload: {
    vendor?: string;
    model?: string;
    device_type?: string;
    vulnerabilities?: Array<Record<string, any>>;
    network_placement?: string;
    behavioral_penalties?: number;
    compliance_penalties?: number;
  }) => fetchJson<PriCalculationResult>("/exposure/calculate-pri", {
    method: "POST",
    body: JSON.stringify(payload)
  }),

  // Containment
  previewContainment: (assetId: number, provider = "iptables", action = "isolate") =>
    fetchJson<ContainmentPolicyResponse>("/containment/preview", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, target_provider: provider, action })
    }),
  approveContainment: (intentId: number) =>
    fetchJson<{ success: boolean; message: string }>("/containment/approve", {
      method: "POST",
      body: JSON.stringify({ intent_id: intentId })
    }),
  applyContainment: (intentId: number) =>
    fetchJson<{ success: boolean; message: string }>("/containment/apply", {
      method: "POST",
      body: JSON.stringify({ intent_id: intentId })
    }),
  rollbackContainment: (intentId: number) =>
    fetchJson<{ success: boolean; message: string }>("/containment/rollback", {
      method: "POST",
      body: JSON.stringify({ intent_id: intentId })
    }),

  // Collectors
  getCollectors: () => fetchJson<CollectorListResponse>("/collectors"),
  registerCollector: (collectorName: string, siteId = "default_site") =>
    fetchJson<Collector & { raw_token: string }>("/collectors/register", {
      method: "POST",
      body: JSON.stringify({ collector_name: collectorName, site_id: siteId })
    }),

  // Audit Log
  getAuditLogs: (params?: { action?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.action) query.append("action", params.action);
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());
    return fetchJson<AuditListResponse>(`/audit?${query.toString()}`);
  },

  // System Observability
  getSystemHealth: () => fetchJson<{ health: any }>("/system/health"),
  getSystemMetrics: () => fetchJson<any>("/system/metrics"),

  // Behavior Stats & Signal History
  getBehaviorStats: () => fetchJson<{
    total_real_observations: number;
    total_assets_monitored: number;
    observation_window_minutes: number;
    observation_window_formatted: string;
    earliest_observation: string | null;
    latest_observation: string | null;
    maturity_distribution: Record<string, number>;
    open_drifts_count: number;
    profile_type: string;
    safe_flows_status: string;
  }>("/behavior/stats"),
  getSignalHistory: (assetId: number, limit = 50) =>
    fetchJson<{
      asset_id: number;
      mac_address: string;
      total_points: number;
      history: Array<{
        timestamp: string;
        rssi: number | null;
        channel: number | null;
        ssid: string | null;
        encryption_type: number | null;
      }>;
    }>(`/assets/${assetId}/signal-history?limit=${limit}`),

  // PRIVIOT RIM (Radio Intelligence & Movement)
  getRadioFingerprint: (assetId: number) =>
    fetchJson<{
      asset_id: number;
      bssid: string;
      ssid: string;
      fingerprint: Record<string, any>;
      similarity: Record<string, any>;
      trajectory: Record<string, any>;
      maturity_stage: string;
      maturity_confidence: number;
      evidence_window: string;
    }>(`/assets/${assetId}/radio-fingerprint`),

  getProximity: (assetId: number) =>
    fetchJson<{
      asset_id: number;
      bssid: string;
      proximity_score: number;
      proximity_state: string;
      rssi_ema: number;
      rssi_current: number | null;
      rssi_mean: number | null;
      confidence: number;
      scale: string;
      interpretation: string;
    }>(`/assets/${assetId}/proximity`),

  getMovement: (assetId: number) =>
    fetchJson<{
      asset_id: number;
      bssid: string;
      movement_state: string;
      trend: string;
      slope_db_per_sec: number;
      directional_consistency: number;
      window_points: number;
      confidence: number;
      description: string;
    }>(`/assets/${assetId}/movement`)
};

