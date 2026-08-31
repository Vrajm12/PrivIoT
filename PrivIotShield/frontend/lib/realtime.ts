/**
 * PrivIoT Shield — Real-Time SSE Client
 * Manages singleton EventSource connection with exponential backoff and TanStack Query cache invalidation.
 */
import { QueryClient } from "@tanstack/react-query";

export type ConnectionStatus = "LIVE" | "RECONNECTING" | "OFFLINE";

export interface SecurityEventMessage {
  event_id: string;
  event_type: string;
  timestamp: string;
  tenant_id: string;
  site_id: string;
  asset_id?: number | null;
  correlation_id?: string;
  severity?: string;
  payload: Record<string, any>;
}

type StatusListener = (status: ConnectionStatus) => void;
type EventListener = (event: SecurityEventMessage) => void;

class RealtimeClient {
  private eventSource: EventSource | null = null;
  private queryClient: QueryClient | null = null;
  private status: ConnectionStatus = "OFFLINE";
  private statusListeners: Set<StatusListener> = new Set();
  private eventListeners: Set<EventListener> = new Set();
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private maxReconnectDelay = 15000;

  public init(queryClient: QueryClient) {
    this.queryClient = queryClient;
    this.connect();
  }

  public getStatus(): ConnectionStatus {
    return this.status;
  }

  public subscribeStatus(listener: StatusListener): () => void {
    this.statusListeners.add(listener);
    listener(this.status);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  public subscribeEvents(listener: EventListener): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  private setStatus(newStatus: ConnectionStatus) {
    if (this.status !== newStatus) {
      this.status = newStatus;
      this.statusListeners.forEach((fn) => fn(newStatus));
    }
  }

  private connect() {
    if (typeof window === "undefined") return;

    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }

    try {
      this.eventSource = new EventSource("/api/v2/events/stream");

      this.eventSource.onopen = () => {
        this.setStatus("LIVE");
        this.reconnectAttempts = 0;
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }
      };

      this.eventSource.onerror = () => {
        this.setStatus("RECONNECTING");
        this.cleanupAndReconnect();
      };

      // Register Event Handlers
      const handledEvents = [
        "ASSET_DISCOVERED",
        "ASSET_UPDATED",
        "OBSERVATION_RECEIVED",
        "BEHAVIOR_DRIFT_DETECTED",
        "ALERT_CREATED",
        "ALERT_UPDATED",
        "PRI_CHANGED",
        "CONTAINMENT_STATE_CHANGED",
        "COLLECTOR_STATUS_CHANGED"
      ];

      handledEvents.forEach((eventType) => {
        this.eventSource?.addEventListener(eventType, (e: MessageEvent) => {
          try {
            const data: SecurityEventMessage = JSON.parse(e.data);
            this.handleSecurityEvent(data);
          } catch {
            // Non-fatal parse error
          }
        });
      });

    } catch {
      this.setStatus("OFFLINE");
      this.cleanupAndReconnect();
    }
  }

  private handleSecurityEvent(event: SecurityEventMessage) {
    // Notify custom event listeners
    this.eventListeners.forEach((fn) => fn(event));

    if (!this.queryClient) return;

    // Intelligent React Query Cache Invalidation
    switch (event.event_type) {
      case "ASSET_DISCOVERED":
      case "ASSET_UPDATED":
        this.queryClient.invalidateQueries({ queryKey: ["assets"] });
        break;

      case "ALERT_CREATED":
      case "ALERT_UPDATED":
        this.queryClient.invalidateQueries({ queryKey: ["alerts"] });
        break;

      case "BEHAVIOR_DRIFT_DETECTED":
        this.queryClient.invalidateQueries({ queryKey: ["drifts"] });
        this.queryClient.invalidateQueries({ queryKey: ["behavior-drifts"] });
        if (event.asset_id) {
          this.queryClient.invalidateQueries({ queryKey: ["asset-profile", event.asset_id] });
        }
        break;

      case "PRI_CHANGED":
      case "CONTAINMENT_STATE_CHANGED":
        if (event.asset_id) {
          this.queryClient.invalidateQueries({ queryKey: ["asset", event.asset_id] });
          this.queryClient.invalidateQueries({ queryKey: ["asset-profile", event.asset_id] });
        }
        this.queryClient.invalidateQueries({ queryKey: ["assets"] });
        break;

      case "COLLECTOR_STATUS_CHANGED":
        this.queryClient.invalidateQueries({ queryKey: ["collectors"] });
        break;

      default:
        break;
    }
  }

  private cleanupAndReconnect() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }

    if (this.reconnectTimer) return;

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), this.maxReconnectDelay);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}

export const realtimeClient = new RealtimeClient();
