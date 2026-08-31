"use client";

import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { realtimeClient, ConnectionStatus, SecurityEventMessage } from "@/lib/realtime";

export function useRealtimeSOC() {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<ConnectionStatus>(realtimeClient.getStatus());
  const [lastEvent, setLastEvent] = useState<SecurityEventMessage | null>(null);

  useEffect(() => {
    realtimeClient.init(queryClient);

    const unsubStatus = realtimeClient.subscribeStatus((newStatus) => {
      setStatus(newStatus);
    });

    const unsubEvents = realtimeClient.subscribeEvents((event) => {
      setLastEvent(event);
    });

    return () => {
      unsubStatus();
      unsubEvents();
    };
  }, [queryClient]);

  return { status, lastEvent };
}
