# PRIVIOT SHIELD — PILOT OBSERVATION BOUNDARIES & EDGE CASE HANDLING
**Technical Boundaries, Network Edge Cases, and Observation Limitations**  
**Version:** 6.0.0-PILOT  

---

## 1. What PrivIoT Observes vs Observation Limitations

| Network Scenario | PrivIoT Observation Capability | Edge Case Handling & Limitations |
| :--- | :--- | :--- |
| **DHCP IP Churn** | Correlates via hardware MAC address; updates IP on reassignment. | If MAC is obscured by router/NAT, marks historical IP as `reconciliation: stale_ip_reassigned`. |
| **Routed / NAT Subnets** | Observes traffic arriving at collector interface. | Devices behind NAT share gateway MAC; identified by IP and TCP fingerprint heuristics. |
| **Multiple VLANs** | Supported via 802.1Q tagged SPAN / mirror interfaces or distributed multi-collector deployment. | Trunk port must be configured on network switch to mirror tagged frames. |
| **Sleeping / Battery IoT**| Retains asset profile in `OFFLINE / STALE` state after observation timeout without deleting records. | Baselines preserved across sleep cycles; wakes trigger immediate last-seen update. |
| **Encrypted TLS Traffic**| Extracts TLS Server Name Indication (SNI) and DNS query domains without decrypting payloads. | Payload contents remain encrypted; threat intel matches on SNI and DNS C2 domains. |
| **Broadcast / Multicast**| Inspects mDNS (5353) and SSDP (1900) for passive device fingerprinting. | Multicast storm thresholds protect sensor worker queues from exhaustion. |
| **Unknown / Custom IoT** | Categorizes as `Generic IoT Device` with exact numerical confidence (e.g. 35%). | Zero manufactured guesses. Operator can manually tag or leave unclassified. |
