"""
PrivIoT - Hardened Safe Multi-Protocol Discovery Engine (Phase 1.5)
Enforces formal ScanAuthorizationPolicy, IPv6/IPv4 boundary validation, SSRF protection,
concurrency bounding, and non-destructive active probing.
"""

import ipaddress
import socket
import logging
import time
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Blocked metadata and reserved networks (IPv4 and IPv6)
FORBIDDEN_NETWORKS_V4 = [
    ipaddress.ip_network("169.254.0.0/16"),    # Link-Local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("255.255.255.255/32") # Broadcast
]

DISCOVERY_PORTS_BY_PROFILE = {
    "passive": [],
    "safe": [80, 443, 554, 1883, 8883, 8080, 8443, 23, 22, 1900, 5000, 8000],
    "standard": [80, 443, 554, 1883, 8883, 8080, 8443, 23, 22, 1900, 5000, 8000, 53, 161, 8081, 9999, 37777],
    "deep": [80, 443, 554, 1883, 8883, 8080, 8443, 23, 22, 1900, 5000, 8000, 53, 161, 8081, 9999, 37777, 21, 25, 110, 143, 445, 3389, 5683, 6668]
}


class ScanAuthorizationPolicy:
    """
    Formal Authorization Policy governing allowed and excluded target subnets,
    rate limits, and scan boundaries for a tenant or site.
    """
    def __init__(self, allowed_cidrs: Optional[List[str]] = None, 
                 excluded_cidrs: Optional[List[str]] = None, 
                 max_hosts: int = 4096, 
                 allow_loopback: bool = False):
        self.allowed_networks = [ipaddress.ip_network(c.strip(), strict=False) for c in (allowed_cidrs or [])]
        self.excluded_networks = [ipaddress.ip_network(c.strip(), strict=False) for c in (excluded_cidrs or [])]
        self.max_hosts = max_hosts
        self.allow_loopback = allow_loopback

    def validate_scope(self, scope_str: str) -> Tuple[bool, Optional[str], Optional[List[ipaddress.IPv4Address]]]:
        if not scope_str or not isinstance(scope_str, str):
            return False, "Target scope cannot be empty", None

        scope_clean = scope_str.strip()

        # Reject IPv6 in active network scanner phase
        if ':' in scope_clean:
            return False, "IPv6 scanning is not authorized for this profile (IPv4 only)", None

        try:
            if '/' in scope_clean:
                network = ipaddress.ip_network(scope_clean, strict=False)
            else:
                ip_obj = ipaddress.ip_address(scope_clean)
                network = ipaddress.ip_network(f"{ip_obj}/32", strict=False)

            if not isinstance(network, ipaddress.IPv4Network):
                return False, "Only IPv4 networks are currently supported for active scanning", None

            # 1. Check forbidden SSRF / cloud metadata
            for forbidden in FORBIDDEN_NETWORKS_V4:
                if network.overlaps(forbidden):
                    return False, f"Target network overlaps with forbidden/reserved range: {forbidden}", None

            # 2. Check loopback
            loopback_net = ipaddress.ip_network("127.0.0.0/8")
            if network.overlaps(loopback_net) and not self.allow_loopback:
                return False, "Scanning loopback addresses (127.0.0.0/8) is forbidden", None

            # 3. Check max CIDR size
            if network.prefixlen < 20:
                return False, f"Target scope CIDR /{network.prefixlen} is too large. Maximum allowed size is /20 (4,096 hosts)", None

            # 4. Check explicit policy exclusions
            for excluded in self.excluded_networks:
                if network.overlaps(excluded):
                    return False, f"Target scope overlaps with policy-excluded sensitive network: {excluded}", None

            # 5. Check allowed whitelist if configured
            if self.allowed_networks:
                is_within_allowed = any(network.subnet_of(allowed) for allowed in self.allowed_networks)
                if not is_within_allowed:
                    return False, "Target scope is not within tenant's authorized allowed_cidrs policy", None

            hosts = [network.network_address] if network.num_addresses == 1 else list(network.hosts())
            if not hosts:
                return False, "No valid host addresses in specified scope", None

            return True, None, hosts

        except ValueError as e:
            return False, f"Invalid network scope format: {str(e)}", None


def validate_target_scope(scope_str: str, allow_loopback: bool = False, allowed_cidrs: Optional[List[str]] = None, excluded_cidrs: Optional[List[str]] = None) -> Tuple[bool, Optional[str], Optional[List[ipaddress.IPv4Address]]]:
    """Helper wrapper around ScanAuthorizationPolicy."""
    policy = ScanAuthorizationPolicy(
        allowed_cidrs=allowed_cidrs,
        excluded_cidrs=excluded_cidrs,
        allow_loopback=allow_loopback
    )
    return policy.validate_scope(scope_str)


class SafeDiscoveryEngine:
    """
    Production-grade safe active IoT discovery prober.
    """
    def __init__(self):
        from deep_discovery import discovery_engine
        self.prober = discovery_engine

    def scan_scope(self, scope_str: str, profile: str = "safe", rate_limit: int = 50, concurrency: int = 10, timeout: float = 1.0, allow_loopback: bool = False, allowed_cidrs: Optional[List[str]] = None, excluded_cidrs: Optional[List[str]] = None) -> Dict[str, Any]:
        policy = ScanAuthorizationPolicy(allowed_cidrs=allowed_cidrs, excluded_cidrs=excluded_cidrs, allow_loopback=allow_loopback)
        is_valid, err, host_ips = policy.validate_scope(scope_str)
        if not is_valid:
            raise ValueError(err)

        target_ports = DISCOVERY_PORTS_BY_PROFILE.get(profile.lower(), DISCOVERY_PORTS_BY_PROFILE["safe"])
        discovered_assets = []
        start_time = time.time()

        logger.info(f"Starting {profile.upper()} discovery on scope {scope_str} ({len(host_ips)} hosts, max concurrency={concurrency})")

        def probe_single_host(ip_addr: ipaddress.IPv4Address) -> Optional[Dict[str, Any]]:
            ip_str = str(ip_addr)
            is_live = False
            open_ports = []
            
            for port in target_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    res = sock.connect_ex((ip_str, port))
                    if res == 0:
                        is_live = True
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass
                time.sleep(1.0 / max(1, rate_limit))

            if is_live:
                service_details = self.prober.probe_device_services(ip_str, timeout=timeout)
                service_details["discovered_at"] = time.time()
                return service_details
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, 20)) as executor:
            future_to_ip = {executor.submit(probe_single_host, ip): ip for ip in host_ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                try:
                    res = future.result()
                    if res:
                        discovered_assets.append(res)
                except Exception as e:
                    logger.debug(f"Host probe error: {e}")

        scan_duration = round(time.time() - start_time, 2)
        logger.info(f"Safe discovery completed on {scope_str} in {scan_duration}s. Discovered {len(discovered_assets)} live assets.")

        return {
            "scope": scope_str,
            "profile": profile,
            "scan_duration": scan_duration,
            "hosts_scanned": len(host_ips),
            "discovered_count": len(discovered_assets),
            "discovered_assets": discovered_assets
        }


# Singleton instance
safe_discovery_engine = SafeDiscoveryEngine()
