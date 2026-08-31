"""
Network Scanner for automatic device detection and fingerprinting
"""
import socket
import logging
import ipaddress
import subprocess
import platform
import re
from datetime import datetime
from typing import List, Dict, Optional
import requests

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Automatically discover and identify devices on the network"""
    
    def __init__(self):
        self.discovered_devices = []
        # OUI (Organizationally Unique Identifier) database for MAC vendor lookup
        self.oui_cache = {}
    
    def scan_network(self, network_range: str = None) -> List[Dict]:
        """
        Scan the network for IoT devices
        
        Args:
            network_range: Network range in CIDR notation (e.g., '192.168.1.0/24')
                          If None, will attempt to detect local network
        
        Returns:
            List of discovered devices with their details
        """
        try:
            if not network_range:
                network_range = self._get_local_network()
            
            logger.info(f"Starting network scan on {network_range}")
            
            devices = []
            
            # Use different scanning methods based on platform
            if platform.system() == "Windows":
                devices = self._scan_network_windows(network_range)
            else:
                devices = self._scan_network_unix(network_range)
            
            # Enrich device information
            for device in devices:
                self._enrich_device_info(device)
            
            self.discovered_devices = devices
            logger.info(f"Network scan complete. Found {len(devices)} devices")
            
            return devices
            
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            return []
    
    def _get_local_network(self) -> str:
        """Detect the local network range"""
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Convert to /24 network
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return network
        except Exception as e:
            logger.error(f"Error detecting local network: {str(e)}")
            return "192.168.1.0/24"  # Default fallback
    
    def _scan_network_windows(self, network_range: str) -> List[Dict]:
        """Scan network on Windows using ARP"""
        devices = []
        
        try:
            # Use arp command to discover devices
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    # Parse ARP table entries
                    # Format: 192.168.1.1      00-11-22-33-44-55     dynamic
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})', line)
                    
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace('-', ':').upper()
                        
                        # Skip local network devices
                        if not ip.endswith('.255') and not ip.endswith('.0'):
                            device = {
                                'ip_address': ip,
                                'mac_address': mac,
                                'hostname': self._get_hostname(ip),
                                'status': 'active',
                                'discovered_at': datetime.now().isoformat()
                            }
                            devices.append(device)
            
            # Additionally try ping sweep for better coverage
            network = ipaddress.ip_network(network_range, strict=False)
            for ip in list(network.hosts())[:50]:  # Limit to first 50 IPs for performance
                ip_str = str(ip)
                if self._is_host_alive(ip_str):
                    # Check if already discovered
                    if not any(d['ip_address'] == ip_str for d in devices):
                        device = {
                            'ip_address': ip_str,
                            'mac_address': self._get_mac_address(ip_str),
                            'hostname': self._get_hostname(ip_str),
                            'status': 'active',
                            'discovered_at': datetime.now().isoformat()
                        }
                        devices.append(device)
        
        except Exception as e:
            logger.error(f"Error in Windows network scan: {str(e)}")
        
        return devices
    
    def _scan_network_unix(self, network_range: str) -> List[Dict]:
        """Scan network on Unix/Linux using ARP and nmap"""
        devices = []
        
        try:
            # Try using arp command
            result = subprocess.run(['arp', '-an'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    # Parse ARP entries
                    match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)', line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).upper()
                        
                        device = {
                            'ip_address': ip,
                            'mac_address': mac,
                            'hostname': self._get_hostname(ip),
                            'status': 'active',
                            'discovered_at': datetime.now().isoformat()
                        }
                        devices.append(device)
        
        except Exception as e:
            logger.error(f"Error in Unix network scan: {str(e)}")
        
        return devices
    
    def _is_host_alive(self, ip: str) -> bool:
        """Check if host is alive using ping"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    timeout=2
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
            
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname for an IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"
    
    def _get_mac_address(self, ip: str) -> str:
        """Get MAC address for an IP using ARP"""
        try:
            # Ping once to populate ARP cache
            self._is_host_alive(ip)
            
            if platform.system() == "Windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
                match = re.search(r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})', result.stdout)
                if match:
                    return match.group(1).replace('-', ':').upper()
            else:
                result = subprocess.run(['arp', ip], capture_output=True, text=True)
                match = re.search(r'([0-9a-fA-F:]+)', result.stdout)
                if match:
                    return match.group(1).upper()
        except Exception:
            pass
        
        return "Unknown"
    
    def _enrich_device_info(self, device: Dict):
        """Enrich device information with manufacturer and device type"""
        try:
            # Get manufacturer from MAC address OUI
            if device.get('mac_address') and device['mac_address'] != "Unknown":
                device['manufacturer'] = self._lookup_mac_vendor(device['mac_address'])
                device['device_type'] = self._guess_device_type(device)
            
            # Detect open ports
            device['open_ports'] = self._scan_common_ports(device['ip_address'])
            
            # Try to detect firmware/version from HTTP headers
            device['firmware_info'] = self._detect_firmware(device['ip_address'])
            
        except Exception as e:
            logger.error(f"Error enriching device info: {str(e)}")
    
    def _lookup_mac_vendor(self, mac_address: str) -> str:
        """Look up manufacturer from MAC address OUI"""
        try:
            # Extract OUI (first 3 octets)
            oui = mac_address.replace(':', '')[:6].upper()
            
            # Check cache first
            if oui in self.oui_cache:
                return self.oui_cache[oui]
            
            # Try online API (with timeout)
            try:
                response = requests.get(
                    f"https://api.macvendors.com/{mac_address}",
                    timeout=2
                )
                if response.status_code == 200:
                    vendor = response.text
                    self.oui_cache[oui] = vendor
                    return vendor
            except Exception:
                pass
            
            # Fallback to local known vendors
            known_vendors = {
                '001122': 'CIMSYS Inc',
                '00D0B7': 'Intel Corporation',
                '0050F2': 'Microsoft',
                '00E04C': 'Realtek',
                '5CF5DA': 'Amazon Technologies Inc.',
                'B827EB': 'Raspberry Pi Foundation',
                '001DC9': 'GOOGLE LLC',
                'F0D1A9': 'Google Inc.',
                '68A86D': 'Espressif Inc.',
                'AC67B2': 'Amazon Technologies Inc.',
                'F00DBE': 'Ubiquiti Networks',
                '5855CA': 'TP-Link Corporation Limited',
                '702D3C': 'Samsung Electronics'
            }
            
            if oui in known_vendors:
                vendor = known_vendors[oui]
                self.oui_cache[oui] = vendor
                return vendor
            
            return "Unknown Manufacturer"
            
        except Exception as e:
            logger.error(f"Error looking up MAC vendor: {str(e)}")
            return "Unknown"
    
    def _guess_device_type(self, device: Dict) -> str:
        """Guess device type based on manufacturer and hostname"""
        manufacturer = device.get('manufacturer', '').lower()
        hostname = device.get('hostname', '').lower()
        
        # IoT device patterns
        if any(term in manufacturer or term in hostname for term in ['amazon', 'echo', 'alexa']):
            return 'Smart Speaker'
        elif any(term in manufacturer or term in hostname for term in ['google', 'nest']):
            return 'Smart Home Device'
        elif any(term in manufacturer or term in hostname for term in ['philips', 'hue']):
            return 'Smart Lighting'
        elif any(term in manufacturer or term in hostname for term in ['ring', 'arlo', 'nest cam']):
            return 'Security Camera'
        elif any(term in manufacturer or term in hostname for term in ['samsung', 'lg', 'smart tv']):
            return 'Smart TV'
        elif any(term in manufacturer or term in hostname for term in ['thermostat', 'ecobee']):
            return 'Smart Thermostat'
        elif 'raspberry' in manufacturer or 'pi' in hostname:
            return 'Single Board Computer'
        elif any(term in manufacturer for term in ['tp-link', 'ubiquiti', 'netgear', 'router']):
            return 'Network Device'
        elif 'espressif' in manufacturer:
            return 'IoT Device (ESP-based)'
        
        return 'Unknown IoT Device'
    
    def _scan_common_ports(self, ip: str, timeout: float = 0.5) -> List[int]:
        """Scan common IoT ports"""
        common_ports = [80, 443, 22, 23, 21, 8080, 8443, 1883, 8883, 5000, 5001]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                pass
        
        return open_ports
    
    def _detect_firmware(self, ip: str) -> Dict:
        """Try to detect firmware version from HTTP headers"""
        firmware_info = {}
        
        for port in [80, 443, 8080]:
            try:
                protocol = 'https' if port == 443 else 'http'
                response = requests.get(
                    f"{protocol}://{ip}:{port}",
                    timeout=2,
                    verify=False,
                    allow_redirects=False
                )
                
                # Extract useful headers
                firmware_info['server'] = response.headers.get('Server', 'Unknown')
                firmware_info['x_powered_by'] = response.headers.get('X-Powered-By', '')
                
                # Try to extract version from HTML
                if 'version' in response.text.lower()[:1000]:
                    version_match = re.search(r'version[:\s]+([0-9.]+)', response.text, re.IGNORECASE)
                    if version_match:
                        firmware_info['detected_version'] = version_match.group(1)
                
                break  # Stop after first successful connection
                
            except Exception:
                continue
        
        return firmware_info


# Global instance
network_scanner = NetworkScanner()
