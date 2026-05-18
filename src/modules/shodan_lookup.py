"""
Shodan network intelligence lookup
"""

import socket
from typing import Dict, Any
from .base_module import BaseModule

class ShodanLookup(BaseModule):
    """Gathers network intelligence using Shodan API"""
    
    def __init__(self, target: str, api_key: str = None):
        super().__init__(target)
        self.api_key = api_key
        self.shodan_api_url = "https://api.shodan.io"
    
    def collect(self) -> Dict[str, Dict[str, Any]]:
        """Collect network intelligence from Shodan"""
        self.logger.info(f"Starting Shodan lookup for {self.target}")
        
        shodan_data = {}
        
        try:
            # Get IP address for domain
            ip_address = socket.gethostbyname(self.target)
            
            if self.api_key:
                # Real Shodan API lookup
                shodan_data = self._query_shodan_api(ip_address)
            else:
                # Simulate Shodan data for demonstration
                shodan_data = self._simulate_shodan_data(ip_address)
                
        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
        
        self.logger.info(f"Collected network intelligence for {len(shodan_data)} IPs")
        return {"shodan_data": shodan_data}
    
    def _query_shodan_api(self, ip: str) -> Dict[str, Any]:
        """Query real Shodan API (requires valid API key)"""
        try:
            response = self.safe_request(
                f"{self.shodan_api_url}/shodan/host/{ip}?key={self.api_key}"
            )
            
            data = response.json()
            
            return {
                ip: {
                    'country': data.get('country_name', 'Unknown'),
                    'organization': data.get('org', 'Unknown'),
                    'ports': data.get('ports', []),
                    'vulnerabilities': data.get('vulns', [])
                }
            }
            
        except Exception as e:
            self.logger.error(f"Shodan API query failed: {e}")
            return {}
    
    def _simulate_shodan_data(self, ip: str) -> Dict[str, Any]:
        """Simulate Shodan data for demonstration purposes"""
        return {
            ip: {
                'country': 'United States',
                'organization': 'Example Organization',
                'ports': [80, 443],
                'vulnerabilities': []
            }
        }
    
    def _check_port(self, ip_address: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open on the target IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on common port numbers"""
        common_services = {
            22: "ssh",
            25: "smtp", 
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            993: "imaps",
            995: "pop3s"
        }
        return common_services.get(port, "unknown")
