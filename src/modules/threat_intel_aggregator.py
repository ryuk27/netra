"""
Threat Intelligence Aggregator Module
Integrates multiple threat intelligence APIs to enrich subdomain reconnaissance data.
APIs: VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, Feodo Tracker
"""

import requests
import socket
import logging
import json
from typing import Dict, List, Optional, Tuple
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib.parse

logger = logging.getLogger(__name__)


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers"""
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.name = self.__class__.__name__
    
    @abstractmethod
    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation"""
        pass
    
    @abstractmethod
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation"""
        pass
    
    def _make_request(self, url: str, headers: Dict = None, method: str = "GET", 
                     params: Dict = None, json_data: Dict = None) -> Optional[Dict]:
        """Helper to make HTTP requests"""
        try:
            if method == "GET":
                response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            else:
                response = requests.post(url, headers=headers, json=json_data, timeout=self.timeout)
            
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.RequestException as e:
            logger.debug(f"{self.name} API error: {str(e)}")
            return None


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API integration for URL/domain reputation"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.enabled = api_key is not None
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation on VirusTotal"""
        if not self.enabled:
            return {"provider": self.name, "enabled": False}
        
        try:
            url = f"{self.BASE_URL}/domains/{domain}"
            headers = {"x-apikey": self.api_key}
            
            data = self._make_request(url, headers=headers)
            if not data or "data" not in data:
                return {"provider": self.name, "domain": domain, "status": "not_found"}
            
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "provider": self.name,
                "domain": domain,
                "status": "found",
                "malicious_votes": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious_votes": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                "undetected_votes": attrs.get("last_analysis_stats", {}).get("undetected", 0),
                "harmless_votes": attrs.get("last_analysis_stats", {}).get("harmless", 0),
                "last_update": attrs.get("last_update_date", ""),
                "threat_types": attrs.get("threat_names", [])
            }
        except Exception as e:
            logger.debug(f"VirusTotal domain check error: {e}")
            return {"provider": self.name, "error": str(e)}
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation on VirusTotal"""
        if not self.enabled:
            return {"provider": self.name, "enabled": False}
        
        try:
            url = f"{self.BASE_URL}/ip_addresses/{ip}"
            headers = {"x-apikey": self.api_key}
            
            data = self._make_request(url, headers=headers)
            if not data or "data" not in data:
                return {"provider": self.name, "ip": ip, "status": "not_found"}
            
            attrs = data.get("data", {}).get("attributes", {})
            return {
                "provider": self.name,
                "ip": ip,
                "status": "found",
                "malicious_votes": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious_votes": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                "country": attrs.get("country", ""),
                "asn": attrs.get("as_number", ""),
                "threat_types": attrs.get("threat_names", [])
            }
        except Exception as e:
            logger.debug(f"VirusTotal IP check error: {e}")
            return {"provider": self.name, "error": str(e)}


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB API integration for IP reputation and abuse reports"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.enabled = api_key is not None
    
    def check_domain(self, domain: str) -> Dict:
        """Resolve domain to IP and check reputation"""
        if not self.enabled:
            return {"provider": self.name, "enabled": False}
        
        try:
            # Resolve domain to IP first
            try:
                ip = socket.gethostbyname(domain)
            except socket.gaierror:
                return {"provider": self.name, "domain": domain, "status": "unresolved"}
            
            return self.check_ip(ip)
        except Exception as e:
            logger.debug(f"AbuseIPDB domain check error: {e}")
            return {"provider": self.name, "error": str(e)}
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP abuse score on AbuseIPDB"""
        if not self.enabled:
            return {"provider": self.name, "enabled": False}
        
        try:
            url = f"{self.BASE_URL}/check"
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            data = self._make_request(url, headers=headers, params=params)
            if not data or "data" not in data:
                return {"provider": self.name, "ip": ip, "status": "not_found"}
            
            info = data.get("data", {})
            return {
                "provider": self.name,
                "ip": ip,
                "status": "found",
                "abuse_score": info.get("abuseConfidenceScore", 0),
                "total_reports": info.get("totalReports", 0),
                "country": info.get("countryCode", ""),
                "isp": info.get("isp", ""),
                "is_whitelisted": info.get("isWhitelisted", False),
                "is_blacklisted": info.get("isBlacklisted", False)
            }
        except Exception as e:
            logger.debug(f"AbuseIPDB IP check error: {e}")
            return {"provider": self.name, "error": str(e)}


class AlienVaultOTXProvider(ThreatIntelProvider):
    """AlienVault OTX API integration for threat indicators and pulses"""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.enabled = True  # OTX allows limited queries without API key
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain indicators on OTX"""
        try:
            url = f"{self.BASE_URL}/indicators/domain/{domain}/general"
            headers = {}
            if self.api_key:
                headers["X-OTX-API-KEY"] = self.api_key
            
            data = self._make_request(url, headers=headers)
            if not data or ("error" in data and data.get("error") == "Not Found"):
                return {"provider": self.name, "domain": domain, "status": "not_found"}
            
            # Additional endpoint for reputation
            url_rep = f"{self.BASE_URL}/indicators/domain/{domain}/reputation"
            data_rep = self._make_request(url_rep, headers=headers)
            
            return {
                "provider": self.name,
                "domain": domain,
                "status": "found",
                "reputation": data_rep.get("reputation", 0) if data_rep else 0,
                "alexa_rank": data.get("alexa_rank", None),
                "pulse_count": len(data.get("pulse_info", {}).get("pulses", [])) if data else 0,
                "whois": data.get("whois", "") if data else ""
            }
        except Exception as e:
            logger.debug(f"OTX domain check error: {e}")
            return {"provider": self.name, "error": str(e)}
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP indicators on OTX"""
        try:
            url = f"{self.BASE_URL}/indicators/IPv4/{ip}/general"
            headers = {}
            if self.api_key:
                headers["X-OTX-API-KEY"] = self.api_key
            
            data = self._make_request(url, headers=headers)
            if not data or ("error" in data and data.get("error") == "Not Found"):
                return {"provider": self.name, "ip": ip, "status": "not_found"}
            
            # Additional endpoint for reputation
            url_rep = f"{self.BASE_URL}/indicators/IPv4/{ip}/reputation"
            data_rep = self._make_request(url_rep, headers=headers)
            
            return {
                "provider": self.name,
                "ip": ip,
                "status": "found",
                "reputation": data_rep.get("reputation", 0) if data_rep else 0,
                "asn": data.get("asn", "") if data else "",
                "country_code": data.get("country_code", "") if data else "",
                "pulse_count": len(data.get("pulse_info", {}).get("pulses", [])) if data else 0
            }
        except Exception as e:
            logger.debug(f"OTX IP check error: {e}")
            return {"provider": self.name, "error": str(e)}


class URLhausProvider(ThreatIntelProvider):
    """URLhaus API integration for malware URL database lookups"""
    
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.enabled = True  # URLhaus allows free queries
    
    def check_domain(self, domain: str) -> Dict:
        """Check if domain is in URLhaus malware database"""
        try:
            url = f"{self.BASE_URL}/host/"
            params = {"host": domain}
            
            data = self._make_request(url, params=params)
            if not data:
                return {"provider": self.name, "domain": domain, "status": "error"}
            
            query_status = data.get("query_status", "no_results")
            
            if query_status == "no_results":
                return {
                    "provider": self.name,
                    "domain": domain,
                    "status": "clean",
                    "malicious": False
                }
            
            results = data.get("results", [])
            return {
                "provider": self.name,
                "domain": domain,
                "status": "found",
                "malicious": True,
                "url_count": len(results),
                "threats": list(set([r.get("threat", "unknown") for r in results]))
            }
        except Exception as e:
            logger.debug(f"URLhaus domain check error: {e}")
            return {"provider": self.name, "error": str(e)}
    
    def check_ip(self, ip: str) -> Dict:
        """Check if IP is associated with malware URLs"""
        # URLhaus doesn't have direct IP lookup, check via domain resolution
        return {"provider": self.name, "ip": ip, "status": "unsupported"}
    
    def check_url(self, url: str) -> Dict:
        """Check if specific URL is in URLhaus database"""
        try:
            api_url = f"{self.BASE_URL}/url/"
            params = {"url": url}
            
            data = self._make_request(api_url, params=params)
            if not data:
                return {"provider": self.name, "url": url, "status": "error"}
            
            query_status = data.get("query_status", "no_results")
            
            if query_status == "no_results":
                return {
                    "provider": self.name,
                    "url": url,
                    "status": "clean",
                    "malicious": False
                }
            
            result = data.get("result", {})
            return {
                "provider": self.name,
                "url": url,
                "status": "found",
                "malicious": True,
                "threat": result.get("threat", "unknown"),
                "tags": result.get("tags", []),
                "submission_date": result.get("submission_date", "")
            }
        except Exception as e:
            logger.debug(f"URLhaus URL check error: {e}")
            return {"provider": self.name, "error": str(e)}


class ThreatIntelAggregator:
    """Orchestrates multiple threat intelligence providers"""
    
    def __init__(self, virustotal_key: Optional[str] = None, 
                 abuseipdb_key: Optional[str] = None,
                 otx_key: Optional[str] = None,
                 timeout: int = 10,
                 max_workers: int = 4):
        """
        Initialize aggregator with API keys for various providers
        
        Args:
            virustotal_key: VirusTotal API key
            abuseipdb_key: AbuseIPDB API key
            otx_key: AlienVault OTX API key
            timeout: Request timeout in seconds
            max_workers: Max concurrent requests
        """
        self.providers: Dict[str, ThreatIntelProvider] = {
            "virustotal": VirusTotalProvider(virustotal_key, timeout),
            "abuseipdb": AbuseIPDBProvider(abuseipdb_key, timeout),
            "otx": AlienVaultOTXProvider(otx_key, timeout),
            "urlhaus": URLhausProvider(None, timeout)
        }
        self.max_workers = max_workers
        self.timeout = timeout
    
    def check_domain(self, domain: str) -> Dict:
        """Check domain reputation across all providers"""
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "providers": {}
        }
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(provider.check_domain, domain): name
                for name, provider in self.providers.items()
            }
            
            for future in as_completed(futures):
                provider_name = futures[future]
                try:
                    results["providers"][provider_name] = future.result()
                except Exception as e:
                    logger.error(f"Error checking {provider_name} for {domain}: {e}")
                    results["providers"][provider_name] = {
                        "provider": provider_name,
                        "error": str(e)
                    }
        
        results["threat_score"] = self._calculate_threat_score(results["providers"], is_ip=False)
        return results
    
    def check_ip(self, ip: str) -> Dict:
        """Check IP reputation across all providers"""
        results = {
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
            "providers": {}
        }
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(provider.check_ip, ip): name
                for name, provider in self.providers.items()
            }
            
            for future in as_completed(futures):
                provider_name = futures[future]
                try:
                    results["providers"][provider_name] = future.result()
                except Exception as e:
                    logger.error(f"Error checking {provider_name} for {ip}: {e}")
                    results["providers"][provider_name] = {
                        "provider": provider_name,
                        "error": str(e)
                    }
        
        results["threat_score"] = self._calculate_threat_score(results["providers"], is_ip=True)
        return results
    
    def check_url(self, url: str) -> Dict:
        """Check URL reputation via URLhaus"""
        result = self.providers["urlhaus"].check_url(url)
        return {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "providers": {"urlhaus": result},
            "threat_score": self._calculate_url_threat_score(result)
        }
    
    def check_subdomains(self, subdomains: List[str]) -> Dict[str, Dict]:
        """Check multiple subdomains for threat intel"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.check_domain, subdomain): subdomain
                for subdomain in subdomains
            }
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    results[subdomain] = future.result()
                except Exception as e:
                    logger.error(f"Error checking subdomain {subdomain}: {e}")
                    results[subdomain] = {
                        "domain": subdomain,
                        "error": str(e),
                        "threat_score": 0
                    }
        
        return results
    
    def _calculate_threat_score(self, provider_results: Dict, is_ip: bool = False) -> int:
        """Calculate combined threat score (0-100)"""
        score = 0
        count = 0
        
        # VirusTotal score
        vt = provider_results.get("virustotal", {})
        if vt.get("status") == "found":
            malicious = vt.get("malicious_votes", 0)
            if malicious > 0:
                score += min(40, malicious * 10)  # Max 40 points
            count += 1
        
        # AbuseIPDB score
        abuseipdb = provider_results.get("abuseipdb", {})
        if abuseipdb.get("status") == "found" and is_ip:
            abuse_score = abuseipdb.get("abuse_score", 0)
            score += (abuse_score / 100) * 30  # Max 30 points
            if abuseipdb.get("is_blacklisted"):
                score += 20  # Max 20 points for blacklist
            count += 1
        
        # OTX score
        otx = provider_results.get("otx", {})
        if otx.get("status") == "found":
            reputation = otx.get("reputation", 0)
            if reputation < 0:
                score += min(25, abs(reputation) * 2)  # Max 25 points
            count += 1
        
        # URLhaus check
        urlhaus = provider_results.get("urlhaus", {})
        if urlhaus.get("malicious"):
            score += 50  # High score for known malware
        
        return min(100, int(score))
    
    def _calculate_url_threat_score(self, result: Dict) -> int:
        """Calculate URL threat score"""
        if result.get("malicious"):
            return 85  # High score for known malware URL
        elif result.get("status") == "clean":
            return 5
        else:
            return 0
    
    def is_enabled(self) -> bool:
        """Check if any providers are enabled"""
        return any(p.enabled for p in self.providers.values())
