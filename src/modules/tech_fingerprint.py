"""
Technology fingerprinting for web applications
"""

import re
from typing import Any, Dict, List
from bs4 import BeautifulSoup
from .base_module import BaseModule

class TechFingerprinter(BaseModule):
    """Identifies web technologies and frameworks"""
    
    def __init__(self, target: str, subdomains: List[str] = None):
        super().__init__(target)
        self.subdomains = subdomains or []
        self.signatures = self._load_signatures()
    
    def collect(self) -> Dict[str, Dict[str, List[str]]]:
        """Collect technology fingerprints from target domains"""
        self.logger.info(f"Starting technology fingerprinting for {self.target}")
        
        results = {}
        domains_to_scan = [self.target]
        
        # Extract subdomain names from subdomain objects if they're dictionaries
        for subdomain in self.subdomains[:10]:
            if isinstance(subdomain, dict):
                domains_to_scan.append(subdomain.get('subdomain', ''))
            else:
                domains_to_scan.append(subdomain)
        
        for domain in domains_to_scan:
            if not domain:  # Skip empty domain names
                continue
            try:
                technologies = self._fingerprint_domain(domain)
                if technologies:
                    results[f"https://{domain}"] = technologies
            except Exception as e:
                self.logger.warning(f"Failed to fingerprint {domain}: {e}")
        
        self.logger.info(f"Fingerprinted {len(results)} domains")
        return {"technology_fingerprint": results}
    
    def _fingerprint_domain(self, domain: str) -> Dict[str, Any]:
        """Fingerprint technologies for a specific domain"""
        result = {
            'server': 'Unknown',
            'x_powered_by': 'Unknown', 
            'status_code': 0,
            'content_type': '',
            'technologies': []
        }
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = self.safe_request(url)
                
                # Update result with response data
                result['status_code'] = response.status_code
                result['content_type'] = response.headers.get('Content-Type', '')
                result['server'] = response.headers.get('Server', 'Unknown')
                result['x_powered_by'] = response.headers.get('X-Powered-By', 'Unknown')
                
                # Analyze HTTP headers
                technologies = self._analyze_headers(response.headers)
                
                # Analyze HTML content
                technologies.extend(self._analyze_html(response.text))
                
                result['technologies'] = list(set(technologies))
                break  # Success, don't try other protocol
                
            except Exception as e:
                self.logger.debug(f"Failed to connect to {protocol}://{domain}: {e}")
                continue
        
        return result
    
    def _analyze_headers(self, headers: Dict) -> List[str]:
        """Analyze HTTP headers for technology signatures"""
        technologies = []
        
        # Server header
        server = headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append(f"Powered-By: {powered_by}")
        
        # Framework-specific headers
        for header, value in headers.items():
            header_lower = header.lower()
            if any(fw in header_lower for fw in ['laravel', 'django', 'rails', 'express']):
                technologies.append(f"{header}: {value}")
        
        return technologies
    
    def _analyze_html(self, html_content: str) -> List[str]:
        """Analyze HTML content for technology signatures"""
        technologies = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Check meta generators
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                technologies.append(f"Generator: {meta_generator['content']}")
            
            # Check for common CMS/framework signatures
            for signature, tech_name in self.signatures.items():
                if signature in html_content:
                    technologies.append(tech_name)
            
            # Check script sources for JavaScript libraries
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script.get('src', '')
                technologies.extend(self._identify_js_libraries(src))
            
        except Exception as e:
            self.logger.debug(f"HTML analysis failed: {e}")
        
        return technologies
    
    def _identify_js_libraries(self, script_src: str) -> List[str]:
        """Identify JavaScript libraries from script sources"""
        libraries = []
        
        js_patterns = {
            'jquery': r'jquery[.-]?(\d+\.?\d*\.?\d*)',
            'react': r'react[.-]?(\d+\.?\d*\.?\d*)',
            'angular': r'angular[.-]?(\d+\.?\d*\.?\d*)',
            'vue': r'vue[.-]?(\d+\.?\d*\.?\d*)',
            'bootstrap': r'bootstrap[.-]?(\d+\.?\d*\.?\d*)'
        }
        
        for lib, pattern in js_patterns.items():
            match = re.search(pattern, script_src.lower())
            if match:
                version = match.group(1) if match.group(1) else 'unknown'
                libraries.append(f"{lib.title()}: {version}")
        
        return libraries
    
    def _load_signatures(self) -> Dict[str, str]:
        """Load technology signatures for detection"""
        return {
            'wp-content': 'WordPress',
            'wp-includes': 'WordPress', 
            'drupal': 'Drupal',
            'joomla': 'Joomla',
            'shopify': 'Shopify',
            'magento': 'Magento',
            'prestashop': 'PrestaShop',
            'woocommerce': 'WooCommerce',
            'laravel_session': 'Laravel',
            'django': 'Django',
            'rails': 'Ruby on Rails',
            'express': 'Express.js',
            'next.js': 'Next.js',
            'nuxt': 'Nuxt.js'
        }
