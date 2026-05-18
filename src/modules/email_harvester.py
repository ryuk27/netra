"""
Email address harvesting from web pages
"""

import re
from typing import Dict, List, Set
from bs4 import BeautifulSoup
from .base_module import BaseModule

class EmailHarvester(BaseModule):
    """Harvests email addresses from target websites"""
    
    def __init__(self, target: str, subdomains: List[str] = None):
        super().__init__(target)
        self.subdomains = subdomains or []
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    
    def collect(self) -> Dict[str, List[str]]:
        """Collect email addresses from target domain and subdomains"""
        self.logger.info(f"Starting email harvesting for {self.target}")
        
        emails = set()
        domains_to_scan = [self.target]
        
        # Extract subdomain names from subdomain objects if they're dictionaries
        for subdomain in self.subdomains[:5]:  # Limit for performance
            if isinstance(subdomain, dict):
                domain_name = subdomain.get('subdomain', '')
                if domain_name:
                    domains_to_scan.append(domain_name)
            else:
                domains_to_scan.append(subdomain)
        
        for domain in domains_to_scan:
            if not domain:  # Skip empty domain names
                continue
            try:
                domain_emails = self._harvest_from_domain(domain)
                emails.update(domain_emails)
            except Exception as e:
                self.logger.warning(f"Failed to harvest emails from {domain}: {e}")
        
        # Filter emails to only include target domain
        target_emails = [email for email in emails if self.target in email]
        
        self.logger.info(f"Found {len(target_emails)} email addresses")
        return {"emails": sorted(target_emails)}
    
    def _harvest_from_domain(self, domain: str) -> List[str]:
        """Harvest emails from a specific domain"""
        emails = set()
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = self.safe_request(url)
                
                # Extract emails from HTML content
                found_emails = self.email_pattern.findall(response.text)
                emails.update(found_emails)
                
                # Parse HTML and check for mailto links
                soup = BeautifulSoup(response.text, 'html.parser')
                mailto_links = soup.find_all('a', href=lambda x: x and x.startswith('mailto:'))
                
                for link in mailto_links:
                    email = link['href'].replace('mailto:', '').split('?')[0]
                    if email:
                        emails.add(email)
                
                break  # Success, don't try other protocol
                
            except Exception as e:
                self.logger.debug(f"Failed to connect to {protocol}://{domain}: {e}")
                continue
        
        return list(emails)
    
    def _filter_target_emails(self, emails: Set[str]) -> List[str]:
        """Filter emails to only include target domain"""
        filtered = []
        
        for email in emails:
            if email.lower().endswith(f"@{self.target}"):
                filtered.append(email.lower())
        
        return sorted(list(set(filtered)))
        
        for email in emails:
            if email.lower().endswith(f"@{self.target}"):
                filtered.append(email.lower())
        
        return sorted(list(set(filtered)))
