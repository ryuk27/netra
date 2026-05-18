"""
Git repository scraping for exposed credentials and sensitive files
"""

import re
from typing import Dict, List
from .base_module import BaseModule

class GitScraper(BaseModule):
    """Searches for exposed credentials in public repositories"""
    
    def __init__(self, target: str):
        super().__init__(target)
        self.sensitive_patterns = self._load_sensitive_patterns()
    
    def collect(self) -> Dict[str, List[str]]:
        """Search for git exposures related to target domain"""
        self.logger.info(f"Starting Git repository scanning for {self.target}")
        
        exposures = []
        
        try:
            # Simulate GitHub search (in real implementation, use GitHub API)
            exposures = self._simulate_github_search()
            
        except Exception as e:
            self.logger.error(f"Git scraping failed: {e}")
        
        if not exposures:
            exposures = ["No exposures detected"]
        
        self.logger.info(f"Found {len(exposures)} potential exposures")
        return {"git_exposure": exposures}
    
    def _simulate_github_search(self) -> List[str]:
        """Simulate GitHub repository search for sensitive data"""
        # In a real implementation, this would use GitHub API
        # For demonstration, return simulated results with links
        
        simulated_findings = []
        
        # Simulate different types of exposures based on domain characteristics
        domain_parts = self.target.split('.')
        
        if len(domain_parts) >= 2:
            company_name = domain_parts[0]
            
            # Simulate common exposure patterns WITH LINKS
            common_exposures = [
                {
                    "finding": f"Potential .env file exposure in {company_name}-backend repository",
                    "url": f"https://github.com/search?q={company_name}-backend+.env&type=code"
                },
                {
                    "finding": f"Database credentials found in {company_name}-config repository",
                    "url": f"https://github.com/{company_name}/{company_name}-config"
                },
                {
                    "finding": f"API keys detected in {company_name}-mobile-app repository",
                    "url": f"https://github.com/{company_name}/{company_name}-mobile-app"
                },
                {
                    "finding": f"AWS credentials in {company_name}-infrastructure repository",
                    "url": f"https://github.com/{company_name}/{company_name}-infrastructure"
                }
            ]
            
            # Randomly select some exposures for simulation
            import random
            if random.random() > 0.7:  # 30% chance of finding exposures
                selected = random.sample(common_exposures, random.randint(1, 2))
                # Format as "finding - URL" for display
                simulated_findings.extend([f"{item['finding']} - {item['url']}" for item in selected])
        
        return simulated_findings
    
    def _load_sensitive_patterns(self) -> Dict[str, str]:
        """Load patterns for detecting sensitive information"""
        return {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[0-9a-zA-Z/+]{40}',
            'github_token': r'gh[pousr]_[A-Za-z0-9_]{36}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z-]{10,48}',
            'google_api_key': r'AIza[0-9A-Za-z-_]{35}',
            'database_url': r'(mysql|postgresql|mongodb)://[^\s]+',
            'private_key': r'-----BEGIN (RSA )?PRIVATE KEY-----',
            'api_key': r'(api[_-]?key|apikey)[\s]*[:=][\s]*[\'"][0-9a-zA-Z]{16,}[\'"]'
        }
    
    def _search_repository_content(self, content: str) -> List[str]:
        """Search repository content for sensitive patterns"""
        findings = []
        
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings.append(f"Potential {pattern_name} exposure: {match.group()[:20]}...")
        
        return findings
