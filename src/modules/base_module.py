"""
Base module for Netra intelligence collectors
"""

import requests
import logging
from typing import Dict, Any
from abc import ABC, abstractmethod
from .logging_filter import SensitiveDataFilter

class BaseModule(ABC):
    """Abstract base class for intelligence collection modules"""
    
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Apply sensitive data filter to prevent API key leakage in logs
        if not any(isinstance(f, SensitiveDataFilter) for f in self.logger.handlers):
            for handler in self.logger.handlers:
                handler.addFilter(SensitiveDataFilter())
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Collect intelligence data - must be implemented by subclasses"""
        pass
    
    def safe_request(self, url: str, **kwargs) -> requests.Response:
        """Make a safe HTTP request with error handling (redacts API keys from logs)"""
        try:
            response = self.session.get(url, timeout=30, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            # Redact API key from URL before logging
            from .logging_filter import SensitiveDataFilter
            safe_url = SensitiveDataFilter._redact(url)
            self.logger.error(f"Request failed for {safe_url}: {e}")
            raise
        
    def validate_domain(self, domain: str) -> bool:
        """Validate domain format"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    def extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        return urlparse(url).netloc or url


