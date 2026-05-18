"""
Logging filter to redact sensitive information (API keys, credentials)
"""

import logging
import re


class SensitiveDataFilter(logging.Filter):
    """Filter that redacts API keys and sensitive data from logs"""
    
    # Patterns to match sensitive data
    PATTERNS = [
        # API keys in URLs (key=XXX, apikey=XXX)
        (r'([?&]key=)[^&\s]+', r'\1[REDACTED]'),
        (r'([?&]apikey=)[^&\s]+', r'\1[REDACTED]'),
        (r'([?&]api_key=)[^&\s]+', r'\1[REDACTED]'),
        
        # Bearer tokens
        (r'(Bearer\s+)[^\s]+', r'\1[REDACTED]'),
        (r'(Authorization:\s+)[^\s]+', r'\1[REDACTED]'),
        
        # Common API key formats
        (r'(AKIA[0-9A-Z]{16})', r'[REDACTED]'),  # AWS keys
        (r'(gh[pousr]_[A-Za-z0-9_]{36,})', r'[REDACTED]'),  # GitHub tokens
        (r'(xox[baprs]-[0-9a-zA-Z-]{10,})', r'[REDACTED]'),  # Slack tokens
        
        # Shodan-specific (pattern from the error)
        (r'([?&]key=)([A-Za-z0-9]+)', r'\1[REDACTED]'),
    ]
    
    def filter(self, record):
        """Filter log record and redact sensitive data"""
        record.msg = self._redact(str(record.msg))
        
        # Also redact any arguments if they're strings
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact(str(arg)) for arg in record.args)
            else:
                record.args = self._redact(str(record.args))
        
        return True
    
    @staticmethod
    def _redact(text):
        """Apply all redaction patterns to text"""
        for pattern, replacement in SensitiveDataFilter.PATTERNS:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text


def setup_logging_filter(logger):
    """Add sensitive data filter to logger"""
    filter_obj = SensitiveDataFilter()
    for handler in logger.handlers:
        handler.addFilter(filter_obj)
