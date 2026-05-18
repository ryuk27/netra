"""
Configuration settings for Netra
"""

# API Keys
SHODAN_API_KEY = "PawIXS84FaZY28CSY23uUbZQghOok4VK"  # Add your Shodan API key here
VIRUSTOTAL_API_KEY = "086d7179223e5c869d39c60a5d0c3c22e42bf03795c734d73dd0072403c050e2"  # Add your VirusTotal API key here (https://www.virustotal.com/gui/my-apikey)
ABUSEIPDB_API_KEY = "04e0dabe4fa97eb82926b71a94c352f8b68228588127b2769b9f6fdaabd5a3d75576b2d3dfa47fb4"   # Add your AbuseIPDB API key here (https://www.abuseipdb.com/account)
OTX_API_KEY = "4619db8ee5ea7724c8c63689b4193160accbc18e65ff8dcf7748b3e770c02b05"       # Add your AlienVault OTX API key here (https://otx.alienvault.com/api)
# URLhaus and Feodo Tracker: No API key needed (public databases)

# Request settings
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
DELAY_BETWEEN_REQUESTS = 1

# Module settings
DEFAULT_MODULES = [
    'subdomain_enum',
    'email_harvester', 
    'tech_fingerprint',
    'git_scraper',
    'shodan_lookup'
]

# Logging settings
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Output settings
DEFAULT_OUTPUT_FORMAT = 'json'
MAX_SUBDOMAINS_DISPLAY = 50
MAX_EMAILS_DISPLAY = 25
CRT_SH_URL = 'https://crt.sh/'

# Domain handling settings
SUPPORTED_TLDS = [
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.co.uk', '.co.jp', '.co.au', '.co.in', '.co.za',
    '.de', '.fr', '.it', '.es', '.ru', '.cn', '.jp', '.kr',
    '.io', '.ai', '.tech', '.dev', '.app', '.cloud'
]

# Domain validation settings
VALIDATE_DOMAIN_DNS = True  # Check if domain resolves
INCLUDE_INTERNATIONALIZED_DOMAINS = True  # Support IDN domains
MAX_DOMAIN_LENGTH = 253  # RFC compliant max domain length
MIN_DOMAIN_LENGTH = 3

# Subdomain enumeration settings
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
    'blog', 'shop', 'support', 'help', 'docs', 'portal', 'secure'
]

# User agents for web scraping
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
]

# Rate limiting settings
GITHUB_RATE_LIMIT_DELAY = 2  # seconds between GitHub API calls
SHODAN_RATE_LIMIT_DELAY = 1  # seconds between Shodan API calls
WEB_CRAWL_DELAY = 1  # seconds between web requests

# Limits
MAX_SUBDOMAINS_TO_CRAWL = 10  # Limit subdomain crawling for email harvesting
MAX_GITHUB_RESULTS_PER_QUERY = 5  # Limit GitHub search results per query
MAX_SUBDOMAINS_DISPLAY = 50
MAX_EMAILS_DISPLAY = 25


