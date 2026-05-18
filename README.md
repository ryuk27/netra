# Netra Framework

**Automated Security Reconnaissance & Intelligence Gathering Framework**

A comprehensive Python-based reconnaissance framework for security assessments, penetration testing, and attack surface analysis.

## Overview

Netra performs multi-module intelligence collection across target domains and IP addresses. It discovers subdomains, identifies technologies, extracts contact information, detects exposed credentials, analyzes content classification, and correlates findings across modules to identify compound security risks.

Supports both domain names and IP addresses (IPv4/IPv6) for compatibility with penetration testing platforms like TryHackMe and HackTheBox.

## Quick Start

```bash
cd src

# Reconnaissance on domain
python main.py -t example.com -m all -o report.json

# Reconnaissance on IP address
python main.py -t 10.10.10.5 -m all -o report.json

# Output formats: .json (default), .html (dashboard), .md (markdown)
python main.py -t target.com -m all -o report.html
```

## Modules

## Installation

### Windows
```bash
git clone <repository-url>
cd netra
pip install -r requirements.txt
```

### Linux / Ubuntu
```bash
git clone <repository-url>
cd netra
pip3 install -r requirements.txt
```

### macOS
```bash
git clone <repository-url>
cd netra
pip3 install -r requirements.txt
```

## Usage

```bash
cd src

# Subdomain enumeration
python main.py -t target.com -m subdomain_enum -o subdomains.json

# All modules
python main.py -t target.com -m all -o comprehensive.json

# Custom wordlist (brute-force)
python main.py -t target.com -m subdomain_enum --wordlist /path/to/words.txt -o results.json

# Skip brute-force (passive sources only)
python main.py -t target.com -m subdomain_enum --no-bruteforce -o results.json

# Output formats
python main.py -t target.com -m all -o report.json       # JSON (default)
python main.py -t target.com -m all -o report.html       # HTML dashboard
python main.py -t target.com -m all -o report.md         # Markdown
```

### Targets
- Domain names: `example.com`
- IPv4 addresses: `192.168.1.1`
- IPv6 addresses: `::1` or `2001:db8::1`

### Visualizations
```bash
# View results in JSON/HTML/Markdown format
python main.py -t example.com -m all -o report.json    # JSON output
python main.py -t example.com -m all -o report.html    # HTML dashboard
python main.py -t example.com -m all -o report.md      # Markdown report
```

## Available Modules

| Module | Description | What It Does (Simple) |
|--------|-------------|------------------------|
| `subdomain_enum` | Discover subdomains | Finds hidden pages of a website |
| `tech_fingerprint` | Identify web technologies | Checks what software the website uses |
| `email_harvest` | Find public email addresses | Looks for email contacts |
| `git_exposure` | Scan for exposed credentials | Checks if passwords were accidentally shared |
| `shodan_scan` | Network scanning | Identifies open ports and services |
| `content_analyzer` | Page classification | Detects admin panels, login pages, APIs, default installs |
| `correlator` | Cross-module correlation | Links findings across modules to identify compound risks |

## Output Structure

```json
{
  "target": "example.com",
  "total_unique": 42,
  "summary": { "alive": 28, "dead": 12, "error": 2 },
  "subdomains": [
    {
      "subdomain": "admin.example.com",
      "alive": true,
      "status_code": 200,
      "title": "Admin Dashboard",
      "threat_intelligence": {
        "threat_score": 45,
        "providers": ["virustotal", "abuseipdb", "otx"]
      },
      "content_analysis": { "risk_level": "high" }
    }
  ],
  "correlated_findings": [
    {
      "severity": "high",
      "title": "Admin panel exposed",
      "remediation": "Restrict access via IP allowlist or VPN. Enable MFA."
    }
  ]
}
```

## Configuration

API keys can be set in `config.py` or via CLI arguments:

```bash
cd src
python main.py -t target.com -m all --virustotal_api_key YOUR_KEY --abuseipdb_api_key YOUR_KEY
```

## Troubleshooting

- **Module not found**: Run `pip install -r requirements.txt`
- **Command not found**: Ensure you are in the `src/` directory
- **No results found**: Target may be very secure or non-existent
- **Screenshots empty**: Requires Selenium and Chrome/Chromium installation

## License

MIT License - See LICENSE file for details