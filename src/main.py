#!/usr/bin/env python3
"""
Netra Framework - Advanced Reconnaissance and Intelligence Gathering
Main entry point for the reconnaissance framework
"""

import argparse
import logging
import sys
import os
import time
from typing import Dict, Any, List

# Import modules
from modules import (
    SubdomainEnumerator, EmailHarvester, TechFingerprinter, 
    GitScraper, ShodanLookup
)
from utils import IntelligenceCorrelator, ReportGenerator
from config import (
    DEFAULT_MODULES, LOG_LEVEL, LOG_FORMAT,
    SHODAN_API_KEY, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
)

class Netra:
    """Main orchestration class for Netra"""
    
    def __init__(self, target: str, modules: List[str], shodan_api_key: str = None, 
                 probe_timeout: int = 10, virustotal_key: str = None, 
                 abuseipdb_key: str = None, otx_key: str = None):
        self.target = target
        self.modules = modules
        self.shodan_api_key = shodan_api_key
        self.probe_timeout = probe_timeout
        self.virustotal_key = virustotal_key
        self.abuseipdb_key = abuseipdb_key
        self.otx_key = otx_key
        
        # Setup logging
        logging.basicConfig(level=getattr(logging, LOG_LEVEL), format=LOG_FORMAT)
        self.logger = logging.getLogger("Netra")
        
        # Initialize components
        self.correlator = IntelligenceCorrelator()
        self.reporter = ReportGenerator()
        
        # Storage for collected data
        self.intelligence_data = {'target': target}
    
    def run_reconnaissance(self) -> Dict[str, Any]:
        """Execute reconnaissance modules and collect intelligence"""
        self.logger.info(f"Starting reconnaissance for {self.target}")
        self.logger.info(f"Modules to execute: {', '.join(self.modules)}")
        
        # Execute modules based on configuration
        if 'subdomain_enum' in self.modules:
            self._run_subdomain_enumeration()
        
        if 'email_harvester' in self.modules:
            self._run_email_harvesting()
        
        if 'tech_fingerprint' in self.modules:
            self._run_technology_fingerprinting()
        
        if 'git_scraper' in self.modules:
            self._run_git_scraping()
        
        if 'shodan_lookup' in self.modules:
            self._run_shodan_lookup()
        
        # Correlate intelligence data
        self._correlate_intelligence()
        
        self.logger.info("Reconnaissance completed successfully")
        return self.intelligence_data
    
    def _run_subdomain_enumeration(self):
        """Execute subdomain enumeration module"""
        try:
            self.logger.info("Executing subdomain enumeration...")
            enumerator = SubdomainEnumerator(
                self.target, 
                probe_timeout=self.probe_timeout,
                virustotal_key=self.virustotal_key,
                abuseipdb_key=self.abuseipdb_key,
                otx_key=self.otx_key
            )
            results = enumerator.collect()
            self.intelligence_data.update(results)
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {e}")
            self.intelligence_data['subdomains'] = []
    
    def _run_email_harvesting(self):
        """Execute email harvesting module"""
        try:
            self.logger.info("Executing email harvesting...")
            subdomains = self.intelligence_data.get('subdomains', [])
            harvester = EmailHarvester(self.target, subdomains)
            results = harvester.collect()
            self.intelligence_data.update(results)
        except Exception as e:
            self.logger.error(f"Email harvesting failed: {e}")
            self.intelligence_data['emails'] = []
    
    def _run_technology_fingerprinting(self):
        """Execute technology fingerprinting module"""
        try:
            self.logger.info("Executing technology fingerprinting...")
            subdomains = self.intelligence_data.get('subdomains', [])
            fingerprinter = TechFingerprinter(self.target, subdomains)
            results = fingerprinter.collect()
            self.intelligence_data.update(results)
        except Exception as e:
            self.logger.error(f"Technology fingerprinting failed: {e}")
            self.intelligence_data['technology_fingerprint'] = {}
    
    def _run_git_scraping(self):
        """Execute Git repository scraping module"""
        try:
            self.logger.info("Executing Git repository scanning...")
            scraper = GitScraper(self.target)
            results = scraper.collect()
            self.intelligence_data.update(results)
        except Exception as e:
            self.logger.error(f"Git scraping failed: {e}")
            self.intelligence_data['git_exposure'] = ["No exposures detected"]
    
    def _run_shodan_lookup(self):
        """Execute Shodan network intelligence module"""
        try:
            self.logger.info("Executing Shodan network intelligence...")
            lookup = ShodanLookup(self.target, self.shodan_api_key)
            results = lookup.collect()
            self.intelligence_data.update(results)
        except Exception as e:
            self.logger.error(f"Shodan lookup failed: {e}")
            self.intelligence_data['shodan_data'] = {}
    
    def _correlate_intelligence(self):
        """Correlate collected intelligence for insights"""
        try:
            self.logger.info("Correlating intelligence data...")
            insights = self.correlator.correlate_data(self.intelligence_data)
            self.intelligence_data['insights'] = insights
        except Exception as e:
            self.logger.error(f"Intelligence correlation failed: {e}")
            # Fixed: Provide more informative error message
            self.intelligence_data['insights'] = [f"Intelligence correlation error: {str(e)}"]
    
    def generate_report(self, output_file: str) -> str:
        """Generate comprehensive report"""
        try:
            # Determine format from file extension
            if output_file.endswith('.md'):
                format_type = 'markdown'
            elif output_file.endswith('.html'):
                format_type = 'html'
            else:
                format_type = 'json'
            
            report_path = self.reporter.generate_report(
                self.intelligence_data, output_file, format_type
            )
            
            self.logger.info(f"Report generated: {report_path}")
            return report_path
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return ""

def validate_target(target: str) -> bool:
    """Validate target — accepts domain names and IP addresses (IPv4 & IPv6)"""
    import re
    import ipaddress
    
    # Try to parse as IP address (IPv4 or IPv6)
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Validate as domain name
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(domain_pattern, target))

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Netra: Multi-Source Intelligence Collection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t example.com
  python main.py -t tesla.com -o tesla_report.md
  python main.py -t example.com -m subdomain_enum tech_fingerprint
  python main.py -t example.com -s YOUR_SHODAN_API_KEY -o network_intel.json
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain (e.g., example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='report.json',
        help='Output file name (default: report.json)'
    )
    
    parser.add_argument(
        '-m', '--modules',
        nargs='*',
        default=['all'],
        choices=['all'] + DEFAULT_MODULES,
        help='Modules to run (default: all)'
    )
    
    parser.add_argument(
        '-s', '--shodan_api_key',
        default=SHODAN_API_KEY,
        help='Shodan API key for enhanced network intelligence (or set in config.py)'
    )
    
    # Threat Intelligence API Keys (from config.py or override via CLI)
    parser.add_argument(
        '--virustotal_api_key',
        default=VIRUSTOTAL_API_KEY,
        help='VirusTotal API key for AV engine reputation checking (or set in config.py)'
    )
    
    parser.add_argument(
        '--abuseipdb_api_key',
        default=ABUSEIPDB_API_KEY,
        help='AbuseIPDB API key for IP reputation and abuse scoring (or set in config.py)'
    )
    
    parser.add_argument(
        '--otx_api_key',
        default=OTX_API_KEY,
        help='AlienVault OTX API key for threat indicator pulses (or set in config.py)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument('--wordlist', type=str, default=None,
                        help='Path to custom wordlist file (one subdomain prefix per line)')
    parser.add_argument('--no-bruteforce', action='store_true',
                        help='Disable wordlist brute-force (passive sources only)')
    parser.add_argument('--no-screenshots', action='store_true',
                        help='Disable screenshot capture')
    parser.add_argument('--timeout', type=int, default=10,
                        help='HTTP request timeout in seconds (default: 10)')

    return parser.parse_args()

def display_banner():
    """Display Netra banner"""
    banner = """
    ============================================================
    
           NETRA - Advanced Reconnaissance Framework
           v 1.0
    
    ============================================================
    
    [+] Authors: Ram | Palash | Shreya | Harsh
    [+] Platform: Cross-Platform (Optimized for Kali Linux)
    [+] Purpose: Automated Security Reconnaissance & Intelligence
    """
    
    print(banner)
    print("[*] Loading Netra Framework...")
    time.sleep(0.5)  # Brief pause for effect

def main():
    """Main entry point"""
    try:
        # Display banner first
        display_banner()
        
        args = parse_arguments()
        
        # Validate target
        if not validate_target(args.target):
            print(f"Error: Invalid target domain format: {args.target}")
            sys.exit(1)
        
        # Set verbose logging
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Determine modules to run
        modules = DEFAULT_MODULES if 'all' in args.modules else args.modules
        
        # Initialize Netra with threat intel API keys
        recon = Netra(
            args.target, 
            modules, 
            args.shodan_api_key, 
            args.timeout,
            args.virustotal_api_key,
            args.abuseipdb_api_key,
            args.otx_api_key
        )
        
        print(f"\n[*] Netra - Starting reconnaissance for {args.target}")
        print(f"[+] Modules: {', '.join(modules)}")
        print(f"[+] Output: {args.output}")
        print("-" * 60)
        
        # Execute reconnaissance
        intelligence_data = recon.run_reconnaissance()
        
        # Generate report
        report_path = recon.generate_report(args.output)
        
        # Display summary
        print("\n" + "=" * 60)
        print("[*] RECONNAISSANCE SUMMARY")
        print("=" * 60)
        print(f"Target: {args.target}")
        print(f"Subdomains Found: {len(intelligence_data.get('subdomains', []))}")
        print(f"Email Addresses: {len(intelligence_data.get('emails', []))}")
        print(f"Technology Services: {len(intelligence_data.get('technology_fingerprint', {}))}")
        print(f"Security Insights: {len(intelligence_data.get('insights', []))}")
        print(f"Report Generated: {report_path}")
        
        # Show top insights
        insights = intelligence_data.get('insights', [])
        if insights and not any('error' in insight.lower() for insight in insights):
            print(f"\n[!] TOP SECURITY FINDINGS:")
            for insight in insights[:5]:
                priority = 'HIGH' if any(word in insight for word in ['CRITICAL', 'HIGH']) else 'MEDIUM'
                icon = '[!]' if priority == 'HIGH' else '[*]'
                print(f"  {icon} {insight}")
        elif insights:
            print(f"\n[*] ANALYSIS NOTES:")
            for insight in insights[:3]:
                print(f"  [+] {insight}")
        
        print("\n[+] Reconnaissance completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n[*] Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


