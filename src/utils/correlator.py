"""
Intelligence correlation engine for Netra
Analyzes collected data to generate actionable insights
"""

import logging
from typing import Dict, Any, List

class IntelligenceCorrelator:
    """Correlates intelligence data to generate security insights"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def correlate_data(self, data: Dict[str, Any]) -> List[str]:
        """Analyze collected data and generate security insights"""
        insights = []
        
        try:
            # Analyze subdomain exposure
            insights.extend(self._analyze_subdomains(data))
            
            # Analyze technology stack
            insights.extend(self._analyze_technology(data))
            
            # Analyze email exposure
            insights.extend(self._analyze_emails(data))
            
            # Analyze git exposures
            insights.extend(self._analyze_git_exposure(data))
            
            # Analyze network data
            insights.extend(self._analyze_network_data(data))
            
            # Cross-reference analysis
            insights.extend(self._cross_reference_analysis(data))
            
            # Prioritize insights
            insights = self._prioritize_insights(insights)
            
            self.logger.info(f"Generated {len(insights)} intelligence insights")
            return insights
            
        except Exception as e:
            self.logger.error(f"Correlation analysis failed: {e}")
            return [f"Correlation analysis error: {str(e)}"]
    
    def _analyze_subdomains(self, data: Dict[str, Any]) -> List[str]:
        """Analyze subdomain discovery results"""
        insights = []
        subdomains = data.get('subdomains', [])
        
        if len(subdomains) > 20:
            insights.append("MEDIUM: Large attack surface detected - consider subdomain consolidation")
        elif len(subdomains) > 50:
            insights.append("HIGH: Very large attack surface - review subdomain necessity")
        
        # Check for common risky subdomains
        risky_patterns = ['dev', 'test', 'staging', 'admin', 'api', 'internal']
        for pattern in risky_patterns:
            if any(pattern in sub for sub in subdomains):
                insights.append(f"MEDIUM: Potentially sensitive subdomain pattern '{pattern}' detected")
        
        return insights
    
    def _analyze_technology(self, data: Dict[str, Any]) -> List[str]:
        """Analyze technology fingerprinting results"""
        insights = []
        tech_data = data.get('technology_fingerprint', {})
        
        for url, tech_info in tech_data.items():
            if isinstance(tech_info, dict):
                server = tech_info.get('server', '')
                if 'nginx' in server.lower():
                    insights.append(f"INFO: Nginx server detected on {url}")
                elif 'apache' in server.lower():
                    insights.append(f"INFO: Apache server detected on {url}")
        
        return insights
    
    def _analyze_emails(self, data: Dict[str, Any]) -> List[str]:
        """Analyze email harvesting results"""
        insights = []
        emails = data.get('emails', [])
        
        if len(emails) > 10:
            insights.append("MEDIUM: Multiple email addresses exposed - consider contact form alternatives")
        
        # Check for admin emails
        admin_emails = [email for email in emails if 'admin' in email.lower()]
        if admin_emails:
            insights.append("HIGH: Administrative email addresses exposed")
        
        return insights
    
    def _analyze_git_exposure(self, data: Dict[str, Any]) -> List[str]:
        """Analyze git exposure results"""
        insights = []
        git_exposure = data.get('git_exposure', [])
        
        # Filter actual exposures
        actual_exposures = [exp for exp in git_exposure 
                          if exp not in ["No exposures detected", "exposed_repos", "git_files"]]
        
        if actual_exposures:
            if len(actual_exposures) > 5:
                insights.append("CRITICAL: Multiple potential credential exposures in public repositories")
            else:
                insights.append("HIGH: Potential credential exposure detected in public repositories")
        
        return insights
    
    def _analyze_network_data(self, data: Dict[str, Any]) -> List[str]:
        """Analyze Shodan network intelligence"""
        insights = []
        shodan_data = data.get('shodan_data', {})
        
        for ip, info in shodan_data.items():
            ports = info.get('ports', [])
            
            if 22 in ports:
                insights.append(f"MEDIUM: SSH port exposed on {ip}")
            if 3389 in ports:
                insights.append(f"HIGH: RDP port exposed on {ip}")
            if len(ports) > 10:
                insights.append(f"MEDIUM: Multiple services exposed on {ip}")
            
            vulnerabilities = info.get('vulnerabilities', [])
            if vulnerabilities:
                insights.append(f"CRITICAL: {len(vulnerabilities)} known vulnerabilities on {ip}")
        
        return insights
    
    def _cross_reference_analysis(self, data: Dict[str, Any]) -> List[str]:
        """Cross-reference different intelligence sources"""
        insights = []
        
        subdomains = data.get('subdomains', [])
        tech_fingerprint = data.get('technology_fingerprint', {})
        shodan_data = data.get('shodan_data', {})
        
        # Check if subdomains have different technology stacks
        tech_diversity = {}
        for url, tech_info in tech_fingerprint.items():
            if isinstance(tech_info, dict):
                server = tech_info.get('server', 'Unknown')
                if server != 'Unknown':
                    tech_diversity[url] = server
        
        if len(set(tech_diversity.values())) > 1:
            insights.append(
                "MEDIUM: Inconsistent server technologies across subdomains - review standardization"
            )
        
        # Check for subdomain-to-IP mapping inconsistencies
        if len(subdomains) > 0 and len(shodan_data) > 0:
            insights.append(
                f"INFO: Network mapping: {len(subdomains)} subdomains mapped to {len(shodan_data)} IP addresses"
            )
        
        return insights
    
    def _prioritize_insights(self, insights: List[str]) -> List[str]:
        """Prioritize insights by security level"""
        priority_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        prioritized = []
        for priority in priority_order:
            priority_insights = [insight for insight in insights if insight.startswith(priority)]
            prioritized.extend(sorted(priority_insights))
        
        # Add insights without priority markers at the end
        no_priority = [insight for insight in insights if not any(
            insight.startswith(p) for p in priority_order
        )]
        prioritized.extend(sorted(no_priority))
        
        return prioritized
    
    def generate_visual_summary_data(self, data: Dict[str, Any], insights: List[str]) -> Dict[str, Any]:
        """Prepare data optimized for visualization generation"""
        try:
            return {
                'visualization_ready': True,
                'summary_stats': {
                    'total_subdomains': len(data.get('subdomains', [])),
                    'total_technologies': len(data.get('technology_fingerprint', {})),
                    'total_insights': len(insights),
                    'critical_issues': len([i for i in insights if i.startswith('CRITICAL')]),
                    'high_issues': len([i for i in insights if i.startswith('HIGH')]),
                    'medium_issues': len([i for i in insights if i.startswith('MEDIUM')])
                },
                'risk_distribution': self._calculate_risk_distribution(insights),
                'technology_breakdown': self._extract_technology_summary(data),
                'subdomain_categories': self._categorize_subdomains(data.get('subdomains', []))
            }
        except Exception as e:
            self.logger.error(f"Failed to generate visual summary data: {e}")
            return {
                'visualization_ready': False,
                'error': str(e),
                'summary_stats': {'total_subdomains': 0, 'total_technologies': 0, 'total_insights': 0}
            }
    
    def _calculate_risk_distribution(self, insights: List[str]) -> Dict[str, int]:
        """Calculate risk level distribution for visualizations"""
        distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for insight in insights:
            for level in distribution.keys():
                if insight.startswith(level):
                    distribution[level] += 1
                    break
        return distribution
    
    def _extract_technology_summary(self, data: Dict[str, Any]) -> Dict[str, int]:
        """Extract technology summary for visualizations"""
        tech_data = data.get('technology_fingerprint', {})
        servers = {}
        
        for url, tech_info in tech_data.items():
            if isinstance(tech_info, dict):
                server = tech_info.get('server', 'Unknown')
                server_name = server.split('/')[0] if server != 'Unknown' else 'Unknown'
                servers[server_name] = servers.get(server_name, 0) + 1
        
        return servers
    
    def _categorize_subdomains(self, subdomains: List[str]) -> Dict[str, int]:
        """Categorize subdomains for visualization"""
        categories = {
            'Development': ['dev', 'test', 'staging', 'demo'],
            'Production': ['www', 'api', 'app', 'web'],
            'Infrastructure': ['mail', 'smtp', 'ftp', 'dns'],
            'Admin': ['admin', 'panel', 'control', 'manage'],
            'Other': []
        }
        
        categorized = {cat: 0 for cat in categories.keys()}
        
        for subdomain in subdomains:
            categorized_flag = False
            for category, keywords in categories.items():
                if category == 'Other':
                    continue
                if any(keyword in subdomain.lower() for keyword in keywords):
                    categorized[category] += 1
                    categorized_flag = True
                    break
            if not categorized_flag:
                categorized['Other'] += 1
        
        return categorized
