"""
Report generation and visualization for Netra
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
import logging

class ReportGenerator:
    """Professional report generation with visualizations"""
    
    def __init__(self, output_dir: str = '.'):
        self.output_dir = output_dir
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Create visualization directory
        self.viz_dir = os.path.join(output_dir, 'visualizations')
        os.makedirs(self.viz_dir, exist_ok=True)
    
    def generate_report(self, data: Dict[str, Any], output_file: str, 
                       format_type: str = 'json') -> str:
        """Generate comprehensive report in specified format"""
        self.logger.info(f"Generating {format_type.upper()} report: {output_file}")
        
        # Add metadata
        report_data = {
            'metadata': {
                'target': data.get('target', 'Unknown'),
                'timestamp': datetime.now().isoformat(),
                'scan_modules': list(data.keys()),
                'total_findings': self._count_findings(data)
            },
            **data
        }
        
        # Generate visualizations
        self._generate_visualizations(report_data)
        
        # Generate report based on format
        if format_type.lower() == 'json':
            return self._generate_json_report(report_data, output_file)
        elif format_type.lower() == 'markdown':
            return self._generate_markdown_report(report_data, output_file)
        elif format_type.lower() == 'html':
            return self._generate_html_report(report_data, output_file)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_json_report(self, data: Dict[str, Any], output_file: str) -> str:
        """Generate JSON format report"""
        output_path = os.path.join(self.output_dir, output_file)
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        self.logger.info(f"JSON report saved to {output_path}")
        return output_path
    
    def _generate_markdown_report(self, data: Dict[str, Any], output_file: str) -> str:
        """Generate Markdown format report"""
        output_path = os.path.join(self.output_dir, output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self._create_markdown_content(data))
        
        self.logger.info(f"Markdown report saved to {output_path}")
        return output_path
    
    def _generate_html_report(self, data: Dict[str, Any], output_file: str) -> str:
        """Generate HTML format report with visualizations"""
        output_path = os.path.join(self.output_dir, output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self._create_html_content(data))
        
        self.logger.info(f"HTML report saved to {output_path}")
        return output_path
    
    def _create_html_content(self, data: Dict[str, Any]) -> str:
        """Create formatted HTML content with styling"""
        target = data.get('target', 'Unknown')
        metadata = data.get('metadata', {})
        
        # Prepare data sections
        subdomains = data.get('subdomains', [])
        emails = data.get('emails', [])
        tech_fingerprint = data.get('technology_fingerprint', {})
        git_exposure = data.get('git_exposure', [])
        shodan_data = data.get('shodan_data', {})
        insights = data.get('insights', [])
        
        # Build subdomains table
        subdomains_html = self._build_subdomains_html(subdomains)
        
        # Build technology table
        tech_html = self._build_technology_html(tech_fingerprint)
        
        # Build insights list
        insights_html = self._build_insights_html(insights)
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netra Intelligence Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
        }}
        
        .meta-item {{
            padding: 15px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        
        .meta-label {{
            font-weight: bold;
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .meta-value {{
            font-size: 1.3em;
            color: #333;
            margin-top: 5px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        section {{
            margin-bottom: 40px;
        }}
        
        h2 {{
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        
        h3 {{
            color: #764ba2;
            font-size: 1.3em;
            margin: 20px 0 15px 0;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            border-radius: 5px;
            overflow: hidden;
        }}
        
        th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tr:hover {{
            background: #f5f5f5;
        }}
        
        .status-alive {{
            color: #27ae60;
            font-weight: bold;
        }}
        
        .status-dead {{
            color: #e74c3c;
            font-weight: bold;
        }}
        
        .tag {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            margin-right: 5px;
        }}
        
        .insight {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
            background: #f8f9fa;
            border-radius: 3px;
        }}
        
        .insight-critical {{
            border-left-color: #e74c3c;
            background: #fcf3f3;
        }}
        
        .insight-high {{
            border-left-color: #e67e22;
            background: #fef5f0;
        }}
        
        .insight-medium {{
            border-left-color: #f39c12;
            background: #fffdf7;
        }}
        
        .insight-info {{
            border-left-color: #3498db;
            background: #f0f7ff;
        }}
        
        footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        .highlight {{
            background: #fff3cd;
            padding: 10px;
            border-radius: 3px;
            margin: 20px 0;
        }}
        
        .stat-box {{
            display: inline-block;
            padding: 20px;
            margin: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 5px;
            text-align: center;
            min-width: 150px;
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Netra Intelligence Report</h1>
            <p class="subtitle">Advanced Reconnaissance & Analysis Framework</p>
        </header>
        
        <div class="metadata">
            <div class="meta-item">
                <div class="meta-label">Target Domain</div>
                <div class="meta-value">{target}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Date</div>
                <div class="meta-value">{metadata.get('timestamp', 'Unknown')}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Total Findings</div>
                <div class="meta-value">{metadata.get('total_findings', 0)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Modules Executed</div>
                <div class="meta-value">{len(metadata.get('scan_modules', []))}</div>
            </div>
        </div>
        
        <div class="content">
            <section>
                <h2>📊 Quick Statistics</h2>
                <div>
                    <div class="stat-box">
                        <div class="stat-number">{len(subdomains)}</div>
                        <div class="stat-label">Subdomains</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(emails)}</div>
                        <div class="stat-label">Email Addresses</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(tech_fingerprint)}</div>
                        <div class="stat-label">Technologies</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(insights)}</div>
                        <div class="stat-label">Insights</div>
                    </div>
                </div>
            </section>
            
            <section>

            </section>
            
            <section>
                <h2>🎯 Subdomain Reconnaissance</h2>
                {subdomains_html}
            </section>
            
            <section>
                <h2>� Threat Intelligence Summary</h2>
                {self._build_threat_intel_html(subdomains)}
            </section>
            
            <section>
                <h2>�🔧 Technology Stack</h2>
                {tech_html}
            </section>
            
            <section>
                <h2>⚠️ Security Insights</h2>
                {insights_html}
            </section>
            
            <section>
                <h2>📧 Email Intelligence</h2>
                <p><strong>Found {len(emails)} email addresses:</strong></p>
                {''.join([f'<div class="tag">{email}</div>' for email in emails[:20]])}
                {'<p style="margin-top: 10px; color: #666;">... and ' + str(len(emails) - 20) + ' more</p>' if len(emails) > 20 else ''}
            </section>
        </div>
        
        <footer>
            <p>Report generated by Netra Intelligence Framework</p>
            <p>For more information, visit your organization's security dashboard</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html_content
    
    def _build_subdomains_html(self, subdomains: List[Dict[str, Any]]) -> str:
        """Build HTML table for subdomains with threat intelligence"""
        if not subdomains:
            return "<p>No subdomains discovered.</p>"
        
        html = "<table><thead><tr><th>Subdomain</th><th>Status</th><th>Status Code</th><th>Threat Score</th><th>Threats</th><th>Title</th></tr></thead><tbody>"
        
        for sub in subdomains[:50]:
            if isinstance(sub, dict):
                subdomain = sub.get('subdomain', 'N/A')
                alive = sub.get('alive', False)
                status_code = sub.get('status_code', 'N/A')
                title = sub.get('title', 'N/A')
                
                status_class = 'status-alive' if alive else 'status-dead'
                status_text = '✅ Alive' if alive else '❌ Dead'
                
                # Get threat intelligence data
                threat_intel = sub.get('threat_intelligence', {})
                threat_score = 0
                threat_info = '-'
                
                if threat_intel and isinstance(threat_intel, dict):
                    threat_score = threat_intel.get('threat_score', 0)
                    
                    # Build threat info from provider data
                    threats = []
                    providers = threat_intel.get('providers', {})
                    
                    if providers.get('virustotal', {}).get('malicious_votes', 0) > 0:
                        threats.append(f"VT:{providers['virustotal']['malicious_votes']}")
                    if providers.get('abuseipdb', {}).get('abuse_score', 0) > 20:
                        threats.append(f"ABUSEIPDB:{providers['abuseipdb']['abuse_score']}")
                    if providers.get('urlhaus', {}).get('malicious'):
                        threats.append("URLhaus")
                    
                    threat_info = ' '.join(threats) if threats else '✓ Clean'
                
                # Color code threat score
                threat_color = '#27ae60'  # Green
                if threat_score > 70:
                    threat_color = '#e74c3c'  # Red
                elif threat_score > 40:
                    threat_color = '#e67e22'  # Orange
                
                html += f"<tr><td>{subdomain}</td><td class='{status_class}'>{status_text}</td><td>{status_code}</td><td style='color: {threat_color}; font-weight: bold;'>{threat_score}/100</td><td>{threat_info}</td><td>{title}</td></tr>"
            else:
                html += f"<tr><td>{sub}</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>"
        
        html += "</tbody></table>"
        return html
    
    def _build_threat_intel_html(self, subdomains: List[Dict[str, Any]]) -> str:
        """Build HTML section for threat intelligence summary"""
        threat_count = 0
        malicious_count = 0
        suspicious_count = 0
        clean_count = 0
        high_risk_domains = []
        
        for sub in subdomains:
            if isinstance(sub, dict):
                threat_intel = sub.get('threat_intelligence', {})
                if threat_intel and isinstance(threat_intel, dict):
                    threat_score = threat_intel.get('threat_score', 0)
                    threat_count += 1
                    
                    if threat_score > 70:
                        malicious_count += 1
                        high_risk_domains.append({
                            'domain': sub.get('subdomain', 'N/A'),
                            'score': threat_score,
                            'providers': threat_intel.get('providers', {})
                        })
                    elif threat_score > 40:
                        suspicious_count += 1
                    else:
                        clean_count += 1
        
        # Build summary stats
        html = f"""
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px;">
            <div class="stat-box" style="background: #e74c3c;">
                <div class="stat-number">{malicious_count}</div>
                <div class="stat-label">Malicious Domains</div>
            </div>
            <div class="stat-box" style="background: #e67e22;">
                <div class="stat-number">{suspicious_count}</div>
                <div class="stat-label">Suspicious Domains</div>
            </div>
            <div class="stat-box" style="background: #27ae60;">
                <div class="stat-number">{clean_count}</div>
                <div class="stat-label">Clean Domains</div>
            </div>
            <div class="stat-box" style="background: #667eea;">
                <div class="stat-number">{threat_count}</div>
                <div class="stat-label">Total Checked</div>
            </div>
        </div>
        """
        
        # Build high-risk domain details
        if high_risk_domains:
            html += "<h3>⚠️ High-Risk Domains</h3>"
            html += "<table><thead><tr><th>Domain</th><th>Threat Score</th><th>Threat Intelligence Providers</th></tr></thead><tbody>"
            
            for domain_info in high_risk_domains[:20]:
                domain = domain_info['domain']
                score = domain_info['score']
                providers = domain_info['providers']
                
                provider_html = "<ul style='margin: 0; padding-left: 20px;'>"
                
                # VirusTotal
                if 'virustotal' in providers:
                    vt = providers['virustotal']
                    if vt.get('status') == 'found':
                        mv = vt.get('malicious_votes', 0)
                        if mv > 0:
                            provider_html += f"<li>VirusTotal: <strong>{mv}</strong> AV engines detect as malicious</li>"
                
                # AbuseIPDB
                if 'abuseipdb' in providers:
                    abuseipdb = providers['abuseipdb']
                    if abuseipdb.get('status') == 'found':
                        abuse_score = abuseipdb.get('abuse_score', 0)
                        if abuse_score > 0:
                            provider_html += f"<li>AbuseIPDB: Abuse score <strong>{abuse_score}%</strong></li>"
                        if abuseipdb.get('is_blacklisted'):
                            provider_html += f"<li>AbuseIPDB: <strong>Blacklisted</strong></li>"
                
                # OTX
                if 'otx' in providers:
                    otx = providers['otx']
                    if otx.get('status') == 'found':
                        reputation = otx.get('reputation', 0)
                        if reputation < 0:
                            provider_html += f"<li>AlienVault OTX: Negative reputation score <strong>{reputation}</strong></li>"
                
                # URLhaus
                if 'urlhaus' in providers:
                    urlhaus = providers['urlhaus']
                    if urlhaus.get('malicious'):
                        threat_type = urlhaus.get('threat', 'unknown')
                        provider_html += f"<li>URLhaus: <strong>Malware hosting</strong> ({threat_type})</li>"
                
                provider_html += "</ul>"
                
                html += f"<tr><td><strong>{domain}</strong></td><td style='color: #e74c3c; font-weight: bold;'>{score}/100</td><td>{provider_html}</td></tr>"
            
            html += "</tbody></table>"
        else:
            html += "<div class='highlight'><strong>✓ No high-risk domains detected</strong></div>"
        
        return html
    
    def _build_technology_html(self, tech_fingerprint: Dict[str, Any]) -> str:
        """Build HTML table for technologies"""
        if not tech_fingerprint:
            return "<p>No technology fingerprints detected.</p>"
        
        html = "<table><thead><tr><th>URL</th><th>Server</th><th>Technologies</th></tr></thead><tbody>"
        
        for url, tech_data in list(tech_fingerprint.items())[:50]:
            server = tech_data.get('server', 'Unknown') if isinstance(tech_data, dict) else 'Unknown'
            technologies = tech_data.get('technologies', []) if isinstance(tech_data, dict) else []
            
            tech_str = ', '.join(technologies[:5]) if technologies else 'None detected'
            
            html += f"<tr><td>{url}</td><td>{server}</td><td>{tech_str}</td></tr>"
        
        html += "</tbody></table>"
        return html
    

    
    def _build_insights_html(self, insights: List[str]) -> str:
        """Build HTML list for insights"""
        if not insights:
            return "<p>No specific insights available.</p>"
        
        html = ""
        for insight in insights[:20]:
            insight_class = "insight-info"
            if any(word in insight for word in ['CRITICAL']):
                insight_class = "insight-critical"
            elif any(word in insight for word in ['HIGH']):
                insight_class = "insight-high"
            elif any(word in insight for word in ['MEDIUM']):
                insight_class = "insight-medium"
            
            html += f'<div class="insight {insight_class}">{insight}</div>'
        
        return html
    
    def _create_markdown_content(self, data: Dict[str, Any]) -> str:
        """Create formatted Markdown content"""
        target = data.get('target', 'Unknown')
        metadata = data.get('metadata', {})
        
        content = f"""# Netra Intelligence Report

## Executive Summary

**Target:** {target}  
**Scan Date:** {metadata.get('timestamp', 'Unknown')}  
**Total Findings:** {metadata.get('total_findings', 0)}  
**Modules Executed:** {len(metadata.get('scan_modules', []))}

---

## Reconnaissance Results

### Subdomain Discovery
"""
        
        # Subdomains section
        subdomains = data.get('subdomains', [])
        summary = data.get('summary', {})
        
        total_discovered = len(subdomains)
        alive_count = summary.get('alive', 0)
        dead_count = summary.get('dead', 0)
        
        content += f"**Discovered {total_discovered} unique subdomains** (passive enumeration)\n\n"
        content += f"**Responsive Subdomains: {alive_count}** | Dead: {dead_count}\n\n"
        
        if subdomains:
            # Show only ALIVE subdomains prominently
            alive_subdomains = [s for s in subdomains if isinstance(s, dict) and s.get('alive')]
            
            if alive_subdomains:
                content += "#### Responsive Subdomains:\n"
                for entry in alive_subdomains[:15]:  # Show more alive ones
                    subdomain_name = entry.get('subdomain', 'Unknown')
                    status = entry.get('status_code')
                    title = entry.get('title') or '—'
                    status_str = f" [{status}]" if status else ""
                    content += f"- `{subdomain_name}`{status_str} — {title}\n"
                
                if len(alive_subdomains) > 15:
                    content += f"- ... and {len(alive_subdomains) - 15} more\n"
                
                content += "\n#### Non-Responsive Subdomains:\n"
                dead_subdomains = [s for s in subdomains if isinstance(s, dict) and not s.get('alive')]
                if dead_subdomains:
                    content += f"({len(dead_subdomains)} subdomains did not respond)\n"
                else:
                    content += "None\n"
            else:
                content += "No responsive subdomains found.\n"
        else:
            content += "No subdomains discovered.\n"
        
        # Email harvesting section
        content += "\n### Email Intelligence\n"
        emails = data.get('emails', [])
        if emails:
            content += f"**Found {len(emails)} email addresses:**\n\n"
            for email in emails[:10]:
                content += f"- `{email}`\n"
            if len(emails) > 10:
                content += f"- ... and {len(emails) - 10} more\n"
        else:
            content += "No email addresses discovered.\n"
        
        # Technology fingerprinting section
        content += "\n### Technology Stack\n"
        tech_fingerprint = data.get('technology_fingerprint', {})
        if tech_fingerprint:
            for url, technologies in tech_fingerprint.items():
                content += f"\n**{url}:**\n"
                # Fixed: Handle both dict and list structures
                if isinstance(technologies, dict):
                    tech_list = technologies.get('technologies', [])
                    if technologies.get('server') != 'Unknown':
                        tech_list.append(f"Server: {technologies.get('server')}")
                    if technologies.get('x_powered_by') != 'Unknown':
                        tech_list.append(f"X-Powered-By: {technologies.get('x_powered_by')}")
                else:
                    tech_list = technologies
                
                for tech in tech_list:
                    content += f"- {tech}\n"
        else:
            content += "No technology fingerprints detected.\n"
        
        # Git exposure section  
        content += "\n### Repository Analysis\n"
        git_exposure = data.get('git_exposure', [])
        # Fixed: Filter out non-exposure indicators
        actual_exposures = [exp for exp in git_exposure 
                          if exp not in ["No exposures detected", "exposed_repos", "git_files"]]
        
        if actual_exposures:
            content += "**Potential exposures found:**\n\n"
            for exposure in actual_exposures[:10]:  # Limit display
                content += f"- WARNING {exposure}\n"
            if len(actual_exposures) > 10:
                content += f"- ... and {len(actual_exposures) - 10} more\n"
        else:
            content += "OK: No credential exposures detected.\n"
        
        # Shodan intelligence section
        content += "\n### Network Intelligence\n"
        shodan_data = data.get('shodan_data', {})
        if shodan_data:
            for ip, info in shodan_data.items():
                content += f"\n**IP Address:** `{ip}`\n"
                content += f"- **Location:** {info.get('country', 'Unknown')}\n"
                content += f"- **Organization:** {info.get('organization', 'Unknown')}\n"
                
                ports = info.get('ports', [])
                if ports:
                    content += f"- **Open Ports:** {', '.join(map(str, ports))}\n"
                
                vulnerabilities = info.get('vulnerabilities', [])
                if vulnerabilities:
                    content += f"- **Vulnerabilities:** {len(vulnerabilities)} CVEs detected\n"
        else:
            content += "No network intelligence available.\n"
        
        # Security insights section
        content += "\n## Security Analysis\n"
        insights = data.get('insights', [])
        if insights:
            content += "**Key Security Findings:**\n\n"
            for insight in insights[:15]:  # Limit display
                priority = 'HIGH' if any(word in insight for word in ['CRITICAL', 'HIGH']) else 'MEDIUM'
                icon = '[!]' if priority == 'HIGH' else '[*]'
                content += f"- {icon} {insight}\n"
        else:
            content += "No specific security concerns identified.\n"
        
        # Recommendations section
        content += "\n## Recommendations\n"
        content += self._generate_recommendations(data)
        
        # Footer
        content += f"\n---\n\n*Report generated by Netra on {metadata.get('timestamp', 'Unknown')}*\n"
        
        return content
    
    def _generate_recommendations(self, data: Dict[str, Any]) -> str:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Subdomain recommendations
        subdomains = data.get('subdomains', [])
        if len(subdomains) > 10:
            recommendations.append(
                "Consider reducing attack surface by consolidating or securing unused subdomains"
            )
        
        # Technology recommendations
        tech_fingerprint = data.get('technology_fingerprint', {})
        if tech_fingerprint:
            recommendations.append(
                "Review exposed technology information and consider security headers"
            )
        
        # Git exposure recommendations
        git_exposure = data.get('git_exposure', [])
        if git_exposure and git_exposure != ["No exposures detected"]:
            recommendations.append(
                "Immediately review and remediate any exposed credentials in public repositories"
            )
        
        # Network security recommendations
        shodan_data = data.get('shodan_data', {})
        for ip, info in shodan_data.items():
            ports = info.get('ports', [])
            if 22 in ports:  # SSH exposed
                recommendations.append(
                    "Secure SSH access with key-based authentication and non-standard ports"
                )
            if len(ports) > 5:
                recommendations.append(
                    "Review open ports and close unnecessary services"
                )
        
        if not recommendations:
            recommendations.append("Continue regular security monitoring and assessments")
        
        content = ""
        for i, rec in enumerate(recommendations, 1):
            content += f"{i}. {rec}\n"
        
        return content
    
    def _generate_visualizations(self, data: Dict[str, Any]):
        """Generate visualization charts and diagrams"""
        try:
            import matplotlib.pyplot as plt
            import seaborn as sns
            import pandas as pd
            
            # Fixed: Use default style instead of deprecated seaborn-v0_8
            plt.style.use('default')
            
            # Executive dashboard
            self._create_executive_dashboard(data)
            
            # Technology distribution
            self._create_technology_chart(data)
            
            # Network analysis
            self._create_network_chart(data)
            
        except ImportError:
            self.logger.warning("Matplotlib not available - skipping visualizations")
        except Exception as e:
            self.logger.error(f"Visualization generation failed: {e}")
    
    def _create_executive_dashboard(self, data: Dict[str, Any]):
        """Create executive overview dashboard"""
        try:
            import matplotlib.pyplot as plt
            
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 8))
            fig.suptitle(f"Netra Executive Dashboard - {data.get('target', 'Unknown')}", 
                        fontsize=16, fontweight='bold')
            
            # Subdomain count
            subdomain_count = len(data.get('subdomains', []))
            ax1.bar(['Subdomains'], [subdomain_count], color='skyblue')
            ax1.set_title('Subdomain Discovery')
            ax1.set_ylabel('Count')
            
            # Email count
            email_count = len(data.get('emails', []))
            ax2.bar(['Emails'], [email_count], color='lightgreen')
            ax2.set_title('Email Addresses Found')
            ax2.set_ylabel('Count')
            
            # Technology stack
            tech_count = len(data.get('technology_fingerprint', {}))
            ax3.bar(['Services'], [tech_count], color='orange')
            ax3.set_title('Technology Services')
            ax3.set_ylabel('Count')
            
            # Security insights
            insight_count = len(data.get('insights', []))
            ax4.bar(['Insights'], [insight_count], color='coral')
            ax4.set_title('Security Findings')
            ax4.set_ylabel('Count')
            
            plt.tight_layout()
            plt.savefig(os.path.join(self.viz_dir, 'executive_dashboard.png'), 
                       dpi=300, bbox_inches='tight')
            plt.close()
            
        except Exception as e:
            self.logger.error(f"Executive dashboard creation failed: {e}")
    
    def _create_technology_chart(self, data: Dict[str, Any]):
        """Create technology distribution chart"""
        try:
            import matplotlib.pyplot as plt
            
            tech_fingerprint = data.get('technology_fingerprint', {})
            if not tech_fingerprint:
                return
            
            # Count technology occurrences
            tech_counts = {}
            for url, technologies in tech_fingerprint.items():
                for tech in technologies:
                    # Extract technology name (before colon if present)
                    tech_name = tech.split(':')[0].strip()
                    tech_counts[tech_name] = tech_counts.get(tech_name, 0) + 1
            
            if tech_counts:
                plt.figure(figsize=(10, 6))
                technologies = list(tech_counts.keys())[:10]  # Top 10
                counts = [tech_counts[tech] for tech in technologies]
                
                plt.pie(counts, labels=technologies, autopct='%1.1f%%', startangle=90)
                plt.title('Technology Distribution')
                plt.axis('equal')
                
                plt.savefig(os.path.join(self.viz_dir, 'technology_distribution.png'), 
                           dpi=300, bbox_inches='tight')
                plt.close()
                
        except Exception as e:
            self.logger.error(f"Technology chart creation failed: {e}")
    
    def _create_network_chart(self, data: Dict[str, Any]):
        """Create network analysis chart"""
        try:
            import matplotlib.pyplot as plt
            
            shodan_data = data.get('shodan_data', {})
            if not shodan_data:
                return
            
            # Analyze port distribution
            all_ports = []
            for ip, info in shodan_data.items():
                all_ports.extend(info.get('ports', []))
            
            if all_ports:
                # Count port occurrences
                port_counts = {}
                for port in all_ports:
                    port_counts[port] = port_counts.get(port, 0) + 1
                
                # Create bar chart
                plt.figure(figsize=(12, 6))
                ports = sorted(port_counts.keys())
                counts = [port_counts[port] for port in ports]
                
                plt.bar([str(port) for port in ports], counts, color='steelblue')
                plt.title('Open Ports Distribution')
                plt.xlabel('Port Number')
                plt.ylabel('Frequency')
                plt.xticks(rotation=45)
                
                plt.tight_layout()
                plt.savefig(os.path.join(self.viz_dir, 'network_analysis.png'), 
                           dpi=300, bbox_inches='tight')
                plt.close()
                
        except Exception as e:
            self.logger.error(f"Network chart creation failed: {e}")
    
    def _count_findings(self, data: Dict[str, Any]) -> int:
        """Count total findings across all modules"""
        total = 0
        total += len(data.get('subdomains', []))
        total += len(data.get('emails', []))
        total += sum(len(tech) for tech in data.get('technology_fingerprint', {}).values())
        
        git_exposure = data.get('git_exposure', [])
        if git_exposure and git_exposure != ["No exposures detected"]:
            total += len(git_exposure)
        
        total += len(data.get('shodan_data', {}))
        total += len(data.get('insights', []))
        
        return total
