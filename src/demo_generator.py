#!/usr/bin/env python3
"""
Demo Report Generator - Create perfect demonstration reports without external dependencies
"""

import json
import os
from datetime import datetime

def generate_demo_report(domain: str, output_file: str):
    """Generate a realistic demo report with live subdomains"""
    
    # Realistic demo data
    demo_data = {
        "metadata": {
            "target": domain,
            "timestamp": datetime.now().isoformat(),
            "scan_modules": [
                "target", "total_unique", "subdomains", "summary", "alive", 
                "dead", "error", "high_interest", "correlated_findings",
                "risk_profile", "emails", "technology_fingerprint", 
                "git_exposure", "shodan_data", "insights"
            ],
            "total_findings": 45
        },
        "target": domain,
        "total_unique": 8,
        "subdomains": [
            {
                "subdomain": domain,
                "alive": True,
                "status_code": 200,
                "title": f"{domain.title()} - Official Website",
                "redirect_url": None,
                "content_length": 45678,
                "response_time": 0.234,
                "headers": {"Server": "nginx/1.18.0", "Content-Type": "text/html"},
                "tags": ["main", "prod"],
                "content_analysis": {"risk_level": "info", "notes": ["Main site"]}
            },
            {
                "subdomain": f"www.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"Welcome to {domain}",
                "redirect_url": f"https://{domain}",
                "content_length": 45678,
                "response_time": 0.189,
                "headers": {"Server": "nginx/1.18.0"},
                "tags": ["www", "active"],
                "content_analysis": {"risk_level": "info", "notes": ["WWW subdomain"]}
            },
            {
                "subdomain": f"api.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"{domain} API Documentation",
                "redirect_url": None,
                "content_length": 28934,
                "response_time": 0.156,
                "headers": {"Server": "gunicorn", "Content-Type": "application/json"},
                "tags": ["api", "service"],
                "content_analysis": {"risk_level": "high", "notes": ["API endpoint - check authentication"]}
            },
            {
                "subdomain": f"admin.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"{domain} Admin Panel",
                "redirect_url": None,
                "content_length": 12456,
                "response_time": 0.267,
                "headers": {"Server": "Apache/2.4.41"},
                "tags": ["admin", "internal"],
                "content_analysis": {"risk_level": "high", "notes": ["Admin panel accessible - requires authentication"]}
            },
            {
                "subdomain": f"mail.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"{domain} Mail Server",
                "redirect_url": None,
                "content_length": 8934,
                "response_time": 0.312,
                "headers": {"Server": "Postfix"},
                "tags": ["mail", "service"],
                "content_analysis": {"risk_level": "medium", "notes": ["Mail service"]}
            },
            {
                "subdomain": f"status.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"{domain} Status Page",
                "redirect_url": None,
                "content_length": 6789,
                "response_time": 0.098,
                "headers": {"Server": "nginx/1.18.0"},
                "tags": ["status", "monitoring"],
                "content_analysis": {"risk_level": "info", "notes": ["Status monitoring page"]}
            },
            {
                "subdomain": f"blog.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"{domain} Blog",
                "redirect_url": None,
                "content_length": 98765,
                "response_time": 0.234,
                "headers": {"Server": "nginx/1.18.0"},
                "tags": ["blog", "content"],
                "content_analysis": {"risk_level": "info", "notes": ["Blog platform"]}
            },
            {
                "subdomain": f"docs.{domain}",
                "alive": True,
                "status_code": 200,
                "title": f"{domain} Documentation",
                "redirect_url": None,
                "content_length": 156789,
                "response_time": 0.167,
                "headers": {"Server": "nginx/1.18.0"},
                "tags": ["docs", "knowledge"],
                "content_analysis": {"risk_level": "info", "notes": ["Public documentation"]}
            }
        ],
        "summary": {"alive": 8, "dead": 2, "error": 0},
        "alive": [
            domain, f"www.{domain}", f"api.{domain}", f"admin.{domain}",
            f"mail.{domain}", f"status.{domain}", f"blog.{domain}", f"docs.{domain}"
        ],
        "dead": [f"backup.{domain}", f"test.{domain}"],
        "error": [],
        "high_interest": [f"api.{domain}", f"admin.{domain}"],
        "correlated_findings": [
            "API endpoint detected without rate limiting",
            "Admin panel accessible on public subnet",
            "Multiple service subdomains with different technologies"
        ],
        "risk_profile": {
            "overall_score": 42,
            "grade": "B",
            "breakdown": {"findings": 15, "attack_surface": 42, "exposure": 25},
            "top_risks": ["Exposed admin panel", "API authentication may be weak"],
            "recommendations": [
                "Implement rate limiting on API",
                "Restrict admin panel to specific IPs",
                "Review mail server configuration"
            ]
        },
        "emails": [f"admin@{domain}", f"info@{domain}", f"contact@{domain}"],
        "technology_fingerprint": {
            f"https://{domain}": {
                "server": "nginx/1.18.0",
                "x_powered_by": "Unknown",
                "status_code": 200,
                "technologies": ["nginx", "HTML5", "JavaScript"]
            },
            f"https://api.{domain}": {
                "server": "gunicorn",
                "x_powered_by": "Python/Flask",
                "status_code": 200,
                "technologies": ["Python", "Flask", "REST API"]
            },
            f"https://admin.{domain}": {
                "server": "Apache/2.4.41",
                "x_powered_by": "PHP",
                "status_code": 200,
                "technologies": ["Apache", "PHP", "MySQL"]
            }
        },
        "git_exposure": ["Production database credentials in git history"],
        "shodan_data": {
            "93.184.216.34": {
                "country": "United States",
                "organization": "Example Corp",
                "ports": [80, 443, 22, 3306],
                "vulnerabilities": []
            }
        },
        "insights": [
            "HIGH: Admin panel found at admin.{} - verify access controls".format(domain),
            "MEDIUM: Multiple service subdomains detected - consider consolid ation",
            "MEDIUM: Large attack surface with 8 live services",
            "INFO: Network mapping: 8 subdomains mapped to 1 IP address",
            "INFO: Technologies detected: nginx, Apache, Python, PHP"
        ]
    }
    
    # Generate HTML report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netra Intelligence Report - {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
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
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
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
        .meta-label {{ font-weight: bold; color: #667eea; font-size: 0.9em; text-transform: uppercase; }}
        .meta-value {{ font-size: 1.3em; color: #333; margin-top: 5px; }}
        .content {{ padding: 40px; }}
        section {{ margin-bottom: 40px; }}
        h2 {{
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
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
        tr:hover {{ background: #f5f5f5; }}
        .status-alive {{ color: #27ae60; font-weight: bold; }}
        .status-dead {{ color: #e74c3c; font-weight: bold; }}
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
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ font-size: 0.9em; opacity: 0.9; }}
        .insight {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
            background: #f8f9fa;
            border-radius: 3px;
        }}
        .insight-high {{ border-left-color: #e67e22; background: #fef5f0; }}
        .insight-medium {{ border-left-color: #f39c12; background: #fffdf7; }}
        footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        .grade {{
            display: inline-block;
            width: 80px;
            height: 80px;
            line-height: 80px;
            text-align: center;
            border-radius: 50%;
            font-size: 2em;
            font-weight: bold;
            color: white;
            margin-left: 20px;
            background: #f39c12;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Netra Intelligence Report</h1>
            <p class="subtitle">Advanced Reconnaissance & Analysis Framework - DEMO MODE</p>
        </header>
        
        <div class="metadata">
            <div class="meta-item">
                <div class="meta-label">Target Domain</div>
                <div class="meta-value">{domain}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Date</div>
                <div class="meta-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Live Subdomains</div>
                <div class="meta-value">8</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Risk Grade</div>
                <div class="meta-value">B</div>
            </div>
        </div>
        
        <div class="content">
            <section>
                <h2>📊 Quick Statistics</h2>
                <div>
                    <div class="stat-box">
                        <div class="stat-number">8</div>
                        <div class="stat-label">Alive Subdomains</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">3</div>
                        <div class="stat-label">Email Addresses</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">6</div>
                        <div class="stat-label">Technologies</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">5</div>
                        <div class="stat-label">Security Insights</div>
                    </div>
                </div>
            </section>
            
            <section>
                <h2>🎯 Live Subdomains</h2>
                <table>
                    <thead><tr><th>Subdomain</th><th>Status</th><th>Status Code</th><th>Response Time</th></tr></thead>
                    <tbody>
                        <tr><td>{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>234ms</td></tr>
                        <tr><td>www.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>189ms</td></tr>
                        <tr><td>api.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>156ms</td></tr>
                        <tr><td>admin.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>267ms</td></tr>
                        <tr><td>mail.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>312ms</td></tr>
                        <tr><td>status.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>98ms</td></tr>
                        <tr><td>blog.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>234ms</td></tr>
                        <tr><td>docs.{domain}</td><td class='status-alive'>✅ Alive</td><td>200</td><td>167ms</td></tr>
                    </tbody>
                </table>
            </section>
            
            <section>
                <h2>🔧 Technology Stack</h2>
                <table>
                    <thead><tr><th>Subdomain</th><th>Server</th><th>Technologies</th></tr></thead>
                    <tbody>
                        <tr><td>{domain}</td><td>nginx/1.18.0</td><td>HTML5, JavaScript, nginx</td></tr>
                        <tr><td>api.{domain}</td><td>gunicorn</td><td>Python, Flask, REST API</td></tr>
                        <tr><td>admin.{domain}</td><td>Apache/2.4.41</td><td>PHP, MySQL, Apache</td></tr>
                    </tbody>
                </table>
            </section>
            
            <section>
                <h2>⚠️ Security Findings</h2>
                <div class="insight insight-high">🚨 HIGH: Admin panel found at admin.{domain} - verify access controls</div>
                <div class="insight insight-medium">⚠️ MEDIUM: Multiple service subdomains detected - consider consolidation</div>
                <div class="insight insight-medium">⚠️ MEDIUM: Large attack surface with 8 live services</div>
                <div class="insight">ℹ️ INFO: Network mapping: 8 subdomains mapped to 1 IP address</div>
                <div class="insight">ℹ️ INFO: Technologies detected: nginx, Apache, Python, PHP</div>
            </section>
            
            <section>
                <h2>📧 Email Addresses Found</h2>
                <ul>
                    <li>admin@{domain}</li>
                    <li>info@{domain}</li>
                    <li>contact@{domain}</li>
                </ul>
            </section>
        </div>
        
        <footer>
            <p><strong>Demo Report Generated by Netra Intelligence Framework</strong></p>
            <p>This is a demonstration report showing the capabilities of the Netra reconnaissance tool</p>
        </footer>
    </div>
</body>
</html>"""
    
    # Write files
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    json_file = output_file.replace('.html', '.json')
    with open(json_file, 'w') as f:
        json.dump(demo_data, f, indent=2)
    
    print(f"✅ Demo HTML Report: {output_file}")
    print(f"✅ Demo JSON Report: {json_file}")
    return output_file

if __name__ == "__main__":
    domain = input("Enter target domain (default: demo.com): ").strip() or "demo.com"
    output = f"{domain.replace('.', '_')}-demo.html"
    generate_demo_report(domain, output)
    print(f"\n🎉 Perfect demo report created! Open {output} in your browser")
