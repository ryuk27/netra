"""
Standalone visualization module for Netra Framework
Generates visual charts and graphs from reconnaissance data
"""

import os
import sys
import json
import argparse
import logging
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime
from typing import Dict, Any, List

class ReconVisualizer:
    """Generate visualizations from reconnaissance data"""
    
    def __init__(self, output_dir: str = "visuals"):
        self.output_dir = output_dir
        self.setup_directories()
        self.setup_logging()
        self.setup_style()
        
    def setup_directories(self):
        """Create output directories"""
        os.makedirs(self.output_dir, exist_ok=True)
        
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def setup_style(self):
        """Setup matplotlib style"""
        # Fix for headless Linux environments
        import matplotlib
        matplotlib.use('Agg')  # Use non-interactive backend
        
        try:
            plt.style.use('seaborn-v0_8')
        except:
            try:
                plt.style.use('seaborn')
            except:
                plt.style.use('default')
        
        sns.set_palette("husl")
        
    def load_data(self, json_file: str) -> Dict[str, Any]:
        """Load data from JSON file"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            self.logger.info(f"Loaded data from {json_file}")
            return data
        except Exception as e:
            self.logger.error(f"Failed to load {json_file}: {e}")
            return {}
            
    def generate_all_visuals(self, data: Dict[str, Any], target: str = None):
        """Generate all available visualizations"""
        if not target:
            target = data.get('target', 'unknown')
            
        self.logger.info(f"Generating visualizations for {target}")
        
        # Generate individual charts
        self.plot_subdomain_analysis(data, target)
        self.plot_technology_stack(data, target)
        self.plot_security_insights(data, target)
        self.plot_network_analysis(data, target)
        self.plot_overview_dashboard(data, target)
        
        self.logger.info(f"All visualizations saved to {self.output_dir}/")
        
    def plot_subdomain_analysis(self, data: Dict[str, Any], target: str):
        """Create subdomain analysis charts"""
        subdomains = data.get('subdomains', [])
        
        if not subdomains:
            self.logger.warning("No subdomain data found")
            return
            
        # Categorize subdomains
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
        
        # Create visualization
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(f'Subdomain Analysis - {target}', fontsize=16, fontweight='bold')
        
        # Pie chart
        valid_categories = {k: v for k, v in categorized.items() if v > 0}
        if valid_categories:
            ax1.pie(valid_categories.values(), labels=valid_categories.keys(), autopct='%1.1f%%')
            ax1.set_title('Subdomain Distribution')
        
        # Bar chart
        ax2.bar(categorized.keys(), categorized.values())
        ax2.set_title('Subdomain Count by Category')
        ax2.tick_params(axis='x', rotation=45)
        
        # Subdomain length analysis
        lengths = [len(sub) for sub in subdomains]
        ax3.hist(lengths, bins=10, alpha=0.7)
        ax3.set_title('Subdomain Length Distribution')
        ax3.set_xlabel('Length (characters)')
        ax3.set_ylabel('Count')
        
        # Top-level analysis
        tlds = {}
        for sub in subdomains:
            if '.' in sub:
                tld = sub.split('.')[-1]
                tlds[tld] = tlds.get(tld, 0) + 1
        
        if tlds:
            ax4.bar(tlds.keys(), tlds.values())
            ax4.set_title('Top-Level Domain Distribution')
            ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/subdomain_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("Generated subdomain analysis chart")
        
    def plot_technology_stack(self, data: Dict[str, Any], target: str):
        """Create technology stack visualization"""
        tech_data = data.get('technology_fingerprint', {})
        
        if not tech_data:
            self.logger.warning("No technology data found")
            return
            
        # Extract server information
        servers = []
        status_codes = []
        content_types = []
        
        for url, tech_info in tech_data.items():
            if isinstance(tech_info, dict):
                server = tech_info.get('server', 'Unknown')
                status = tech_info.get('status_code', 0)
                content = tech_info.get('content_type', 'Unknown')
                
                servers.append(server)
                status_codes.append(status)
                content_types.append(content.split(';')[0])  # Remove charset info
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(f'Technology Stack Analysis - {target}', fontsize=16, fontweight='bold')
        
        # Server distribution
        server_counts = pd.Series(servers).value_counts()
        if len(server_counts) > 0:
            ax1.pie(server_counts.values, labels=server_counts.index, autopct='%1.1f%%')
            ax1.set_title('Web Server Distribution')
        
        # Status code analysis
        status_counts = pd.Series(status_codes).value_counts()
        colors = ['green' if code == 200 else 'red' if code >= 400 else 'orange' 
                 for code in status_counts.index]
        ax2.bar(status_counts.index.astype(str), status_counts.values, color=colors)
        ax2.set_title('HTTP Status Code Distribution')
        ax2.set_xlabel('Status Code')
        ax2.set_ylabel('Count')
        
        # Content type analysis
        content_counts = pd.Series(content_types).value_counts()
        ax3.barh(content_counts.index, content_counts.values)
        ax3.set_title('Content Type Distribution')
        ax3.set_xlabel('Count')
        
        # Technology timeline (simulated)
        ax4.plot(range(len(tech_data)), [1] * len(tech_data), 'o-', markersize=8)
        ax4.set_title('Technology Scan Timeline')
        ax4.set_xlabel('Scan Order')
        ax4.set_ylabel('Response')
        ax4.set_ylim(0, 2)
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/technology_stack.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("Generated technology stack chart")
        
    def plot_security_insights(self, data: Dict[str, Any], target: str):
        """Create security insights visualization"""
        insights = data.get('insights', [])
        
        if not insights:
            self.logger.warning("No security insights found")
            return
            
        # Categorize by severity
        severity_counts = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
        }
        
        for insight in insights:
            for severity in severity_counts.keys():
                if insight.startswith(severity):
                    severity_counts[severity] += 1
                    break
        
        # Filter out zero counts
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(f'Security Analysis - {target}', fontsize=16, fontweight='bold')
        
        # Severity distribution pie chart
        if severity_counts:
            colors = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 
                     'LOW': 'blue', 'INFO': 'green'}
            chart_colors = [colors.get(k, 'gray') for k in severity_counts.keys()]
            
            ax1.pie(severity_counts.values(), labels=severity_counts.keys(), 
                   colors=chart_colors, autopct='%1.1f%%')
            ax1.set_title('Security Issue Severity')
        
        # Severity bar chart
        if severity_counts:
            bars = ax2.bar(severity_counts.keys(), severity_counts.values(), 
                          color=[colors.get(k, 'gray') for k in severity_counts.keys()])
            ax2.set_title('Security Issues by Severity')
            ax2.set_ylabel('Count')
            
            # Add value labels
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
        
        # Security score calculation
        base_score = 100
        deductions = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 10, 'LOW': 5, 'INFO': 1}
        
        total_deduction = sum(severity_counts.get(sev, 0) * ded 
                             for sev, ded in deductions.items())
        security_score = max(0, base_score - total_deduction)
        
        # Security score gauge
        angles = [0, 25, 50, 75, 100]
        colors_gauge = ['red', 'orange', 'yellow', 'lightgreen', 'green']
        
        for i, (angle, color) in enumerate(zip(angles[:-1], colors_gauge)):
            if security_score >= angle:
                ax3.barh(0, 25, left=angle, color=color, alpha=0.7, height=0.5)
        
        ax3.axvline(x=security_score, color='black', linewidth=3)
        ax3.set_xlim(0, 100)
        ax3.set_ylim(-0.5, 0.5)
        ax3.set_xlabel('Security Score')
        ax3.set_title(f'Security Score: {security_score}/100')
        ax3.set_yticks([])
        
        # Insights timeline
        timeline_data = list(range(len(insights)))
        severities_numeric = []
        for insight in insights:
            for i, severity in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']):
                if insight.startswith(severity):
                    severities_numeric.append(4-i)
                    break
            else:
                severities_numeric.append(0)
        
        ax4.plot(timeline_data, severities_numeric, 'o-', linewidth=2, markersize=6)
        ax4.set_title('Security Issues Discovery Timeline')
        ax4.set_xlabel('Discovery Order')
        ax4.set_ylabel('Severity Level')
        ax4.set_yticks([0, 1, 2, 3, 4])
        ax4.set_yticklabels(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/security_insights.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("Generated security insights chart")
        
    def plot_network_analysis(self, data: Dict[str, Any], target: str):
        """Create network analysis visualization"""
        # This would analyze Shodan data, emails, etc.
        # For now, create a placeholder with available data
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle(f'Network Analysis - {target}', fontsize=16, fontweight='bold')
        
        # Metadata analysis
        metadata = data.get('metadata', {})
        total_findings = metadata.get('total_findings', 0)
        modules = metadata.get('scan_modules', [])
        
        # Findings distribution
        ax1.text(0.5, 0.7, f'Total Findings: {total_findings}', 
                ha='center', va='center', fontsize=16, transform=ax1.transAxes)
        ax1.text(0.5, 0.5, f'Modules Used: {len(modules)}', 
                ha='center', va='center', fontsize=14, transform=ax1.transAxes)
        ax1.text(0.5, 0.3, f'Target: {target}', 
                ha='center', va='center', fontsize=12, transform=ax1.transAxes)
        ax1.set_title('Scan Summary')
        ax1.axis('off')
        
        # Module coverage
        if modules:
            ax2.pie([1] * len(modules), labels=modules, autopct=lambda pct: f'{pct:.0f}%')
            ax2.set_title('Module Coverage')
        
        # Placeholder for network data
        ax3.text(0.5, 0.5, 'Network Analysis\n(Requires Shodan/Network Data)', 
                ha='center', va='center', transform=ax3.transAxes)
        ax3.set_title('Network Exposure')
        ax3.axis('off')
        
        # Placeholder for vulnerability data
        ax4.text(0.5, 0.5, 'Vulnerability Analysis\n(Requires CVE Data)', 
                ha='center', va='center', transform=ax4.transAxes)
        ax4.set_title('Vulnerability Assessment')
        ax4.axis('off')
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/network_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("Generated network analysis chart")
        
    def plot_overview_dashboard(self, data: Dict[str, Any], target: str):
        """Create comprehensive overview dashboard"""
        fig = plt.figure(figsize=(20, 12))
        fig.suptitle(f'Netra Overview Dashboard - {target}', 
                     fontsize=20, fontweight='bold')
        
        # Calculate statistics
        stats = {
            'Subdomains': len(data.get('subdomains', [])),
            'Technologies': len(data.get('technology_fingerprint', {})),
            'Insights': len(data.get('insights', [])),
            'Findings': data.get('metadata', {}).get('total_findings', 0)
        }
        
        # Main statistics
        ax1 = plt.subplot(3, 4, 1)
        bars = ax1.bar(stats.keys(), stats.values(), 
                      color=['blue', 'green', 'orange', 'purple'])
        ax1.set_title('Discovery Statistics', fontweight='bold')
        ax1.tick_params(axis='x', rotation=45)
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')
        
        # Security overview
        ax2 = plt.subplot(3, 4, 2)
        insights = data.get('insights', [])
        if insights:
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for insight in insights:
                for severity in severity_counts.keys():
                    if insight.startswith(severity):
                        severity_counts[severity] += 1
                        break
            
            severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
            if severity_counts:
                colors = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 
                         'LOW': 'blue', 'INFO': 'green'}
                chart_colors = [colors.get(k, 'gray') for k in severity_counts.keys()]
                ax2.pie(severity_counts.values(), labels=severity_counts.keys(), 
                       colors=chart_colors, autopct='%1.1f%%')
        ax2.set_title('Security Risk Distribution', fontweight='bold')
        
        # Technology breakdown
        ax3 = plt.subplot(3, 4, 3)
        tech_data = data.get('technology_fingerprint', {})
        if tech_data:
            status_codes = [info.get('status_code', 0) for info in tech_data.values() 
                           if isinstance(info, dict)]
            successful = sum(1 for code in status_codes if code == 200)
            failed = len(status_codes) - successful
            
            ax3.pie([successful, failed], labels=['Successful', 'Failed'], 
                   colors=['green', 'red'], autopct='%1.1f%%')
        ax3.set_title('Technology Scan Results', fontweight='bold')
        
        # Timeline
        ax4 = plt.subplot(3, 4, 4)
        modules = data.get('metadata', {}).get('scan_modules', [])
        if modules:
            ax4.plot(range(len(modules)), modules, 'o-', linewidth=2, markersize=8)
            ax4.set_title('Scan Module Timeline', fontweight='bold')
            ax4.tick_params(axis='x', rotation=45)
        
        # Detailed insights (spanning multiple columns)
        ax5 = plt.subplot(3, 1, 2)
        if insights:
            insights_text = '\n'.join([f"• {insight}" for insight in insights[:10]])
            ax5.text(0.05, 0.95, 'Top Security Insights:', fontweight='bold', 
                    fontsize=12, transform=ax5.transAxes, va='top')
            ax5.text(0.05, 0.85, insights_text, fontsize=10, 
                    transform=ax5.transAxes, va='top')
        ax5.axis('off')
        
        # Summary metrics
        ax6 = plt.subplot(3, 1, 3)
        timestamp = data.get('metadata', {}).get('timestamp', 'Unknown')
        summary_text = f"""
Scan Summary for {target}
Timestamp: {timestamp}
Total Findings: {stats['Findings']}
Subdomains Discovered: {stats['Subdomains']}
Technologies Identified: {stats['Technologies']}
Security Issues: {stats['Insights']}
        """
        ax6.text(0.05, 0.95, summary_text, fontsize=12, 
                transform=ax6.transAxes, va='top', fontfamily='monospace')
        ax6.axis('off')
        
        plt.tight_layout()
        plt.savefig(f'{self.output_dir}/overview_dashboard.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("Generated overview dashboard")

def main():
    """Command-line interface for visualization generation"""
    parser = argparse.ArgumentParser(description='Generate visualizations from Netra data')
    parser.add_argument('-i', '--input', required=True, 
                       help='Input JSON file with reconnaissance data')
    parser.add_argument('-o', '--output', default='visuals', 
                       help='Output directory for visualizations (default: visuals)')
    parser.add_argument('-t', '--type', choices=['all', 'subdomains', 'technology', 'security', 'network', 'dashboard'], 
                       default='all', help='Type of visualization to generate')
    parser.add_argument('--target', help='Target name override')
    
    args = parser.parse_args()
    
    print("🎨 Netra Visualizer")
    print("=" * 50)
    
    # Initialize visualizer
    visualizer = ReconVisualizer(args.output)
    
    # Load data
    data = visualizer.load_data(args.input)
    if not data:
        print("❌ Failed to load data")
        return
    
    target = args.target or data.get('target', 'unknown')
    
    # Generate visualizations based on type
    if args.type == 'all':
        visualizer.generate_all_visuals(data, target)
    elif args.type == 'subdomains':
        visualizer.plot_subdomain_analysis(data, target)
    elif args.type == 'technology':
        visualizer.plot_technology_stack(data, target)
    elif args.type == 'security':
        visualizer.plot_security_insights(data, target)
    elif args.type == 'network':
        visualizer.plot_network_analysis(data, target)
    elif args.type == 'dashboard':
        visualizer.plot_overview_dashboard(data, target)
    
    print(f"✅ Visualizations generated in {args.output}/")

if __name__ == "__main__":
    main()
