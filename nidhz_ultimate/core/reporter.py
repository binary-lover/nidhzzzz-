"""
Professional report generator for NIDHZ
"""

import os
import json
import csv
from datetime import datetime
from typing import Dict, List, Any
import html


class Reporter:
    """Generates multiple report formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_html_report(self, results: Dict[str, Any]):
        """Generate interactive HTML report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>NIDHZ Security Scan Report - {results['target']}</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    line-height: 1.6; 
                    color: #333; 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                }}
                
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    padding: 20px;
                }}
                
                .report-card {{
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    overflow: hidden;
                    margin: 40px auto;
                }}
                
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                    text-align: center;
                }}
                
                .header h1 {{
                    font-size: 2.5em;
                    margin-bottom: 10px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 15px;
                }}
                
                .header .logo {{
                    font-size: 2em;
                }}
                
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    padding: 30px;
                    background: #f8f9fa;
                }}
                
                .summary-card {{
                    background: white;
                    padding: 25px;
                    border-radius: 15px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    text-align: center;
                    transition: transform 0.3s;
                }}
                
                .summary-card:hover {{
                    transform: translateY(-5px);
                }}
                
                .summary-card h3 {{
                    color: #667eea;
                    margin-bottom: 15px;
                    font-size: 1.1em;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                }}
                
                .summary-card .number {{
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #764ba2;
                    margin: 10px 0;
                }}
                
                .section {{
                    padding: 30px;
                    border-bottom: 1px solid #eee;
                }}
                
                .section:last-child {{
                    border-bottom: none;
                }}
                
                .section h2 {{
                    color: #667eea;
                    margin-bottom: 20px;
                    padding-bottom: 10px;
                    border-bottom: 3px solid #764ba2;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }}
                
                .tech-badges {{
                    display: flex;
                    flex-wrap: wrap;
                    gap: 10px;
                    margin: 20px 0;
                }}
                
                .tech-badge {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 8px 20px;
                    border-radius: 50px;
                    font-size: 0.9em;
                    font-weight: 500;
                }}
                
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                
                th {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px;
                    text-align: left;
                }}
                
                td {{
                    padding: 12px 15px;
                    border-bottom: 1px solid #eee;
                }}
                
                tr:hover {{
                    background: #f8f9fa;
                }}
                
                .vuln-card {{
                    background: #fff5f5;
                    border-left: 4px solid #fc8181;
                    padding: 20px;
                    margin: 15px 0;
                    border-radius: 10px;
                }}
                
                .vuln-card.high {{ border-color: #fc8181; background: #fff5f5; }}
                .vuln-card.medium {{ border-color: #f6ad55; background: #fffaf0; }}
                .vuln-card.low {{ border-color: #68d391; background: #f0fff4; }}
                
                .confidence-badge {{
                    display: inline-block;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 0.8em;
                    font-weight: bold;
                    margin-left: 10px;
                }}
                
                .high-badge {{ background: #fc8181; color: white; }}
                .medium-badge {{ background: #f6ad55; color: white; }}
                .low-badge {{ background: #68d391; color: white; }}
                
                .footer {{
                    text-align: center;
                    padding: 30px;
                    color: #666;
                    font-size: 0.9em;
                    background: #f8f9fa;
                }}
                
                @media (max-width: 768px) {{
                    .container {{ padding: 10px; }}
                    .header {{ padding: 20px; }}
                    .header h1 {{ font-size: 1.8em; }}
                    table {{ display: block; overflow-x: auto; }}
                }}
            </style>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        </head>
        <body>
            <div class="container">
                <div class="report-card">
                    <!-- Header -->
                    <div class="header">
                        <h1>
                            <i class="fas fa-shield-alt logo"></i>
                            NIDHZ Security Scan Report
                        </h1>
                        <p>Comprehensive Web Vulnerability Assessment</p>
                    </div>
                    
                    <!-- Summary Section -->
                    <div class="summary">
                        <div class="summary-card">
                            <h3><i class="fas fa-target"></i> Target</h3>
                            <p>{html.escape(results['target'])}</p>
                        </div>
                        
                        <div class="summary-card">
                            <h3><i class="fas fa-calendar"></i> Scan Date</h3>
                            <p>{timestamp}</p>
                        </div>
                        
                        <div class="summary-card">
                            <h3><i class="fas fa-folder-open"></i> Directories Found</h3>
                            <div class="number">{len(results['directories'])}</div>
                        </div>
                        
                        <div class="summary-card">
                            <h3><i class="fas fa-bug"></i> Vulnerabilities</h3>
                            <div class="number">{len(results['xss_vulnerabilities']) + len(results['sqli_vulnerabilities'])}</div>
                        </div>
                    </div>
                    
                    <!-- Technology Stack -->
                    <div class="section">
                        <h2><i class="fas fa-microchip"></i> Technology Stack</h2>
                        <div class="tech-badges">
                            {''.join([f'<span class="tech-badge">{tech}</span>' for tech in results['technology']]) if results['technology'] else '<p>No specific technology detected</p>'}
                        </div>
                    </div>
                    
                    <!-- Discovered Directories -->
                    <div class="section">
                        <h2><i class="fas fa-sitemap"></i> Discovered Directories ({len(results['directories'])})</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>URL</th>
                                    <th>Status</th>
                                    <th>Size</th>
                                    <th>Title</th>
                                </tr>
                            </thead>
                            <tbody>
                                {self._generate_directory_rows(results['directories'][:50])}
                            </tbody>
                        </table>
                    </div>
                    
                    <!-- XSS Vulnerabilities -->
                    {self._generate_vuln_section('XSS Vulnerabilities', results['xss_vulnerabilities'], 'fa-exclamation-triangle')}
                    
                    <!-- SQLi Vulnerabilities -->
                    {self._generate_vuln_section('SQL Injection Vulnerabilities', results['sqli_vulnerabilities'], 'fa-database')}
                    
                    <!-- Footer -->
                    <div class="footer">
                        <p>Generated by <strong>NIDHZ Ultimate v2.0</strong></p>
                        <p><i class="fas fa-exclamation-circle"></i> This report is for authorized security testing only.</p>
                        <p>© {datetime.now().year} NIDHZ Security Team. All rights reserved.</p>
                    </div>
                </div>
            </div>
            
            <script>
                // Add interactivity
                document.addEventListener('DOMContentLoaded', function() {{
                    // Toggle vulnerability details
                    document.querySelectorAll('.vuln-card').forEach(card => {{
                        card.addEventListener('click', function() {{
                            const details = this.querySelector('.vuln-details');
                            if (details) {{
                                details.style.display = details.style.display === 'none' ? 'block' : 'none';
                            }}
                        }});
                    }});
                    
                    // Copy URLs on click
                    document.querySelectorAll('td:first-child').forEach(td => {{
                        td.style.cursor = 'pointer';
                        td.title = 'Click to copy URL';
                        td.addEventListener('click', function() {{
                            navigator.clipboard.writeText(this.textContent);
                            const original = this.textContent;
                            this.textContent = 'Copied!';
                            setTimeout(() => this.textContent = original, 1000);
                        }});
                    }});
                }});
            </script>
        </body>
        </html>
        """
        
        filepath = os.path.join(self.output_dir, 'report.html')
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated: {filepath}")
    
    def _generate_directory_rows(self, directories: List[Dict]) -> str:
        """Generate HTML table rows for directories"""
        rows = []
        for dir_info in directories:
            status = dir_info.get('status_code', 0)
            status_icon = self._get_status_icon(status)
            
            row = f"""
            <tr>
                <td>{html.escape(dir_info.get('url', ''))}</td>
                <td>{status_icon} {status}</td>
                <td>{dir_info.get('content_length', 0):,} bytes</td>
                <td>{html.escape(dir_info.get('title', ''))[:50]}</td>
            </tr>
            """
            rows.append(row)
        
        return ''.join(rows)
    
    def _generate_vuln_section(self, title: str, vulnerabilities: List[Dict], icon: str) -> str:
        """Generate vulnerability section HTML"""
        if not vulnerabilities:
            return ""
        
        vuln_cards = []
        for vuln in vulnerabilities:
            confidence = vuln.get('confidence', 'low').lower()
            confidence_badge = f'<span class="confidence-badge {confidence}-badge">{confidence.upper()}</span>'
            
            card = f"""
            <div class="vuln-card {confidence}">
                <h3>{vuln.get('type', 'Vulnerability')} {confidence_badge}</h3>
                <p><strong>URL:</strong> {html.escape(vuln.get('url', ''))}</p>
                <p><strong>Parameter:</strong> {html.escape(vuln.get('parameter', 'N/A'))}</p>
                <p><strong>Payload:</strong> <code>{html.escape(vuln.get('payload', ''))}</code></p>
                {f'<p><strong>Evidence:</strong><br><pre>{html.escape(vuln.get("evidence", ""))}</pre></p>' if vuln.get('evidence') else ''}
            </div>
            """
            vuln_cards.append(card)
        
        return f"""
        <div class="section">
            <h2><i class="fas {icon}"></i> {title} ({len(vulnerabilities)})</h2>
            {''.join(vuln_cards)}
        </div>
        """
    
    def _get_status_icon(self, status_code: int) -> str:
        """Get Font Awesome icon for status code"""
        if 200 <= status_code < 300:
            return '<i class="fas fa-check-circle" style="color: #68d391"></i>'
        elif 300 <= status_code < 400:
            return '<i class="fas fa-exchange-alt" style="color: #f6ad55"></i>'
        elif 400 <= status_code < 500:
            return '<i class="fas fa-lock" style="color: #fc8181"></i>'
        elif status_code >= 500:
            return '<i class="fas fa-exclamation-circle" style="color: #764ba2"></i>'
        else:
            return '<i class="fas fa-question-circle" style="color: #a0aec0"></i>'
    
    def generate_json_report(self, results: Dict[str, Any]):
        """Generate JSON report"""
        filepath = os.path.join(self.output_dir, 'report.json')
        
        # Clean up results for JSON serialization
        clean_results = self._clean_for_json(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(clean_results, f, indent=2, default=str)
        
        print(f"[+] JSON report generated: {filepath}")
    
    def generate_csv_report(self, results: Dict[str, Any]):
        """Generate CSV reports"""
        # Directories CSV
        if results['directories']:
            dir_file = os.path.join(self.output_dir, 'directories.csv')
            with open(dir_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Status', 'Size', 'Title', 'Response Time'])
                
                for dir_info in results['directories']:
                    writer.writerow([
                        dir_info.get('url', ''),
                        dir_info.get('status_code', 0),
                        dir_info.get('content_length', 0),
                        dir_info.get('title', ''),
                        dir_info.get('response_time', 0)
                    ])
            
            print(f"[+] Directories CSV generated: {dir_file}")
        
        # XSS Vulnerabilities CSV
        if results['xss_vulnerabilities']:
            xss_file = os.path.join(self.output_dir, 'xss_vulnerabilities.csv')
            with open(xss_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'URL', 'Parameter', 'Payload', 'Confidence', 'Evidence'])
                
                for vuln in results['xss_vulnerabilities']:
                    writer.writerow([
                        vuln.get('type', ''),
                        vuln.get('url', ''),
                        vuln.get('parameter', ''),
                        vuln.get('payload', ''),
                        vuln.get('confidence', ''),
                        vuln.get('evidence', '')[:500]
                    ])
            
            print(f"[+] XSS Vulnerabilities CSV generated: {xss_file}")
        
        # SQLi Vulnerabilities CSV
        if results['sqli_vulnerabilities']:
            sqli_file = os.path.join(self.output_dir, 'sqli_vulnerabilities.csv')
            with open(sqli_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Subtype', 'URL', 'Parameter', 'Payload', 'Confidence', 'Database', 'Evidence'])
                
                for vuln in results['sqli_vulnerabilities']:
                    writer.writerow([
                        vuln.get('type', ''),
                        vuln.get('subtype', ''),
                        vuln.get('url', ''),
                        vuln.get('parameter', ''),
                        vuln.get('payload', ''),
                        vuln.get('confidence', ''),
                        vuln.get('database', ''),
                        vuln.get('evidence', '')[:500]
                    ])
            
            print(f"[+] SQLi Vulnerabilities CSV generated: {sqli_file}")
    
    def generate_markdown_report(self, results: Dict[str, Any]):
        """Generate Markdown report"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        md_content = f"""# NIDHZ Security Scan Report

## 📋 Executive Summary

| Metric | Value |
|--------|-------|
| **Target** | `{results['target']}` |
| **Scan Date** | {timestamp} |
| **Directories Found** | {len(results['directories'])} |
| **XSS Vulnerabilities** | {len(results['xss_vulnerabilities'])} |
| **SQLi Vulnerabilities** | {len(results['sqli_vulnerabilities'])} |
| **Total Vulnerabilities** | {len(results['xss_vulnerabilities']) + len(results['sqli_vulnerabilities'])} |

## 🏗️ Technology Stack

{', '.join(results['technology']) if results['technology'] else 'No specific technology detected'}

## 📁 Discovered Directories

Found **{len(results['directories'])}** directories:
