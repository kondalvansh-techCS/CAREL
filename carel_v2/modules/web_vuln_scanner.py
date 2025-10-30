#!/usr/bin/env python3
"""
Enhanced Web Vulnerability Scanner for CAREL v2.0
Maintains all original features + adds NVD CVE intelligence
"""

import requests
import json
from typing import Dict, List, Any
from datetime import datetime

class WebVulnScanner:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.nvd_api_key = config.get("nvd_api_key")
        self.tech_cpe_mapping = {
            "WordPress": "cpe:/a:wordpress:wordpress",
            "Joomla": "cpe:/a:joomla:joomla",
            "Drupal": "cpe:/a:drupal:drupal",
            "Apache": "cpe:/a:apache:http_server",
            "Nginx": "cpe:/a:nginx:nginx",
            "PHP": "cpe:/a:php:php",
            "Node.js": "cpe:/a:nodejs:nodejs",
            "React": "cpe:/a:facebook:react",
            "Express.js": "cpe:/a:expressjs:express"
        }
    
    def query_nvd_for_technology(self, technology: str) -> List[Dict]:
        """NEW: Query NVD API for technology-specific vulnerabilities"""
        if not self.nvd_api_key:
            return []
        
        try:
            cpe_name = self.tech_cpe_mapping.get(technology, "")
            if not cpe_name:
                return []
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": 3,
                "sortBy": "publishedDate",
                "sortOrder": "desc"
            }
            headers = {
                "apiKey": self.nvd_api_key
            }
            
            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for vuln in data.get("vulnerabilities", [])[:3]:
                    cve_data = vuln.get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    
                    # Get CVSS score
                    cvss_score = "Unknown"
                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    
                    vulnerabilities.append({
                        "cve_id": cve_data.get("id", "Unknown"),
                        "description": cve_data.get("descriptions", [{}])[0].get("value", "No description"),
                        "cvss_score": cvss_score,
                        "published": cve_data.get("published", "Unknown"),
                        "technology": technology
                    })
                
                return vulnerabilities
            else:
                self.logger.debug(f"NVD API returned status: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.debug(f"NVD query failed for {technology}: {e}")
            return []
    
    def detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies used by the target"""
        technologies = []
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            content = response.text.lower()
            
            # Simple technology detection
            tech_indicators = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Joomla": ["joomla", "media/jui"],
                "Drupal": ["drupal", "sites/all"],
                "Apache": ["server: apache", "apache"],
                "Nginx": ["server: nginx", "nginx"],
                "PHP": ["x-powered-by: php", ".php"],
                "React": ["react", "__react"],
                "Node.js": ["x-powered-by: express", "node.js"]
            }
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in str(headers).lower() or indicator in content:
                        technologies.append(tech)
                        break
            
            return list(set(technologies))  # Remove duplicates
            
        except Exception as e:
            self.logger.error(f"Technology detection failed: {e}")
            return []
    
    def scan_website(self, url: str, scan_depth: str = "basic", timeout: int = 30) -> Dict[str, Any]:
        """ORIGINAL METHOD ENHANCED with NVD integration"""
        
        # FIX: Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url  # Use HTTP first for better connectivity
        
        self.logger.info(f"🌐 Starting web vulnerability scan for {url}")
        self.logger.info(f"🔍 Scan depth: {scan_depth}, NVD CVE integration: {'ACTIVE' if self.nvd_api_key else 'INACTIVE'}")
        
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "scan_depth": scan_depth,
            "technologies_detected": [],
            "security_headers": {},
            "vulnerabilities": [],
            "nvd_cves": [],
            "summary": {
                "total_technologies": 0,
                "total_vulnerabilities": 0,
                "total_cves": 0,
                "high_risk_cves": 0
            }
        }
        
        try:
            # Try to connect to the target
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            # 1. Detect technologies
            technologies = self.detect_technologies(url)
            results["technologies_detected"] = technologies
            results["summary"]["total_technologies"] = len(technologies)
            
            # 2. NEW: Query NVD for each detected technology
            all_cves = []
            if self.nvd_api_key:
                for tech in technologies:
                    tech_cves = self.query_nvd_for_technology(tech)
                    all_cves.extend(tech_cves)
            
            results["nvd_cves"] = all_cves
            results["summary"]["total_cves"] = len(all_cves)
            results["summary"]["high_risk_cves"] = len([cve for cve in all_cves if isinstance(cve.get('cvss_score'), (int, float)) and cve.get('cvss_score', 0) >= 7.0])
            
            # 3. ORIGINAL: Security headers check
            security_headers = self._check_security_headers(response.headers)
            results["security_headers"] = security_headers
            
            # 4. ORIGINAL: Basic vulnerability checks based on scan depth
            basic_vulns = self._perform_basic_checks(url, response, scan_depth)
            results["vulnerabilities"] = basic_vulns
            results["summary"]["total_vulnerabilities"] = len(basic_vulns) + len(all_cves)
            
            self.logger.info(f"✅ Web scan completed for {url}")
            
        except Exception as e:
            self.logger.error(f"❌ Web vulnerability scan failed: {e}")
            results["error"] = str(e)
        
        return results
    
    def _check_security_headers(self, headers: Dict) -> Dict:
        """ORIGINAL: Check for important security headers"""
        security_headers = {
            'Content-Security-Policy': 'Missing',
            'Strict-Transport-Security': 'Missing', 
            'X-Frame-Options': 'Missing',
            'X-Content-Type-Options': 'Missing',
            'X-XSS-Protection': 'Missing',
            'Referrer-Policy': 'Missing'
        }
        
        for header in security_headers.keys():
            if header in headers:
                security_headers[header] = f"Present: {headers[header][:50]}"
        
        return security_headers
    
    def _perform_basic_checks(self, url: str, response, scan_depth: str) -> List[Dict]:
        """ORIGINAL: Perform basic web vulnerability checks"""
        vulnerabilities = []
        
        # Basic checks for all scan depths
        if not url.startswith('https://'):
            vulnerabilities.append({
                "type": "Missing HTTPS",
                "severity": "Medium",
                "description": "Website not using HTTPS encryption"
            })
        
        if 'Server' in response.headers:
            vulnerabilities.append({
                "type": "Server Information Disclosure",
                "severity": "Low", 
                "description": f"Server header reveals: {response.headers['Server'][:50]}"
            })
        
        # Additional checks for advanced scans
        if scan_depth in ["advanced", "full"]:
            if response.status_code == 200 and "admin" in response.text.lower():
                vulnerabilities.append({
                    "type": "Admin Interface Detected",
                    "severity": "Info",
                    "description": "Admin interface accessible"
                })
        
        return vulnerabilities
    
    def generate_scan_report(self, results: Dict) -> str:
        """ORIGINAL REPORT METHOD with NVD enhancements"""
        report = []
        report.append("🌐 WEB VULNERABILITY SCAN REPORT")
        report.append("=" * 55)
        report.append(f"Target: {results.get('url', 'Unknown')}")
        report.append(f"Scan Date: {results.get('timestamp', 'Unknown')}")
        report.append(f"Scan Depth: {results.get('scan_depth', 'Unknown').upper()}")
        report.append("")
        
        # ORIGINAL SUMMARY SECTION
        summary = results.get('summary', {})
        report.append("📊 SCAN SUMMARY")
        report.append("-" * 20)
        report.append(f"Technologies Detected: {summary.get('total_technologies', 0)}")
        report.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        
        # NEW: CVE summary if available
        if results.get('nvd_cves'):
            report.append(f"NVD CVEs Found: {summary.get('total_cves', 0)}")
            report.append(f"High-Risk CVEs: {summary.get('high_risk_cves', 0)}")
        report.append("")
        
        # ORIGINAL: Detected Technologies
        technologies = results.get('technologies_detected', [])
        if technologies:
            report.append("🔧 DETECTED TECHNOLOGIES")
            report.append("-" * 25)
            for tech in technologies:
                report.append(f"  • {tech}")
            report.append("")
        
        # NEW: NVD CVE Findings
        cves = results.get('nvd_cves', [])
        if cves:
            report.append("🚨 NVD CVE INTELLIGENCE")
            report.append("-" * 25)
            
            # Group by technology
            by_tech = {}
            for cve in cves:
                tech = cve.get('technology', 'Unknown')
                if tech not in by_tech:
                    by_tech[tech] = []
                by_tech[tech].append(cve)
            
            for tech, tech_cves in by_tech.items():
                report.append(f"📁 {tech}:")
                for cve in tech_cves:
                    cvss = cve.get('cvss_score', 'Unknown')
                    risk_icon = "🔴" if isinstance(cvss, (int, float)) and cvss >= 7.0 else "🟡" if isinstance(cvss, (int, float)) and cvss >= 4.0 else "🟢"
                    report.append(f"  {risk_icon} {cve['cve_id']} (CVSS: {cvss})")
                report.append("")
        
        # ORIGINAL: Security Headers
        headers = results.get('security_headers', {})
        missing_headers = [k for k, v in headers.items() if v == 'Missing']
        if missing_headers:
            report.append("🛡️ MISSING SECURITY HEADERS")
            report.append("-" * 30)
            for header in missing_headers:
                report.append(f"  ❌ {header}")
            report.append("")
        
        # ORIGINAL: Basic Vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            report.append("⚠️ BASIC VULNERABILITY CHECKS")
            report.append("-" * 35)
            for vuln in vulns:
                severity_icon = "🔴" if vuln['severity'] == 'High' else "🟡" if vuln['severity'] == 'Medium' else "🟢"
                report.append(f"  {severity_icon} [{vuln['severity']}] {vuln['type']}")
                report.append(f"     {vuln['description']}")
            report.append("")
        
        # NEW: Risk Assessment
        high_risk_cves = summary.get('high_risk_cves', 0)
        if high_risk_cves > 0:
            report.append("💀 CRITICAL FINDINGS")
            report.append("-" * 20)
            report.append(f"🔴 {high_risk_cves} high-risk CVEs require immediate attention!")
            report.append("")
        
        # ORIGINAL: NVD status
        if results.get('nvd_cves'):
            report.append("💡 NVD CVE Intelligence: ✅ ACTIVE")
        else:
            report.append("💡 NVD CVE Intelligence: ❌ INACTIVE (No API key or no technologies detected)")
        report.append("")
        
        return "\n".join(report)
    
    def save_scan_results(self, results: Dict, filename: str = None) -> str:
        """ORIGINAL: Save scan results to file"""
        from datetime import datetime
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = results.get('url', 'unknown').replace('https://', '').replace('http://', '').split('/')[0]
            filename = f"web_scan_{domain}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 Web scan results saved to: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save web scan results: {e}")
            return None
