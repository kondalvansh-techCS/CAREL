#!/usr/bin/env python3
"""
Enhanced Port Scanner for CAREL v2.0
Maintains all original features + adds NVD CVE intelligence
"""

import socket
import concurrent.futures
import time
from typing import Dict, List, Any
import requests
import json
from datetime import datetime

class PortScanner:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.nvd_api_key = config.get("nvd_api_key")
        self.service_cve_mapping = self._load_service_cve_mapping()
    
    def _load_service_cve_mapping(self) -> Dict:
        """Map services to CPE names for NVD queries"""
        return {
            21: {"service": "FTP", "cpe": "cpe:/a:ftp:ftp"},
            22: {"service": "SSH", "cpe": "cpe:/a:openssh:openssh"},
            23: {"service": "Telnet", "cpe": "cpe:/a:telnet:telnet"},
            25: {"service": "SMTP", "cpe": "cpe:/a:smtp:smtp"},
            53: {"service": "DNS", "cpe": "cpe:/a:dns:dns"},
            80: {"service": "HTTP", "cpe": "cpe:/a:apache:http_server"},
            443: {"service": "HTTPS", "cpe": "cpe:/a:apache:http_server"},
            110: {"service": "POP3", "cpe": "cpe:/a:pop3:pop3"},
            143: {"service": "IMAP", "cpe": "cpe:/a:imap:imap"},
            993: {"service": "IMAPS", "cpe": "cpe:/a:imap:imap"},
            995: {"service": "POP3S", "cpe": "cpe:/a:pop3:pop3"},
            1433: {"service": "MSSQL", "cpe": "cpe:/a:microsoft:sql_server"},
            3306: {"service": "MySQL", "cpe": "cpe:/a:mysql:mysql"},
            3389: {"service": "RDP", "cpe": "cpe:/a:microsoft:remote_desktop"},
            5432: {"service": "PostgreSQL", "cpe": "cpe:/a:postgresql:postgresql"},
            5900: {"service": "VNC", "cpe": "cpe:/a:vnc:vnc"}
        }
    
    def get_scan_types(self):
        """Return available scan types - ORIGINAL FEATURE PRESERVED"""
        return [
            {
                "id": "quick",
                "name": "Quick Scan", 
                "desc": "Fast scan of 15 most common ports"
            },
            {
                "id": "comprehensive", 
                "name": "Comprehensive Scan",
                "desc": "Full port range scan (1-1000)"
            },
            {
                "id": "custom",
                "name": "Custom Scan", 
                "desc": "Scan specific ports or ranges"
            },
            {
                "id": "stealth",
                "name": "Stealth Scan",
                "desc": "Slower scan to avoid detection"
            }
        ]
    
    def query_nvd_for_service(self, service_name: str, port: int) -> List[Dict]:
        """NEW: Query NVD API for service-specific vulnerabilities"""
        if not self.nvd_api_key:
            return []
        
        try:
            cpe_name = self.service_cve_mapping.get(port, {}).get("cpe", "")
            if not cpe_name:
                return []
            
            # NVD API endpoint
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": 3  # Get top 3 recent CVEs
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
                    
                    # Get CVSS score if available
                    cvss_score = "Unknown"
                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    
                    vulnerabilities.append({
                        "cve_id": cve_data.get("id", "Unknown"),
                        "description": cve_data.get("descriptions", [{}])[0].get("value", "No description"),
                        "cvss_score": cvss_score,
                        "published": cve_data.get("published", "Unknown")
                    })
                
                return vulnerabilities
            else:
                self.logger.debug(f"NVD API returned status: {response.status_code}")
                return []
                
        except Exception as e:
            self.logger.debug(f"NVD query failed for {service_name}: {e}")
            return []
    
    def scan_target(self, target: str, scan_type: str = "quick", 
                   custom_ports: str = "", threads: int = 10, timeout: int = 300) -> Dict[str, Any]:
        """ORIGINAL METHOD ENHANCED with NVD integration"""
        
        # ORIGINAL PORT SELECTION LOGIC
        if scan_type == "quick":
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900]
        elif scan_type == "comprehensive":
            ports = list(range(1, 1001))
        elif scan_type == "custom" and custom_ports:
            ports = self._parse_custom_ports(custom_ports)
        elif scan_type == "stealth":
            ports = [21, 22, 80, 443, 3389]  # Minimal stealth scan
        else:
            ports = [21, 22, 23, 80, 443, 3389]  # Fallback
        
        self.logger.info(f"🎯 Starting port scan for {target}")
        self.logger.info(f"📡 Scan type: {scan_type}, Ports: {len(ports)}, Threads: {threads}")
        
        open_ports = []
        start_time = time.time()
        
        def scan_port(port):
            """ORIGINAL PORT SCANNING LOGIC with NVD enhancement"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    # Port is open - ORIGINAL BEHAVIOR PRESERVED
                    service_info = self.service_cve_mapping.get(port, {"service": "Unknown"})
                    service_name = service_info["service"]
                    
                    # NEW: Query NVD for CVEs (optional enhancement)
                    cves = []
                    if self.nvd_api_key:  # Only query NVD if API key is available
                        cves = self.query_nvd_for_service(service_name, port)
                    
                    return {
                        "port": port,
                        "service": service_name,
                        "state": "open",
                        "cves": cves,  # NEW: CVE information
                        "cve_count": len(cves)  # NEW: Count of CVEs
                    }
                return None
            except:
                return None
        
        # ORIGINAL MULTI-THREADED SCANNING
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        scan_duration = time.time() - start_time
        
        # ORIGINAL RESULTS STRUCTURE with NEW fields
        results = {
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "duration": round(scan_duration, 2),
            "open_ports": open_ports,
            "total_ports_scanned": len(ports),
            "total_open_ports": len(open_ports),
            # NEW: CVE intelligence summary
            "total_cves_found": sum(port.get("cve_count", 0) for port in open_ports),
            "nvd_integration": "active" if self.nvd_api_key else "inactive",
            # ORIGINAL: Backward compatibility
            "scan_config": {
                "threads": threads,
                "timeout": timeout,
                "custom_ports": custom_ports
            }
        }
        
        return results
    
    def _parse_custom_ports(self, custom_ports: str) -> List[int]:
        """ORIGINAL: Parse custom port ranges"""
        ports = []
        try:
            for part in custom_ports.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            return list(set(ports))  # Remove duplicates
        except:
            return [21, 22, 80, 443, 3389]  # Fallback to common ports
    
    def generate_scan_report(self, results: Dict) -> str:
        """ORIGINAL REPORT METHOD with NVD enhancements"""
        report = []
        report.append("🎯 PORT SCAN RESULTS")
        report.append("=" * 50)
        report.append(f"Target: {results.get('target', 'Unknown')}")
        report.append(f"Scan Type: {results.get('scan_type', 'Unknown')}")
        report.append(f"Scan Date: {results.get('timestamp', 'Unknown')}")
        report.append(f"Scan Duration: {results.get('duration', 0)} seconds")
        report.append("")
        
        # ORIGINAL SUMMARY SECTION
        report.append("📊 SCAN SUMMARY")
        report.append("-" * 20)
        report.append(f"Total Ports Scanned: {results.get('total_ports_scanned', 0)}")
        report.append(f"Open Ports Found: {results.get('total_open_ports', 0)}")
        
        # NEW: CVE summary if available
        if results.get('nvd_integration') == 'active':
            report.append(f"CVEs Identified: {results.get('total_cves_found', 0)}")
        report.append("")
        
        # ORIGINAL PORT LISTING with NVD enhancements
        open_ports = results.get('open_ports', [])
        if open_ports:
            report.append("🚪 OPEN PORTS")
            report.append("-" * 15)
            
            for port_info in open_ports:
                report.append(f"🔓 Port {port_info['port']} - {port_info['service']}")
                
                # NEW: Show CVEs if available
                cves = port_info.get('cves', [])
                if cves:
                    report.append(f"   🚨 {len(cves)} CVEs Found:")
                    for cve in cves:
                        cvss_score = cve.get('cvss_score', 'Unknown')
                        risk_icon = "🔴" if isinstance(cvss_score, (int, float)) and cvss_score >= 7.0 else "🟡" if isinstance(cvss_score, (int, float)) and cvss_score >= 4.0 else "🟢"
                        report.append(f"     {risk_icon} {cve['cve_id']} (CVSS: {cvss_score})")
                report.append("")
        else:
            report.append("✅ No open ports found")
            report.append("")
        
        # NEW: High-risk analysis section
        if results.get('nvd_integration') == 'active' and results.get('total_cves_found', 0) > 0:
            high_risk_ports = [p for p in open_ports if any(
                isinstance(cve.get('cvss_score'), (int, float)) and cve.get('cvss_score', 0) >= 7.0 
                for cve in p.get('cves', [])
            )]
            
            if high_risk_ports:
                report.append("⚠️ HIGH RISK PORTS (CVSS >= 7.0)")
                report.append("-" * 35)
                for port in high_risk_ports:
                    high_cves = [cve for cve in port.get('cves', []) 
                               if isinstance(cve.get('cvss_score'), (int, float)) and cve.get('cvss_score', 0) >= 7.0]
                    report.append(f"🔴 Port {port['port']} - {len(high_cves)} critical CVEs")
                report.append("")
        
        # ORIGINAL: NVD status
        if results.get('nvd_integration') == 'active':
            report.append("💡 NVD CVE Intelligence: ✅ ACTIVE")
        else:
            report.append("💡 NVD CVE Intelligence: ❌ INACTIVE (No API key)")
        report.append("")
        
        return "\n".join(report)
    
    def save_scan_results(self, results: Dict, filename: str = None) -> str:
        """ORIGINAL: Save scan results to file"""
        from datetime import datetime
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"port_scan_{results.get('target', 'unknown')}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 Port scan results saved to: {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save port scan results: {e}")
            return None
