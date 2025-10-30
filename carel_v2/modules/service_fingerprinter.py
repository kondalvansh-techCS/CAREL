#!/usr/bin/env python3
"""
Advanced Service Fingerprinter for CAREL v2.0
Comprehensive network service identification and vulnerability assessment
"""
import concurrent.futures  
import requests           
import socket
import ssl
import re
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

class ServiceFingerprinter:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.service_signatures = self._load_service_signatures()
    
    def _load_service_signatures(self) -> Dict:
        """Load service fingerprints and vulnerability patterns"""
        return {
            "web_servers": {
                "Apache": {
                    "patterns": [r"Apache", r"Apache/2", r"Server: Apache"],
                    "versions": {
                        "2.4.49": {"vulnerabilities": ["CVE-2021-41773", "CVE-2021-42013"], "risk": "Critical"},
                        "2.4.48": {"vulnerabilities": ["CVE-2021-41773"], "risk": "Critical"},
                        "2.4.46": {"vulnerabilities": ["CVE-2020-11984"], "risk": "High"}
                    },
                    "ports": [80, 443, 8080, 8443]
                },
                "Nginx": {
                    "patterns": [r"nginx", r"Server: nginx"],
                    "versions": {
                        "1.20.0": {"vulnerabilities": ["CVE-2021-23017"], "risk": "Medium"},
                        "1.18.0": {"vulnerabilities": ["CVE-2021-23017"], "risk": "Medium"}
                    },
                    "ports": [80, 443, 8080]
                },
                "IIS": {
                    "patterns": [r"Microsoft-IIS", r"Server: Microsoft-IIS"],
                    "versions": {
                        "10.0": {"vulnerabilities": ["CVE-2021-31166"], "risk": "High"},
                        "8.5": {"vulnerabilities": ["CVE-2021-31166"], "risk": "High"}
                    },
                    "ports": [80, 443]
                }
            },
            "database_servers": {
                "MySQL": {
                    "patterns": [r"mysql", r"MySQL"],
                    "versions": {
                        "8.0.26": {"vulnerabilities": ["CVE-2021-35604"], "risk": "High"},
                        "5.7.35": {"vulnerabilities": ["CVE-2021-35604"], "risk": "High"}
                    },
                    "ports": [3306]
                },
                "PostgreSQL": {
                    "patterns": [r"PostgreSQL"],
                    "versions": {
                        "13.3": {"vulnerabilities": ["CVE-2021-36765"], "risk": "Medium"},
                        "12.7": {"vulnerabilities": ["CVE-2021-36765"], "risk": "Medium"}
                    },
                    "ports": [5432]
                },
                "Redis": {
                    "patterns": [r"Redis"],
                    "versions": {
                        "6.2.6": {"vulnerabilities": ["CVE-2021-32765"], "risk": "High"},
                        "5.0.14": {"vulnerabilities": ["CVE-2021-32765"], "risk": "High"}
                    },
                    "ports": [6379]
                }
            },
            "remote_access": {
                "SSH": {
                    "patterns": [r"SSH-2.0", r"OpenSSH"],
                    "versions": {
                        "8.8": {"vulnerabilities": ["CVE-2023-28531"], "risk": "Medium"},
                        "8.7": {"vulnerabilities": ["CVE-2023-28531"], "risk": "Medium"}
                    },
                    "ports": [22]
                },
                "Telnet": {
                    "patterns": [r"telnet", r"Telnet"],
                    "versions": {},
                    "ports": [23],
                    "inherent_risk": "Critical"
                },
                "RDP": {
                    "patterns": [r"rdp", r"RDP", r"Terminal Services"],
                    "versions": {},
                    "ports": [3389],
                    "inherent_risk": "High"
                }
            },
            "file_services": {
                "FTP": {
                    "patterns": [r"220.*ftp", r"FTP server"],
                    "versions": {
                        "ProFTPD": {"vulnerabilities": ["CVE-2021-46854"], "risk": "Medium"},
                        "vsftpd": {"vulnerabilities": ["CVE-2021-3618"], "risk": "Medium"}
                    },
                    "ports": [21],
                    "inherent_risk": "High"
                },
                "SMB": {
                    "patterns": [r"SMB", r"Server Message Block"],
                    "versions": {
                        "SMBv1": {"vulnerabilities": ["CVE-2017-0143", "CVE-2017-0144"], "risk": "Critical"}
                    },
                    "ports": [445, 139],
                    "inherent_risk": "High"
                }
            }
        }
    
    def fingerprint_service(self, target: str, port: int, timeout: int = 5) -> Dict[str, Any]:
        """Fingerprint a specific service on a target"""
        self.logger.info(f"🔍 Fingerprinting {target}:{port}")
        
        result = {
            "target": target,
            "port": port,
            "service": "Unknown",
            "version": "Unknown",
            "banner": "",
            "vulnerabilities": [],
            "risk_level": "Unknown",
            "protocol_info": {},
            "recommendations": []
        }
        
        try:
            # Connect to the service
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Try to get banner
            try:
                if port in [80, 443, 8080, 8443]:
                    # HTTP/HTTPS services
                    banner = self._get_http_banner(target, port)
                elif port == 22:
                    # SSH service
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                else:
                    # Generic banner grab
                    sock.send(b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                
                result["banner"] = banner.strip()
                
            except Exception as e:
                result["banner"] = f"Banner grab failed: {e}"
            
            # Analyze the banner
            analysis = self._analyze_banner(result["banner"], port)
            result.update(analysis)
            
            # Get additional protocol info
            result["protocol_info"] = self._get_protocol_info(target, port)
            
            sock.close()
            
            self.logger.info(f"✅ Fingerprinted {target}:{port} as {result['service']}")
            
        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"❌ Fingerprinting failed for {target}:{port}: {e}")
        
        return result
    
    def _get_http_banner(self, target: str, port: int) -> str:
        """Get HTTP/HTTPS server banner"""
        try:
            if port == 443:
                # HTTPS
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        ssock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                        response = ssock.recv(1024).decode('utf-8', errors='ignore')
            else:
                # HTTP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
            
            return response
        except Exception as e:
            return f"HTTP banner error: {e}"
    
    def _analyze_banner(self, banner: str, port: int) -> Dict[str, Any]:
        """Analyze banner to identify service and version"""
        analysis = {
            "service": "Unknown",
            "version": "Unknown", 
            "vulnerabilities": [],
            "risk_level": "Unknown",
            "confidence": "Low"
        }
        
        banner_lower = banner.lower()
        
        # Check each service category
        for category, services in self.service_signatures.items():
            for service_name, service_info in services.items():
                # Check if this service typically runs on this port
                if port not in service_info.get("ports", []):
                    continue
                
                # Check patterns
                for pattern in service_info.get("patterns", []):
                    if re.search(pattern, banner, re.IGNORECASE):
                        analysis["service"] = service_name
                        analysis["confidence"] = "High"
                        
                        # Try to extract version
                        version_match = self._extract_version(banner, service_name)
                        if version_match:
                            analysis["version"] = version_match
                        
                        # Check for vulnerabilities
                        vulns = self._check_vulnerabilities(service_name, analysis["version"])
                        analysis["vulnerabilities"] = vulns
                        
                        # Determine risk level
                        analysis["risk_level"] = self._determine_risk_level(service_info, vulns)
                        
                        return analysis
        
        return analysis
    
    def _extract_version(self, banner: str, service: str) -> str:
        """Extract version information from banner"""
        # Common version patterns
        version_patterns = [
            r"(\d+\.\d+(?:\.\d+)?)",  # X.X.X version
            r"v?(\d+\-\d+\-\d+)",     # X-X-X version
            r"(\d+\.\d+[a-z]?)",      # X.Xa version
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, banner)
            if matches:
                return matches[0]
        
        return "Unknown"
    
    def _check_vulnerabilities(self, service: str, version: str) -> List[Dict]:
        """Check for known vulnerabilities"""
        vulnerabilities = []
        
        # Search through all service categories
        for category, services in self.service_signatures.items():
            if service in services:
                service_info = services[service]
                
                # Check specific versions
                for ver, vuln_info in service_info.get("versions", {}).items():
                    if ver in version or version in ver:
                        for vuln in vuln_info.get("vulnerabilities", []):
                            vulnerabilities.append({
                                "cve": vuln,
                                "risk": vuln_info.get("risk", "Medium"),
                                "service": service,
                                "version": version
                            })
                
                # Check inherent risks
                if "inherent_risk" in service_info:
                    vulnerabilities.append({
                        "cve": "Inherent Risk",
                        "risk": service_info["inherent_risk"],
                        "service": service,
                        "version": version,
                        "description": f"{service} has inherent security risks"
                    })
        
        return vulnerabilities
    
    def _determine_risk_level(self, service_info: Dict, vulnerabilities: List[Dict]) -> str:
        """Determine overall risk level"""
        if not vulnerabilities:
            return "Low"
        
        risk_weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        max_risk = max([risk_weights.get(vuln.get("risk", "Low"), 1) for vuln in vulnerabilities])
        
        risk_levels = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}
        return risk_levels.get(max_risk, "Low")
    
    def _get_protocol_info(self, target: str, port: int) -> Dict[str, Any]:
        """Get additional protocol-specific information"""
        info = {}
        
        try:
            if port == 22:
                # SSH specific checks
                info["protocol"] = "SSH"
                info["key_exchange"] = "Unknown"
            elif port in [80, 443, 8080, 8443]:
                # HTTP specific checks
                info["protocol"] = "HTTPS" if port in [443, 8443] else "HTTP"
                info["security_headers"] = self._check_http_headers(target, port)
            elif port == 21:
                # FTP specific checks
                info["protocol"] = "FTP"
                info["anonymous_login"] = self._check_ftp_anonymous(target)
        
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    def _check_http_headers(self, target: str, port: int) -> Dict[str, str]:
        """Check HTTP security headers"""
        headers = {}
        try:
            if port == 443:
                url = f"https://{target}"
            else:
                url = f"http://{target}:{port}"
            
            response = requests.get(url, timeout=5, verify=False)
            security_headers = [
                'Content-Security-Policy', 'Strict-Transport-Security',
                'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'
            ]
            
            for header in security_headers:
                headers[header] = "Present" if header in response.headers else "Missing"
                
        except:
            headers["error"] = "Could not check headers"
        
        return headers
    
    def _check_ftp_anonymous(self, target: str) -> bool:
        """Check if FTP allows anonymous login"""
        try:
            from ftplib import FTP
            ftp = FTP(target, timeout=5)
            ftp.login('anonymous', 'anonymous@example.com')
            ftp.quit()
            return True
        except:
            return False
    
    def scan_multiple_services(self, target: str, ports: List[int], max_workers: int = 10) -> Dict[str, Any]:
        """Scan multiple services on a target"""
        self.logger.info(f"🎯 Starting comprehensive service fingerprinting for {target}")
        
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "services": [],
            "summary": {
                "total_services": 0,
                "identified_services": 0,
                "high_risk_services": 0,
                "critical_vulnerabilities": 0
            }
        }
        
        # Scan services in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(self.fingerprint_service, target, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_result = future.result()
                    results["services"].append(service_result)
                    
                    # Update summary
                    if service_result.get("service") != "Unknown":
                        results["summary"]["identified_services"] += 1
                    
                    if service_result.get("risk_level") == "High":
                        results["summary"]["high_risk_services"] += 1
                    
                    for vuln in service_result.get("vulnerabilities", []):
                        if vuln.get("risk") == "Critical":
                            results["summary"]["critical_vulnerabilities"] += 1
                            
                except Exception as e:
                    self.logger.error(f"❌ Service scan failed for {target}:{port}: {e}")
        
        results["summary"]["total_services"] = len(results["services"])
        return results
