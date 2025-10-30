# engines/nmap_engine.py
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import time

class NmapEngine:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.scan_results = {}
    
    def check_nmap_installed(self) -> bool:
        """Check if nmap is installed and accessible"""
        try:
            result = subprocess.run(
                ["nmap", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                self.logger.info(f"✅ Nmap found: {result.stdout.split()[2]}")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.error("❌ Nmap not found or not accessible")
            return False
    
    def build_scan_command(self, target: str, scan_type: str = "quick", 
                          custom_ports: str = "", threads: int = 10) -> List[str]:
        """Build nmap command based on scan type"""
        
        base_cmd = ["nmap"]
        
        # Add scan type arguments
        if scan_type == "quick":
            base_cmd.extend(["-F", "--open"])  # Fast scan
        elif scan_type == "full":
            base_cmd.extend(["-p-", "--open"])  # All ports
        elif scan_type == "custom":
            if custom_ports:
                base_cmd.extend(["-p", custom_ports, "--open"])
            else:
                base_cmd.extend(["-F", "--open"])  # Fallback to quick
        elif scan_type == "vuln":
            base_cmd.extend(["-sV", "--script", "vuln", "--open"])  # Vulnerability scan
        elif scan_type == "stealth":
            base_cmd.extend([
                "-sS",  # SYN stealth scan
                "-T2",  # Polite timing (slower, stealthier)
                "--max-parallelism", "1",
                "--scan-delay", "5s",
                "-f",  # Fragment packets
                "--data-length", "50",  # Add random data
                "--open"
            ])
        
        # Add performance options
        base_cmd.extend([
            f"--min-rate", str(threads * 10),
            f"--min-parallelism", str(threads),
            "-v"  # Verbose output for progress
        ])
        
        # Add output options
        base_cmd.extend(["-oX", "-"])  # Output XML to stdout
        
        # Add target
        base_cmd.append(target)
        
        self.logger.debug(f"Built nmap command: {' '.join(base_cmd)}")
        return base_cmd
    
    def run_scan(self, target: str, scan_type: str = "quick", 
                custom_ports: str = "", threads: int = 10, 
                timeout: int = 1800) -> Dict[str, Any]:
        """Execute nmap scan and parse results"""
        
        if not self.check_nmap_installed():
            return {"error": "Nmap not installed"}
        
        self.logger.scan_start("port_scan", target)
        
        try:
            # Build command
            cmd = self.build_scan_command(target, scan_type, custom_ports, threads)
            
            self.logger.info(f"🎯 Starting {scan_type} scan on {target}")
            self.logger.info(f"⏱️  Timeout: {timeout} seconds")
            
            # Run nmap scan
            start_time = time.time()
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            scan_duration = time.time() - start_time
            
            if process.returncode != 0:
                self.logger.error(f"❌ Nmap scan failed: {process.stderr}")
                return {"error": f"Nmap failed: {process.stderr}"}
            
            # Parse XML output
            results = self.parse_nmap_xml(process.stdout, target)
            results["scan_duration"] = round(scan_duration, 2)
            results["scan_type"] = scan_type
            
            self.logger.scan_complete("port_scan", target, len(results.get("ports", [])))
            
            return results
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Nmap scan timed out after {timeout} seconds")
            return {"error": f"Scan timed out after {timeout} seconds"}
        except Exception as e:
            self.logger.error(f"💥 Unexpected error during scan: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}"}
    
    def parse_nmap_xml(self, xml_output: str, target: str) -> Dict[str, Any]:
        """Parse nmap XML output into structured data"""
        
        try:
            root = ET.fromstring(xml_output)
            results = {
                "target": target,
                "ports": [],
                "hostnames": [],
                "os_info": {},
                "scan_info": {}
            }
            
            # Extract host information
            for host in root.findall("host"):
                # Get hostnames
                for hostname in host.findall("hostnames/hostname"):
                    results["hostnames"].append({
                        "name": hostname.get("name", ""),
                        "type": hostname.get("type", "")
                    })
                
                # Get OS information
                os_elem = host.find("os/osmatch")
                if os_elem is not None:
                    results["os_info"] = {
                        "name": os_elem.get("name", ""),
                        "accuracy": os_elem.get("accuracy", "")
                    }
                
                # Get ports
                for port in host.findall("ports/port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    state = port.find("state")
                    service = port.find("service")
                    
                    port_info = {
                        "port": port_id,
                        "protocol": protocol,
                        "state": state.get("state") if state is not None else "unknown",
                        "service": service.get("name") if service is not None else "unknown",
                        "product": service.get("product") if service is not None else "",
                        "version": service.get("version") if service is not None else "",
                        "extra": service.get("extrainfo") if service is not None else ""
                    }
                    
                    # Only include open ports
                    if port_info["state"] == "open":
                        results["ports"].append(port_info)
                
                # Get scan timing
                scan_info = root.find("runstats/finished")
                if scan_info is not None:
                    results["scan_info"] = {
                        "time": scan_info.get("timestr", ""),
                        "elapsed": scan_info.get("elapsed", ""),
                        "summary": scan_info.get("summary", "")
                    }
            
            # Sort ports by port number
            results["ports"].sort(key=lambda x: int(x["port"]))
            
            self.logger.info(f"📊 Found {len(results['ports'])} open ports on {target}")
            return results
            
        except ET.ParseError as e:
            self.logger.error(f"❌ Failed to parse Nmap XML: {str(e)}")
            return {"error": f"XML parse error: {str(e)}"}
    
    def get_service_versions(self, ports: List[Dict]) -> List[str]:
        """Extract service version information from port results"""
        versions = []
        for port in ports:
            if port.get("product") and port.get("version"):
                service_str = f"{port['product']} {port['version']}".strip()
                if service_str and service_str not in versions:
                    versions.append(service_str)
        return versions

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    engine = NmapEngine(config, logger)
    
    # Test scan on a safe target (scanme.nmap.org is designed for testing)
    print("🧪 Testing Nmap Engine on scanme.nmap.org...")
    results = engine.run_scan("scanme.nmap.org", "quick", timeout=60)
    
    if "error" not in results:
        print(f"✅ Scan completed in {results.get('scan_duration', 0)}s")
        print(f"📊 Found {len(results.get('ports', []))} open ports")
        for port in results.get("ports", []):
            print(f"   Port {port['port']}/{port['protocol']}: {port['service']} - {port['state']}")
    else:
        print(f"❌ Scan failed: {results['error']}")
