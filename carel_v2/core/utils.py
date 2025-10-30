# core/utils.py
import re
import socket
import subprocess
from typing import Optional, Tuple, List
from urllib.parse import urlparse
import ipaddress

class ValidationUtils:
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate domain name format"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def sanitize_target(target: str) -> str:
        """Sanitize and normalize target input"""
        target = target.strip().lower()
        
        # Remove http/https if present
        if target.startswith(('http://', 'https://')):
            target = target.split('//', 1)[1]
        
        # Remove path components
        target = target.split('/')[0]
        
        return target

class NetworkUtils:
    @staticmethod
    def is_host_alive(host: str, timeout: int = 5) -> bool:
        """Check if host is reachable"""
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(host)
            return True
        except (socket.gaierror, socket.timeout):
            return False
    
    @staticmethod
    def run_command(cmd: List[str], timeout: int = 300) -> Tuple[bool, str, str]:
        """Execute system command safely"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return (
                result.returncode == 0,
                result.stdout.strip(),
                result.stderr.strip()
            )
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

class TextUtils:
    @staticmethod
    def truncate_text(text: str, max_length: int = 100) -> str:
        """Truncate text with ellipsis"""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

# Example usage
if __name__ == "__main__":
    utils = ValidationUtils()
    print(utils.validate_domain("google.com"))  # True
    print(utils.validate_domain("invalid..domain"))  # False
    print(utils.sanitize_target("https://example.com/path"))  # example.com
