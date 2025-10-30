# engines/http_engine.py
import requests
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse
import ssl
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPEngine:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a configured HTTP session"""
        session = requests.Session()
        
        # Configure session with stealth settings
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Set proxy if configured
        proxy = self.config.get("proxy")
        if proxy:
            session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        return session
    
    def get_stealth_headers(self) -> List[Dict[str, str]]:
        """Return various stealth headers to avoid detection"""
        return [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Description': 'Standard Chrome'
            },
            {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Description': 'Mac Chrome'
            },
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Description': 'Linux Chrome'
            },
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Description': 'Firefox'
            },
            {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                'Description': 'iPhone Safari'
            }
        ]
    
    def probe_url(self, url: str, timeout: int = 10, verify_ssl: bool = False) -> Dict[str, Any]:
        """Probe a URL and gather basic information"""
        result = {
            'url': url,
            'alive': False,
            'status_code': 0,
            'headers': {},
            'server': '',
            'content_length': 0,
            'response_time': 0,
            'technologies': [],
            'security_headers': {},
            'redirect_chain': []
        }
        
        try:
            start_time = time.time()
            response = self.session.get(
                url, 
                timeout=timeout, 
                verify=verify_ssl,
                allow_redirects=True
            )
            result['response_time'] = round(time.time() - start_time, 2)
            
            result.update({
                'alive': True,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', ''),
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', '')
            })
            
            # Extract security headers
            result['security_headers'] = self._extract_security_headers(response.headers)
            
            # Detect technologies
            result['technologies'] = self._detect_technologies(response.headers, response.text)
            
            self.logger.debug(f"Probed {url}: Status {response.status_code}")
            
        except requests.exceptions.SSLError:
            result['error'] = 'SSL certificate error'
            self.logger.warning(f"SSL error for {url}")
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection failed'
            self.logger.warning(f"Connection failed for {url}")
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout'
            self.logger.warning(f"Timeout for {url}")
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Error probing {url}: {str(e)}")
        
        return result
    
    def _extract_security_headers(self, headers: Dict) -> Dict[str, Any]:
        """Extract and analyze security headers"""
        security_headers = {}
        important_headers = [
            'Content-Security-Policy', 'X-Content-Type-Options', 
            'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security',
            'Referrer-Policy', 'Feature-Policy', 'Permissions-Policy'
        ]
        
        for header in important_headers:
            if header in headers:
                security_headers[header] = {
                    'value': headers[header],
                    'status': 'present'
                }
            else:
                security_headers[header] = {
                    'value': None,
                    'status': 'missing'
                }
        
        return security_headers
    
    def _detect_technologies(self, headers: Dict, content: str) -> List[str]:
        """Detect web technologies from headers and content"""
        technologies = []
        
        # Server detection
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append('Apache')
        elif 'nginx' in server:
            technologies.append('Nginx')
        elif 'iis' in server:
            technologies.append('IIS')
        elif 'cloudflare' in server:
            technologies.append('Cloudflare')
        
        # Framework detection from headers
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Framework detection from content
        content_lower = content.lower()
        framework_indicators = {
            'wordpress': ['wp-content', 'wordpress'],
            'drupal': ['drupal', 'sites/all'],
            'joomla': ['joomla', 'media/jui'],
            'react': ['react', 'react-dom'],
            'angular': ['angular', 'ng-'],
            'jquery': ['jquery'],
            'bootstrap': ['bootstrap']
        }
        
        for tech, indicators in framework_indicators.items():
            if any(indicator in content_lower for indicator in indicators):
                technologies.append(tech.capitalize())
        
        return list(set(technologies))  # Remove duplicates
    
    def check_common_endpoints(self, base_url: str, timeout: int = 5) -> List[Dict[str, Any]]:
        """Check common administrative and sensitive endpoints"""
        common_paths = [
            '/admin', '/login', '/wp-admin', '/administrator',
            '/phpmyadmin', '/server-status', '/.git', '/backup',
            '/api', '/graphql', '/swagger', '/robots.txt',
            '/.env', '/config', '/debug', '/test'
        ]
        
        results = []
        
        def check_endpoint(path):
            url = urljoin(base_url, path)
            try:
                response = self.session.get(url, timeout=timeout, verify=False)
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'redirect': response.url if response.url != url else None
                }
            except Exception as e:
                return {
                    'url': url,
                    'status_code': 0,
                    'error': str(e)
                }
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_path = {executor.submit(check_endpoint, path): path for path in common_paths}
            
            for future in as_completed(future_to_path):
                result = future.result()
                results.append(result)
        
        # Filter only interesting results (not 404s)
        interesting_results = [
            r for r in results 
            if r.get('status_code', 0) not in [0, 404, 403] or r.get('redirect')
        ]
        
        self.logger.info(f"Checked {len(common_paths)} endpoints, found {len(interesting_results)} interesting")
        return interesting_results
    
    def test_http_methods(self, url: str, timeout: int = 5) -> Dict[str, Any]:
        """Test various HTTP methods"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']
        results = {}
        
        for method in methods:
            try:
                response = self.session.request(
                    method, url, 
                    timeout=timeout, 
                    verify=False,
                    allow_redirects=False
                )
                results[method] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content) if hasattr(response, 'content') else 0,
                    'allowed': response.status_code not in [405, 501, 403]
                }
            except Exception as e:
                results[method] = {
                    'status_code': 0,
                    'error': str(e),
                    'allowed': False
                }
        
        return results
    
    def scan_headers_vulnerabilities(self, headers: Dict) -> List[Dict[str, Any]]:
        """Scan headers for common security vulnerabilities"""
        vulnerabilities = []
        
        # Check for missing security headers
        security_headers = self._extract_security_headers(headers)
        missing_headers = [h for h, info in security_headers.items() if info['status'] == 'missing']
        
        if missing_headers:
            vulnerabilities.append({
                'type': 'MISSING_SECURITY_HEADER',
                'severity': 'MEDIUM',
                'description': f'Missing important security headers: {", ".join(missing_headers)}',
                'remediation': 'Implement missing security headers according to best practices'
            })
        
        # Check for insecure headers
        if headers.get('Server'):
            vulnerabilities.append({
                'type': 'SERVER_BANNER_LEAK',
                'severity': 'LOW',
                'description': f'Server banner disclosed: {headers["Server"]}',
                'remediation': 'Remove or obscure server banner information'
            })
        
        if headers.get('X-Powered-By'):
            vulnerabilities.append({
                'type': 'TECHNOLOGY_DISCLOSURE',
                'severity': 'LOW', 
                'description': f'Technology disclosed: {headers["X-Powered-By"]}',
                'remediation': 'Remove X-Powered-By header'
            })
        
        # Check HSTS
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            vulnerabilities.append({
                'type': 'MISSING_HSTS',
                'severity': 'HIGH',
                'description': 'HSTS header not implemented',
                'remediation': 'Implement HSTS to enforce HTTPS'
            })
        
        return vulnerabilities

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    engine = HTTPEngine(config, logger)
    
    # Test with a safe target
    print("🧪 Testing HTTP Engine...")
    test_url = "https://httpbin.org/json"
    
    result = engine.probe_url(test_url)
    print(f"✅ URL Probe: {result['url']}")
    print(f"   Status: {result['status_code']}")
    print(f"   Server: {result['server']}")
    print(f"   Technologies: {', '.join(result['technologies'])}")
    print(f"   Security Headers: {len([h for h in result['security_headers'].values() if h['status'] == 'present'])} present")
    
    # Test common endpoints
    print("\n🔍 Testing common endpoints...")
    endpoints = engine.check_common_endpoints("https://httpbin.org")
    for endpoint in endpoints[:5]:  # Show first 5
        print(f"   {endpoint['url']} -> {endpoint['status_code']}")
    
    # Test HTTP methods
    print("\n🔄 Testing HTTP methods...")
    methods = engine.test_http_methods("https://httpbin.org/get")
    for method, info in methods.items():
        status = "✅ ALLOWED" if info.get('allowed') else "❌ BLOCKED"
        print(f"   {method}: {status} (Status: {info.get('status_code', 'Error')})")
