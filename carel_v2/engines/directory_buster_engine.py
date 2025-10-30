# engines/directory_buster_engine.py
import subprocess
import json
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urljoin

class DirectoryBusterEngine:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.results = []
    
    def check_feroxbuster_installed(self) -> bool:
        """Check if feroxbuster is installed and accessible"""
        try:
            result = subprocess.run(
                ["feroxbuster", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip().split()[-1] if result.stdout else "unknown"
                self.logger.info(f"✅ Feroxbuster found: v{version}")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.error("❌ Feroxbuster not found or not accessible")
            return False
    
    def get_available_wordlists(self) -> List[Dict[str, str]]:
        """Get available wordlists with descriptions"""
        wordlists_dir = self.config.home_dir / "wordlists"
        wordlists_dir.mkdir(exist_ok=True)
        
        # Common wordlist paths
        common_paths = [
            ("/usr/share/wordlists/dirb/common.txt", "DIRB Common (4.6K words)"),
            ("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "DirBuster Medium (220K words)"),
            ("/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt", "SecLists Common (4.6K words)"),
            ("/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt", "Raft Medium (6K words)"),
            (str(wordlists_dir / "common_dirs.txt"), "CAREL Common Directories"),
        ]
        
        available = []
        
        # Check which wordlists exist
        for path, description in common_paths:
            if os.path.exists(path):
                # Count lines for size info
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                    description = f"{description} (~{line_count} words)"
                except:
                    pass
                
                available.append({
                    "path": path,
                    "description": description,
                    "size": os.path.getsize(path) if os.path.exists(path) else 0
                })
        
        # Create a default wordlist if none exist
        if not available:
            self._create_default_wordlist()
            available.append({
                "path": str(wordlists_dir / "common_dirs.txt"),
                "description": "CAREL Common Directories (Built-in)",
                "size": os.path.getsize(str(wordlists_dir / "common_dirs.txt"))
            })
        
        return available
    
    def _create_default_wordlist(self):
        """Create a default wordlist for directory busting"""
        wordlists_dir = self.config.home_dir / "wordlists"
        wordlists_dir.mkdir(exist_ok=True)
        
        default_words = [
            # Common directories
            "admin", "administrator", "login", "logout", "signin", "signup",
            "dashboard", "panel", "control", "manager", "system", "config",
            "configuration", "setup", "install", "update", "upgrade",
            "backup", "backups", "bak", "old", "temp", "tmp", "cache",
            "logs", "log", "debug", "test", "testing", "demo", "example",
            "api", "ajax", "json", "xml", "rpc", "rest", "graphql",
            "doc", "docs", "documentation", "help", "support", "faq",
            "blog", "news", "articles", "posts", "forum", "forums",
            "shop", "store", "cart", "checkout", "payment", "pay",
            "user", "users", "member", "members", "profile", "account",
            "images", "img", "pictures", "photos", "media", "uploads",
            "files", "downloads", "static", "assets", "resources",
            "css", "js", "javascript", "scripts", "styles", "fonts",
            "include", "includes", "inc", "lib", "library", "libraries",
            "src", "source", "sources", "code", "bin", "binaries",
            "vendor", "vendors", "packages", "components", "modules",
            "themes", "templates", "layouts", "views", "pages",
            "public", "private", "secure", "protected", "hidden",
            "secret", "confidential", "internal", "external",
            "web", "webapp", "webapps", "application", "applications",
            "service", "services", "portal", "gateway", "interface",
            "cgi", "cgi-bin", "bin", "scripts", "exec", "execute",
            
            # Common files
            "index", "main", "home", "default", "start",
            "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd",
            "web.config", "config.php", "settings.py", "config.json",
            "package.json", "composer.json", "yarn.lock", "Gemfile",
            "README", "CHANGELOG", "LICENSE", "AUTHORS", "CONTRIBUTORS",
            ".git", ".svn", ".env", ".dockerignore", ".gitignore",
            "docker-compose.yml", "Dockerfile", "dockerfile",
            "phpinfo.php", "test.php", "info.php", "debug.php",
            "backup.sql", "dump.sql", "database.sql", "db.sql",
            "backup.zip", "backup.tar", "backup.tar.gz", "backup.rar",
            "log.txt", "error.log", "access.log", "debug.log",
            "wp-admin", "wp-content", "wp-includes", "wp-config.php",
            "administrator", "joomla", "drupal", "wordpress",
            
            # API endpoints
            "v1", "v2", "v3", "latest", "current", "stable",
            "users", "products", "orders", "payments", "auth",
            "token", "oauth", "login", "register", "profile",
            "admin", "manager", "system", "config", "settings",
            
            # Configuration files
            ".env.local", ".env.production", ".env.development",
            "config.local.php", "config.production.php",
            "settings.local.py", "settings.production.py",
            "application.properties", "application.yml",
            "app.config", "appsettings.json", "web.config",
            
            # Backup extensions
            ".bak", ".backup", ".old", ".save", ".orig",
            ".tmp", ".temp", ".copy", ".bkp", ".back",
        ]
        
        wordlist_path = wordlists_dir / "common_dirs.txt"
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            for word in sorted(set(default_words)):
                f.write(f"{word}\n")
        
        self.logger.info(f"📝 Created default wordlist with {len(default_words)} entries")
        return wordlist_path
    
    def build_feroxbuster_command(self, url: str, wordlist: str, threads: int = 10, 
                                 timeout: int = 300, stealth: bool = False) -> List[str]:
        """Build feroxbuster command with appropriate options"""
        
        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-o", "-",  # Output to stdout
            "--json",   # JSON output
            "--no-state",
            "--auto-tune",
            "--auto-bail",
        ]
        
        # Stealth options for avoiding detection
        if stealth:
            cmd.extend([
                "--random-agent",
                "--rate-limit", "5",
                "--scan-delay", "2000",
                "--time-limit", str(timeout),
            ])
        else:
            cmd.extend([
                "--timeout", str(timeout),
            ])
        
        # Common extensions to check
        cmd.extend(["-x", "php,html,htm,txt,js,css,json,xml,bak,old,save"])
        
        # Filter out common false positives
        cmd.extend(["--filter-status", "404,500,502,503"])
        
        # Don't follow redirects by default (we'll handle them)
        cmd.extend(["--redirects", "0"])
        
        return cmd
    
    def run_feroxbuster_scan(self, url: str, wordlist: str, threads: int = 10,
                           timeout: int = 300, stealth: bool = False) -> Dict[str, Any]:
        """Run feroxbuster scan and parse results"""
        
        if not self.check_feroxbuster_installed():
            return {"error": "Feroxbuster not installed"}
        
        self.logger.info(f"🎯 Starting directory busting on {url}")
        self.logger.info(f"📁 Wordlist: {wordlist}")
        self.logger.info(f"🔄 Threads: {threads}, Stealth: {stealth}")
        
        cmd = self.build_feroxbuster_command(url, wordlist, threads, timeout, stealth)
        
        self.logger.debug(f"Feroxbuster command: {' '.join(cmd)}")
        
        try:
            # Run feroxbuster
            start_time = time.time()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Parse output in real-time
            results = []
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    if data.get("type") == "response":
                        results.append(data)
                        # Show progress
                        if len(results) % 50 == 0:
                            self.logger.info(f"📈 Found {len(results)} items so far...")
                except json.JSONDecodeError:
                    continue
            
            # Wait for process to complete
            process.wait(timeout=timeout + 10)
            
            scan_duration = round(time.time() - start_time, 2)
            
            # Check for errors
            stderr = process.stderr.read()
            if process.returncode != 0 and stderr:
                self.logger.warning(f"Feroxbuster warnings: {stderr}")
            
            # Process results
            processed_results = self._process_feroxbuster_results(results, url)
            
            self.logger.info(f"✅ Directory busting completed in {scan_duration}s")
            self.logger.info(f"📊 Found {len(processed_results)} interesting items")
            
            return {
                "success": True,
                "target": url,
                "wordlist": wordlist,
                "threads": threads,
                "stealth_mode": stealth,
                "scan_duration": scan_duration,
                "total_found": len(processed_results),
                "results": processed_results,
                "raw_count": len(results)
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"⏰ Feroxbuster timed out after {timeout} seconds")
            process.kill()
            return {"error": f"Scan timed out after {timeout} seconds"}
        except Exception as e:
            self.logger.error(f"💥 Feroxbuster error: {str(e)}")
            return {"error": f"Scan failed: {str(e)}"}
    
    def _process_feroxbuster_results(self, raw_results: List[Dict], base_url: str) -> List[Dict[str, Any]]:
        """Process and filter feroxbuster results"""
        processed = []
        
        for result in raw_results:
            url = result.get("url", "")
            status = result.get("status", 0)
            content_length = result.get("content_length", 0)
            redirect = result.get("redirect_location")
            
            # Skip error status codes and small responses (likely 404 pages)
            if status in [404, 500, 502, 503]:
                continue
            
            # Calculate path depth for sorting
            path = url.replace(base_url, "").strip("/")
            depth = path.count("/") + 1 if path else 0
            
            # Categorize findings
            category = self._categorize_finding(path, status, content_length)
            
            processed.append({
                "url": url,
                "path": path,
                "status": status,
                "content_length": content_length,
                "redirect": redirect,
                "depth": depth,
                "category": category,
                "interesting": self._is_interesting_finding(path, status, content_length)
            })
        
        # Sort by interestingness, then by depth, then by status
        processed.sort(key=lambda x: (
            -x["interesting"],  # Most interesting first
            x["depth"],         # Then shallow paths
            x["status"]         # Then status code
        ))
        
        return processed
    
    def _categorize_finding(self, path: str, status: int, length: int) -> str:
        """Categorize findings for better analysis"""
        path_lower = path.lower()
        
        # Admin and authentication
        if any(term in path_lower for term in ["admin", "login", "auth", "signin", "dashboard", "panel"]):
            return "Administrative"
        
        # API endpoints
        if any(term in path_lower for term in ["api", "rest", "graphql", "json", "xml"]):
            return "API"
        
        # Configuration files
        if any(term in path_lower for term in [".env", "config", "settings", ".git", "backup"]):
            return "Configuration"
        
        # Documentation
        if any(term in path_lower for term in ["readme", "doc", "help", "faq"]):
            return "Documentation"
        
        # Uploads and media
        if any(term in path_lower for term in ["upload", "media", "images", "files"]):
            return "Media"
        
        # Development and debugging
        if any(term in path_lower for term in ["debug", "test", "dev", "stage"]):
            return "Development"
        
        # Common web directories
        if any(term in path_lower for term in ["css", "js", "static", "assets"]):
            return "Web Resources"
        
        return "General"
    
    def _is_interesting_finding(self, path: str, status: int, length: int) -> int:
        """Rate how interesting a finding is (higher = more interesting)"""
        score = 0
        
        path_lower = path.lower()
        
        # Status code points
        if status == 200:
            score += 3
        elif status in [301, 302]:
            score += 2
        elif status == 403:
            score += 1
        
        # Content length (medium sizes often mean actual content)
        if 100 < length < 10000:
            score += 2
        
        # High-value paths
        high_value_terms = [
            "admin", "login", "config", ".env", ".git", "backup", 
            "api", "upload", "install", "setup", "debug", "test"
        ]
        for term in high_value_terms:
            if term in path_lower:
                score += 3
        
        # Medium-value paths
        medium_value_terms = [
            "dashboard", "panel", "control", "manager", "system",
            "database", "db", "sql", "export", "import"
        ]
        for term in medium_value_terms:
            if term in path_lower:
                score += 2
        
        return score
    
    def quick_manual_check(self, url: str, timeout: int = 5) -> List[Dict[str, Any]]:
        """Perform quick manual checks for common high-value targets"""
        common_targets = [
            "/.git/HEAD",
            "/.env",
            "/wp-config.php",
            "/config.php",
            "/backup.zip",
            "/admin",
            "/administrator",
            "/phpmyadmin",
            "/server-status",
            "/.htaccess",
            "/web.config",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
        ]
        
        results = []
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        def check_target(target_path):
            target_url = urljoin(url, target_path)
            try:
                response = session.get(
                    target_url, 
                    timeout=timeout, 
                    verify=False,
                    allow_redirects=False
                )
                return {
                    "url": target_url,
                    "status": response.status_code,
                    "content_length": len(response.content),
                    "redirect": response.headers.get('Location') if response.is_redirect else None
                }
            except Exception as e:
                return {
                    "url": target_url,
                    "status": 0,
                    "error": str(e)
                }
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_target = {
                executor.submit(check_target, target): target 
                for target in common_targets
            }
            
            for future in as_completed(future_to_target):
                result = future.result()
                if result.get("status", 0) not in [0, 404]:
                    results.append(result)
        
        self.logger.info(f"🔍 Quick check found {len(results)} interesting manual targets")
        return results

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    engine = DirectoryBusterEngine(config, logger)
    
    print("🧪 Testing Directory Buster Engine...")
    
    # Test wordlist detection
    wordlists = engine.get_available_wordlists()
    print(f"\n📁 Available wordlists: {len(wordlists)}")
    for wl in wordlists[:3]:  # Show first 3
        print(f"  • {wl['description']}")
    
    # Test quick manual check
    print(f"\n🔍 Testing quick manual check...")
    quick_results = engine.quick_manual_check("https://httpbin.org")
    for result in quick_results:
        print(f"  {result['url']} -> {result['status']}")
    
    # Test with a safe target (small scan)
    if wordlists:
        test_wordlist = wordlists[0]["path"]
        print(f"\n🚀 Testing feroxbuster with {test_wordlist}...")
        
        # Just test with a few words to avoid long scan
        results = engine.run_feroxbuster_scan(
            "https://httpbin.org",
            test_wordlist,
            threads=5,
            timeout=30,
            stealth=True
        )
        
        if "error" not in results:
            print(f"✅ Scan completed in {results.get('scan_duration', 0)}s")
            print(f"📊 Found {results.get('total_found', 0)} items")
            
            interesting = [r for r in results.get('results', []) if r['interesting'] > 5]
            print(f"🎯 {len(interesting)} interesting findings:")
            for item in interesting[:5]:  # Show top 5
                print(f"  • {item['path']} ({item['status']}) - {item['category']}")
        else:
            print(f"❌ Scan failed: {results['error']}")
