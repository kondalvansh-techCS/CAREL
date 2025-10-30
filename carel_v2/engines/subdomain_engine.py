# engines/subdomain_engine.py
import asyncio
import dns.resolver
import dns.asyncresolver
import aiodns
import subprocess
import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from urllib.parse import urlparse

class SubdomainEngine:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.found_subdomains: Set[str] = set()
    
    def get_enumeration_methods(self) -> List[Dict[str, Any]]:
        """Return available subdomain enumeration methods"""
        methods = [
            {
                "id": "dns_brute",
                "name": "DNS Brute Force",
                "description": "Fast DNS resolution with wordlist",
                "speed": "Fast",
                "stealth": "Low",
                "requires": "Wordlist"
            },
            {
                "id": "async_dns",
                "name": "Async DNS",
                "description": "High-performance async DNS resolution",
                "speed": "Very Fast", 
                "stealth": "Low",
                "requires": "Wordlist, aiodns"
            },
            {
                "id": "sublist3r",
                "name": "Sublist3r",
                "description": "Use Sublist3r tool with public sources",
                "speed": "Medium",
                "stealth": "Medium", 
                "requires": "Sublist3r installed"
            },
            {
                "id": "hybrid",
                "name": "Hybrid Approach",
                "description": "Combine multiple methods for best results",
                "speed": "Medium",
                "stealth": "Medium",
                "requires": "Multiple tools"
            }
        ]
        return methods
    
    def get_available_wordlists(self) -> List[Dict[str, str]]:
        """Get available subdomain wordlists"""
        wordlists_dir = self.config.home_dir / "wordlists"
        wordlists_dir.mkdir(exist_ok=True)
        
        common_paths = [
            ("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "SecLists Top 5K"),
            ("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt", "SecLists Top 20K"),
            ("/usr/share/wordlists/dnsmap.txt", "DNSMap Wordlist"),
            ("/usr/share/wordlists/subdomains.txt", "Common Subdomains"),
            (str(wordlists_dir / "subdomains.txt"), "CAREL Subdomains"),
        ]
        
        available = []
        
        for path, description in common_paths:
            if Path(path).exists():
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        line_count = sum(1 for _ in f)
                    description = f"{description} (~{line_count} words)"
                except:
                    pass
                
                available.append({
                    "path": path,
                    "description": description,
                    "size": Path(path).stat().st_size if Path(path).exists() else 0
                })
        
        # Create default subdomain wordlist if none exist
        if not available:
            self._create_default_subdomain_wordlist()
            available.append({
                "path": str(wordlists_dir / "subdomains.txt"),
                "description": "CAREL Subdomains (Built-in)",
                "size": Path(str(wordlists_dir / "subdomains.txt")).stat().st_size
            })
        
        return available
    
    def _create_default_subdomain_wordlist(self):
        """Create a default subdomain wordlist"""
        wordlists_dir = self.config.home_dir / "wordlists"
        wordlists_dir.mkdir(exist_ok=True)
        
        default_subdomains = [
            # Common subdomains
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap",
            "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
            "vpn", "ns4", "mail2", "new", "mysql", "old", "lists", "support", "mobile",
            "mx", "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp",
            "calendar", "wiki", "web", "media", "email", "images", "img", "cdn",
            "uploads", "download", "downloads", "backup", "backups", "search",
            "staging", "api", "apis", "app", "apps", "office", "owa", "proxy",
            "en", "us", "de", "it", "fr", "es", "ru", "cn", "jp", "uk", "au",
            "cache", "dns", "dns1", "dns2", "dns3", "dns4", "dns5", "dns6",
            "ns5", "ns6", "ns7", "ns8", "ns9", "ns10", "ns0", "dns0",
            
            # Cloud and hosting
            "cdn", "cdn1", "cdn2", "cdn3", "cdn4", "cdn5", "cdn6", "cdn7", "cdn8",
            "cloud", "cloud1", "cloud2", "cloud3", "cloud4", "s3", "s3-bucket",
            "storage", "storage1", "storage2", "assets", "assets1", "assets2",
            "media", "media1", "media2", "images", "images1", "images2",
            "img", "img1", "img2", "static", "static1", "static2",
            
            # Development and staging
            "dev", "devel", "develop", "development", "stage", "staging", "test",
            "testing", "qa", "preprod", "pre-prod", "sandbox", "demo", "demo1",
            "lab", "labs", "experiment", "experimental", "beta", "alpha",
            "new", "old", "temp", "tmp", "backup", "back", "bak",
            
            # Administrative
            "admin", "administrator", "adm", "ad", "manager", "management",
            "manage", "direct", "director", "office", "offices", "corp",
            "corporate", "enterprise", "internal", "intranet", "portal",
            "login", "logins", "signin", "signins", "auth", "authentication",
            "account", "accounts", "user", "users", "member", "members",
            "profile", "profiles", "dashboard", "dash", "control", "controller",
            "panel", "cp", "cpanel", "whm", "webmin", "plesk",
            
            # Services and applications
            "api", "apis", "app", "apps", "application", "applications",
            "service", "services", "svc", "svcs", "gateway", "gateways",
            "router", "routers", "switch", "switches", "firewall", "fw",
            "loadbalancer", "loadbalance", "lb", "load", "balance",
            "monitor", "monitoring", "nagios", "zabbix", "cacti",
            "database", "db", "dbs", "sql", "mysql", "postgres", "mongo",
            "redis", "memcache", "cache", "caching",
            
            # Mail and communication
            "mail", "email", "emails", "smtp", "pop", "pop3", "imap", "imaps",
            "exchange", "exch", "owa", "outlook", "webmail", "webemail",
            "mailserver", "mail1", "mail2", "mail3", "mail4", "mail5",
            "mx", "mx1", "mx2", "mx3", "mx4", "mx5", "mx6", "mx7", "mx8",
            "mx9", "mx10", "mx0", "mta", "mta1", "mta2", "mta3",
            
            # Network infrastructure
            "ns", "dns", "router", "switch", "firewall", "fw", "vpn", "vpn1",
            "vpn2", "vpn3", "gateway", "gw", "proxy", "proxy1", "proxy2",
            "bastion", "jump", "jumpserver", "jumpbox", "nat", "nat1",
            "loadbalancer", "lb", "loadbalance", "balancer",
            
            # Geographic and language
            "en", "us", "uk", "gb", "de", "fr", "es", "it", "ru", "cn", "jp",
            "au", "ca", "br", "in", "sg", "hk", "tw", "kr", "nl", "se", "no",
            "dk", "fi", "pl", "cz", "hu", "ro", "gr", "tr", "ae", "sa",
            "na", "sa", "eu", "asia", "apac", "emea", "latam", "mena",
            "north", "south", "east", "west", "central", "global",
            
            # Technology specific
            "wp", "wordpress", "joomla", "drupal", "magento", "shopify",
            "php", "phpmyadmin", "cgi", "cgi-bin", "bin", "scripts",
            "java", "jsp", "asp", "aspx", "net", "dotnet", "rails",
            "python", "django", "flask", "node", "nodejs", "go", "golang",
            "ruby", "ror", "laravel", "symfony", "yii", "codeigniter",
            "spring", "struts", "hibernate", "jquery", "angular", "react",
            "vue", "ember", "backbone", "bootstrap", "foundation",
            
            # E-commerce
            "shop", "store", "cart", "checkout", "payment", "pay", "billing",
            "invoice", "invoices", "order", "orders", "product", "products",
            "catalog", "catalogue", "category", "categories", "item", "items",
            "price", "prices", "sale", "sales", "promo", "promotion",
            "discount", "coupon", "voucher", "deal", "deals",
            
            # Social and community
            "blog", "blogs", "news", "newsletter", "article", "articles",
            "post", "posts", "forum", "forums", "community", "communities",
            "social", "socialmedia", "facebook", "twitter", "instagram",
            "linkedin", "youtube", "vimeo", "flickr", "pinterest",
            "share", "sharing", "comment", "comments", "review", "reviews",
            "rating", "ratings", "vote", "votes", "poll", "polls",
            
            # Security and monitoring
            "security", "secure", "ssl", "tls", "https", "http", "ftp",
            "sftp", "scp", "rsync", "ssh", "telnet", "rdp", "vnc",
            "monitor", "monitoring", "nagios", "zabbix", "cacti", "prtg",
            "solarwinds", "grafana", "prometheus", "kibana", "elastic",
            "log", "logs", "logging", "audit", "auditing", "scan", "scanner",
            "virus", "malware", "antivirus", "firewall", "ids", "ips",
            
            # Mobile and apps
            "m", "mobile", "mob", "android", "ios", "iphone", "ipad",
            "tablet", "phone", "app", "apps", "application", "applications",
            "play", "game", "games", "gaming", "player", "players",
            "stream", "streaming", "video", "videos", "audio", "music",
            "radio", "tv", "television", "film", "films", "movie", "movies",
        ]
        
        wordlist_path = wordlists_dir / "subdomains.txt"
        with open(wordlist_path, 'w', encoding='utf-8') as f:
            for subdomain in sorted(set(default_subdomains)):
                f.write(f"{subdomain}\n")
        
        self.logger.info(f"📝 Created default subdomain wordlist with {len(default_subdomains)} entries")
        return wordlist_path
    
    def check_sublist3r_installed(self) -> Tuple[bool, Optional[str]]:
        """Check if Sublist3r is installed and return path"""
        possible_paths = [
            "sublist3r",
            "/usr/bin/sublist3r",
            "/usr/local/bin/sublist3r",
            "/usr/share/sublist3r/sublist3r.py",
            str(Path.home() / ".local/bin/sublist3r"),
            self.config.get("sublist3r_path", "")
        ]
        
        for path in possible_paths:
            if not path:
                continue
                
            try:
                # Check if it's a Python script or executable
                if path.endswith('.py'):
                    if Path(path).exists():
                        return True, path
                else:
                    result = subprocess.run(
                        ["which", path], 
                        capture_output=True, 
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        return True, result.stdout.strip()
            except:
                continue
        
        return False, None
    
    async def async_dns_enumeration(self, domain: str, wordlist_path: str, 
                                  timeout: int = 5, max_concurrent: int = 100) -> List[str]:
        """Perform async DNS enumeration"""
        if not aiodns:
            self.logger.warning("aiodns not available, falling back to threaded DNS")
            return self.threaded_dns_enumeration(domain, wordlist_path, timeout)
        
        found = []
        
        # Read wordlist
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [f"{line.strip()}.{domain}" for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Failed to read wordlist: {e}")
            return []
        
        self.logger.info(f"🔍 Starting async DNS enumeration for {domain} with {len(subdomains)} subdomains")
        
        resolver = aiodns.DNSResolver(timeout=timeout)
        
        async def check_subdomain(subdomain):
            try:
                await resolver.query(subdomain, 'A')
                return subdomain
            except (aiodns.error.DNSError, Exception):
                return None
        
        # Process in batches to avoid overwhelming
        batch_size = max_concurrent
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            tasks = [check_subdomain(subdomain) for subdomain in batch]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    found.append(result)
                    self.logger.debug(f"Found: {result}")
            
            # Progress update
            if (i + batch_size) % 1000 == 0:
                self.logger.info(f"📈 Progress: {min(i + batch_size, len(subdomains))}/{len(subdomains)} subdomains checked")
        
        return found
    
    def threaded_dns_enumeration(self, domain: str, wordlist_path: str, 
                               timeout: int = 5, max_workers: int = 50) -> List[str]:
        """Perform threaded DNS enumeration"""
        found = []
        
        # Read wordlist
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [f"{line.strip()}.{domain}" for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Failed to read wordlist: {e}")
            return []
        
        self.logger.info(f"🔍 Starting threaded DNS enumeration for {domain} with {len(subdomains)} subdomains")
        
        def resolve_subdomain(subdomain):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = timeout
                resolver.lifetime = timeout
                resolver.resolve(subdomain, 'A')
                return subdomain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                   dns.resolver.Timeout, dns.exception.DNSException):
                return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {
                executor.submit(resolve_subdomain, subdomain): subdomain 
                for subdomain in subdomains
            }
            
            for i, future in enumerate(as_completed(future_to_subdomain)):
                result = future.result()
                if result:
                    found.append(result)
                    self.logger.debug(f"Found: {result}")
                
                # Progress update
                if (i + 1) % 1000 == 0:
                    self.logger.info(f"📈 Progress: {i + 1}/{len(subdomains)} subdomains checked")
        
        return found
    
    def run_sublist3r(self, domain: str, timeout: int = 600) -> List[str]:
        """Run Sublist3r tool"""
        is_installed, sublist3r_path = self.check_sublist3r_installed()
        
        if not is_installed:
            self.logger.warning("Sublist3r not found, skipping this method")
            return []
        
        self.logger.info(f"🔍 Running Sublist3r for {domain}")
        
        output_file = Path("/tmp") / f"sublist3r_{domain}_{int(time.time())}.txt"
        
        try:
            if sublist3r_path.endswith('.py'):
                cmd = [
                    "python3", sublist3r_path,
                    "-d", domain,
                    "-o", str(output_file)
                ]
            else:
                cmd = [
                    sublist3r_path,
                    "-d", domain, 
                    "-o", str(output_file)
                ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if process.returncode != 0:
                self.logger.warning(f"Sublist3r had non-zero exit: {process.stderr}")
            
            # Read results
            if output_file.exists():
                with open(output_file, 'r', encoding='utf-8') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                
                # Clean up
                output_file.unlink()
                
                self.logger.info(f"Sublist3r found {len(subdomains)} subdomains")
                return subdomains
            else:
                self.logger.warning("Sublist3r produced no output file")
                return []
                
        except subprocess.TimeoutExpired:
            self.logger.error("Sublist3r timed out")
            return []
        except Exception as e:
            self.logger.error(f"Sublist3r error: {e}")
            return []
    
    def verify_live_subdomains(self, subdomains: List[str], timeout: int = 5) -> List[Dict[str, Any]]:
        """Verify which subdomains are live (HTTP/HTTPS)"""
        live_subdomains = []
        
        def check_protocol(subdomain, protocol):
            url = f"{protocol}://{subdomain}"
            try:
                response = requests.get(
                    url, 
                    timeout=timeout, 
                    verify=False,
                    allow_redirects=True
                )
                return {
                    "subdomain": subdomain,
                    "url": url,
                    "status_code": response.status_code,
                    "protocol": protocol,
                    "live": True
                }
            except Exception:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            for subdomain in subdomains:
                for protocol in ['https', 'http']:
                    futures.append(
                        executor.submit(check_protocol, subdomain, protocol)
                    )
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_subdomains.append(result)
                    # Break if we found a live protocol for a subdomain
                    break
        
        # Remove duplicates (keep first occurrence - usually HTTPS)
        seen = set()
        unique_live = []
        for item in live_subdomains:
            if item['subdomain'] not in seen:
                seen.add(item['subdomain'])
                unique_live.append(item)
        
        self.logger.info(f"🌐 Found {len(unique_live)} live subdomains")
        return unique_live

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    engine = SubdomainEngine(config, logger)
    
    print("🧪 Testing Subdomain Engine...")
    
    # Test methods
    methods = engine.get_enumeration_methods()
    print(f"\n📋 Available Methods: {len(methods)}")
    for method in methods:
        print(f"  • {method['name']}: {method['description']}")
    
    # Test wordlists
    wordlists = engine.get_available_wordlists()
    print(f"\n📁 Available Wordlists: {len(wordlists)}")
    for wl in wordlists[:3]:
        print(f"  • {wl['description']}")
    
    # Test Sublist3r
    sl_installed, path = engine.check_sublist3r_installed()
    print(f"\n🔧 Sublist3r: {'Installed' if sl_installed else 'Not installed'}")
    if sl_installed:
        print(f"   Path: {path}")
    
    # Test threaded DNS (small test)
    if wordlists:
        test_domain = "example.com"
        test_wordlist = wordlists[0]["path"]
        
        print(f"\n🔍 Testing threaded DNS with {test_domain}...")
        found = engine.threaded_dns_enumeration(test_domain, test_wordlist, timeout=2, max_workers=5)
        print(f"   Found {len(found)} subdomains")
        for sub in found[:5]:  # Show first 5
            print(f"   • {sub}")
