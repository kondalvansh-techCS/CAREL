# modules/subdomain_enum.py
import asyncio
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from engines.subdomain_engine import SubdomainEngine
from core.utils import ValidationUtils

class SubdomainEnum:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.engine = SubdomainEngine(config_manager, logger)
        self.validator = ValidationUtils()
    
    def get_enumeration_profiles(self) -> List[Dict[str, Any]]:
        """Return different enumeration profiles"""
        return [
            {
                "id": "quick",
                "name": "Quick Enumeration",
                "description": "Fast scan with top subdomains only",
                "methods": ["dns_brute"],
                "timeout": 120,
                "max_workers": 20,
                "wordlist_size": "small"
            },
            {
                "id": "standard",
                "name": "Standard Enumeration", 
                "description": "Balanced approach with multiple methods",
                "methods": ["dns_brute", "sublist3r"],
                "timeout": 300,
                "max_workers": 50,
                "wordlist_size": "medium"
            },
            {
                "id": "comprehensive",
                "name": "Comprehensive Enumeration",
                "description": "Thorough scan with all available methods",
                "methods": ["async_dns", "sublist3r", "dns_brute"],
                "timeout": 600,
                "max_workers": 100,
                "wordlist_size": "large"
            },
            {
                "id": "stealth",
                "name": "Stealth Enumeration",
                "description": "Slow and quiet to avoid detection",
                "methods": ["dns_brute"],
                "timeout": 900,
                "max_workers": 10,
                "wordlist_size": "small",
                "stealth": True
            }
        ]
    
    def validate_domain(self, domain: str) -> Dict[str, Any]:
        """Validate domain input"""
        domain = domain.strip().lower()
        
        # Remove protocol if present
        if "://" in domain:
            domain = domain.split("://")[1]
        
        # Remove path
        domain = domain.split("/")[0]
        
        # Remove www. prefix for cleaner results
        if domain.startswith("www."):
            domain = domain[4:]
        
        if not self.validator.validate_domain(domain):
            return {
                "valid": False,
                "error": f"Invalid domain: {domain}"
            }
        
        return {
            "valid": True,
            "normalized_domain": domain,
            "clean_domain": domain
        }
    
    def select_wordlist(self, profile: Dict, available_wordlists: List[Dict]) -> Optional[str]:
        """Select appropriate wordlist based on profile"""
        if not available_wordlists:
            return None
        
        size_preference = profile.get("wordlist_size", "medium")
        
        # Sort wordlists by size
        small_wordlists = [wl for wl in available_wordlists if wl.get("size", 0) < 50000]  # < 50KB
        medium_wordlists = [wl for wl in available_wordlists if 50000 <= wl.get("size", 0) < 500000]  # 50KB - 500KB
        large_wordlists = [wl for wl in available_wordlists if wl.get("size", 0) >= 500000]  # >= 500KB
        
        if size_preference == "small" and small_wordlists:
            return small_wordlists[0]["path"]
        elif size_preference == "medium" and medium_wordlists:
            return medium_wordlists[0]["path"]
        elif size_preference == "large" and large_wordlists:
            return large_wordlists[0]["path"]
        
        # Fallback to first available
        return available_wordlists[0]["path"]
    
    async def run_subdomain_enumeration(self, domain: str, profile_id: str = "standard",
                                      custom_wordlist: str = None, verify_live: bool = True) -> Dict[str, Any]:
        """Main method to run subdomain enumeration"""
        
        # Validate domain
        validation = self.validate_domain(domain)
        if not validation["valid"]:
            return {
                "success": False,
                "error": validation["error"]
            }
        
        clean_domain = validation["clean_domain"]
        
        # Get profile
        profiles = self.get_enumeration_profiles()
        profile = next((p for p in profiles if p["id"] == profile_id), profiles[1])  # Default to standard
        
        # Get available wordlists
        available_wordlists = self.engine.get_available_wordlists()
        if not available_wordlists:
            return {
                "success": False,
                "error": "No wordlists available"
            }
        
        # Select wordlist
        wordlist = custom_wordlist or self.select_wordlist(profile, available_wordlists)
        if not wordlist or not Path(wordlist).exists():
            return {
                "success": False,
                "error": f"Wordlist not found: {wordlist}"
            }
        
        self.logger.scan_start("subdomain_enumeration", clean_domain)
        self.logger.info(f"🎯 Starting subdomain enumeration for: {clean_domain}")
        self.logger.info(f"📋 Profile: {profile['name']}")
        self.logger.info(f"📁 Wordlist: {Path(wordlist).name}")
        self.logger.info(f"🔄 Methods: {', '.join(profile['methods'])}")
        
        all_subdomains = set()
        method_results = {}
        
        start_time = time.time()
        
        # Run each enabled method
        for method in profile["methods"]:
            self.logger.info(f"🚀 Running {method}...")
            
            try:
                if method == "async_dns":
                    if hasattr(self.engine, 'async_dns_enumeration'):
                        found = await self.engine.async_dns_enumeration(
                            clean_domain, wordlist, 
                            timeout=5, 
                            max_concurrent=profile["max_workers"]
                        )
                    else:
                        self.logger.warning("Async DNS not available, skipping")
                        found = []
                
                elif method == "dns_brute":
                    found = self.engine.threaded_dns_enumeration(
                        clean_domain, wordlist,
                        timeout=5,
                        max_workers=profile["max_workers"]
                    )
                
                elif method == "sublist3r":
                    found = self.engine.run_sublist3r(clean_domain, timeout=profile["timeout"])
                
                else:
                    found = []
                
                method_results[method] = {
                    "found": len(found),
                    "subdomains": found
                }
                
                # Add to main results
                all_subdomains.update(found)
                self.logger.info(f"✅ {method} found {len(found)} subdomains")
                
            except Exception as e:
                self.logger.error(f"❌ {method} failed: {e}")
                method_results[method] = {
                    "found": 0,
                    "error": str(e),
                    "subdomains": []
                }
        
        # Verify live subdomains if requested
        live_subdomains = []
        if verify_live and all_subdomains:
            self.logger.info("🌐 Verifying live subdomains...")
            live_subdomains = self.engine.verify_live_subdomains(list(all_subdomains))
        
        scan_duration = round(time.time() - start_time, 2)
        
        # Prepare results
        results = {
            "success": True,
            "target_domain": clean_domain,
            "profile": profile,
            "wordlist": wordlist,
            "wordlist_name": Path(wordlist).name,
            "scan_duration": scan_duration,
            "total_subdomains_found": len(all_subdomains),
            "total_live_subdomains": len(live_subdomains),
            "method_results": method_results,
            "all_subdomains": sorted(list(all_subdomains)),
            "live_subdomains": live_subdomains,
            "summary": self._generate_summary(method_results, live_subdomains, scan_duration),
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.scan_complete("subdomain_enumeration", clean_domain, len(all_subdomains))
        self.logger.info(f"📊 Found {len(all_subdomains)} total subdomains, {len(live_subdomains)} live")
        
        return results
    
    def _generate_summary(self, method_results: Dict, live_subdomains: List, scan_duration: float) -> Dict[str, Any]:
        """Generate scan summary"""
        total_found = 0
        method_breakdown = {}
        
        for method, results in method_results.items():
            found_count = results.get("found", 0)
            total_found += found_count
            method_breakdown[method] = found_count
        
        # Count live subdomains by status code
        status_codes = {}
        for subdomain in live_subdomains:
            status = subdomain.get("status_code", 0)
            status_codes[status] = status_codes.get(status, 0) + 1
        
        return {
            "total_subdomains": total_found,
            "live_subdomains": len(live_subdomains),
            "method_breakdown": method_breakdown,
            "status_codes": status_codes,
            "scan_duration": scan_duration
        }
    
    def generate_scan_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable scan report"""
        
        if not results.get("success", False):
            return f"❌ Scan failed: {results.get('error', 'Unknown error')}"
        
        report = []
        report.append("=" * 70)
        report.append("🌐 SUBDOMAIN ENUMERATION REPORT")
        report.append("=" * 70)
        report.append(f"Target Domain: {results.get('target_domain', 'Unknown')}")
        report.append(f"Profile: {results.get('profile', {}).get('name', 'Unknown')}")
        report.append(f"Wordlist: {results.get('wordlist_name', 'Unknown')}")
        report.append(f"Scan Date: {results.get('timestamp', 'Unknown')}")
        report.append("")
        
        # Summary section
        summary = results.get("summary", {})
        report.append("📊 SCAN SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Subdomains Found: {summary.get('total_subdomains', 0)}")
        report.append(f"Live Subdomains: {summary.get('live_subdomains', 0)}")
        report.append(f"Scan Duration: {summary.get('scan_duration', 0)} seconds")
        report.append("")
        
        # Method breakdown
        method_breakdown = summary.get('method_breakdown', {})
        if method_breakdown:
            report.append("🔧 METHOD BREAKDOWN")
            report.append("-" * 30)
            for method, count in method_breakdown.items():
                report.append(f"  {method}: {count} subdomains")
            report.append("")
        
        # Live subdomains
        live_subdomains = results.get("live_subdomains", [])
        if live_subdomains:
            report.append("🌐 LIVE SUBDOMAINS")
            report.append("-" * 30)
            report.append("  URL                               Status  Protocol")
            report.append("  ---                               ------  --------")
            
            for subdomain in live_subdomains[:25]:  # Show top 25
                url = subdomain.get('url', '')[:35].ljust(35)
                status = str(subdomain.get('status_code', 0)).ljust(6)
                protocol = subdomain.get('protocol', 'unknown')
                
                report.append(f"  {url} {status} {protocol}")
            
            if len(live_subdomains) > 25:
                report.append(f"  ... and {len(live_subdomains) - 25} more live subdomains")
            report.append("")
        
        # All subdomains (condensed)
        all_subdomains = results.get("all_subdomains", [])
        if all_subdomains:
            report.append("📋 ALL SUBDOMAINS FOUND")
            report.append("-" * 30)
            
            # Group by first part of subdomain for organization
            grouped = {}
            for subdomain in all_subdomains:
                first_part = subdomain.split('.')[0]
                if first_part not in grouped:
                    grouped[first_part] = []
                grouped[first_part].append(subdomain)
            
            # Show most common prefixes
            common_prefixes = sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True)[:10]
            
            for prefix, subdomains in common_prefixes:
                report.append(f"  {prefix}.* ({len(subdomains)} subdomains):")
                for subdomain in subdomains[:3]:  # Show first 3
                    report.append(f"    • {subdomain}")
                if len(subdomains) > 3:
                    report.append(f"    ... and {len(subdomains) - 3} more")
                report.append("")
        
        # Status code breakdown for live subdomains
        status_codes = summary.get('status_codes', {})
        if status_codes:
            report.append("📊 LIVE SUBDOMAINS BY STATUS CODE")
            report.append("-" * 40)
            for status, count in sorted(status_codes.items()):
                report.append(f"  HTTP {status}: {count} subdomains")
            report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 30)
        
        total_found = summary.get('total_subdomains', 0)
        live_count = summary.get('live_subdomains', 0)
        
        if total_found == 0:
            report.append("  ✅ No subdomains found - domain appears to have minimal subdomain usage")
        elif total_found < 10:
            report.append("  🔍 Few subdomains found - consider using a larger wordlist or comprehensive profile")
        elif total_found > 100:
            report.append("  🚨 Many subdomains discovered - review all subdomains for security implications")
        
        if live_count > 0:
            report.append(f"  ⚠️  {live_count} live subdomains need security assessment")
        
        report.append("  📝 Consider further analysis of discovered subdomains")
        report.append("")
        
        report.append("=" * 70)
        report.append("💡 Note: Subdomain enumeration helps discover potential attack surfaces.")
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def save_scan_results(self, results: Dict[str, Any], filename: str = None):
        """Save scan results to file"""
        from datetime import datetime
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_domain = results.get('target_domain', 'unknown').replace('.', '_')
            filename = f"subdomains_{safe_domain}_{timestamp}.json"
        
        # Ensure scans directory exists
        scans_dir = self.config.home_dir / "scans"
        scans_dir.mkdir(exist_ok=True)
        
        file_path = scans_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 Subdomain enumeration results saved to: {file_path}")
            return str(file_path)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save subdomain results: {str(e)}")
            return None

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    scanner = SubdomainEnum(config, logger)
    
    print("🧪 Testing Subdomain Enumeration...")
    
    # Show available profiles
    profiles = scanner.get_enumeration_profiles()
    print("\n📋 Available Profiles:")
    for profile in profiles:
        print(f"  • {profile['name']}: {profile['description']}")
    
    # Test with a safe domain
    test_domain = "example.com"
    
    print(f"\n🔍 Testing quick enumeration on {test_domain}...")
    
    # Run async function
    async def test_scan():
        return await scanner.run_subdomain_enumeration(test_domain, "quick", verify_live=False)
    
    results = asyncio.run(test_scan())
    
    if results.get('success'):
        report = scanner.generate_scan_report(results)
        print("\n" + report)
        
        # Save results
        saved_path = scanner.save_scan_results(results)
        if saved_path:
            print(f"\n💾 Results saved to: {saved_path}")
    else:
        print(f"❌ Scan failed: {results.get('error')}")
