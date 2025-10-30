# modules/directory_buster.py
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from engines.directory_buster_engine import DirectoryBusterEngine
from core.utils import ValidationUtils

class DirectoryBuster:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.engine = DirectoryBusterEngine(config_manager, logger)
        self.validator = ValidationUtils()
    
    def get_scan_profiles(self) -> List[Dict[str, Any]]:
        """Return different scanning profiles for various scenarios"""
        return [
            {
                "id": "quick",
                "name": "Quick Scan",
                "description": "Fast scan with common words only",
                "threads": 10,
                "timeout": 120,
                "stealth": False,
                "wordlist_size": "small"
            },
            {
                "id": "standard", 
                "name": "Standard Scan",
                "description": "Balanced scan for most scenarios",
                "threads": 20,
                "timeout": 300,
                "stealth": False,
                "wordlist_size": "medium"
            },
            {
                "id": "stealth",
                "name": "Stealth Scan",
                "description": "Slow, quiet scan to avoid detection",
                "threads": 5,
                "timeout": 600,
                "stealth": True,
                "wordlist_size": "small"
            },
            {
                "id": "comprehensive",
                "name": "Comprehensive Scan",
                "description": "Thorough scan with large wordlist",
                "threads": 25,
                "timeout": 900,
                "stealth": False,
                "wordlist_size": "large"
            },
            {
                "id": "aggressive",
                "name": "Aggressive Scan", 
                "description": "Maximum speed and coverage",
                "threads": 50,
                "timeout": 600,
                "stealth": False,
                "wordlist_size": "large"
            }
        ]
    
    def validate_target(self, target: str) -> Dict[str, Any]:
        """Validate and prepare target URL"""
        # Ensure URL has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        # Basic URL validation
        if not self.validator.validate_url(target):
            return {
                "valid": False,
                "error": f"Invalid URL: {target}"
            }
        
        return {
            "valid": True,
            "normalized_url": target,
            "domain": target.split('//')[-1].split('/')[0]
        }
    
    def select_wordlist(self, profile: Dict, available_wordlists: List[Dict]) -> Optional[str]:
        """Select appropriate wordlist based on scan profile"""
        if not available_wordlists:
            return None
        
        size_preference = profile.get("wordlist_size", "medium")
        
        # Sort wordlists by size
        small_wordlists = [wl for wl in available_wordlists if wl.get("size", 0) < 100000]  # < 100KB
        medium_wordlists = [wl for wl in available_wordlists if 100000 <= wl.get("size", 0) < 1000000]  # 100KB - 1MB
        large_wordlists = [wl for wl in available_wordlists if wl.get("size", 0) >= 1000000]  # >= 1MB
        
        if size_preference == "small" and small_wordlists:
            return small_wordlists[0]["path"]
        elif size_preference == "medium" and medium_wordlists:
            return medium_wordlists[0]["path"]
        elif size_preference == "large" and large_wordlists:
            return large_wordlists[0]["path"]
        
        # Fallback to first available wordlist
        return available_wordlists[0]["path"]
    
    def run_directory_scan(self, target: str, profile_id: str = "standard", 
                          custom_wordlist: str = None, custom_threads: int = None,
                          custom_timeout: int = None) -> Dict[str, Any]:
        """Main method to run directory busting scan"""
        
        # Validate target
        validation = self.validate_target(target)
        if not validation["valid"]:
            return {
                "success": False,
                "error": validation["error"]
            }
        
        normalized_url = validation["normalized_url"]
        
        # Get scan profile
        profiles = self.get_scan_profiles()
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
        
        # Use custom settings if provided
        threads = custom_threads or profile["threads"]
        timeout = custom_timeout or profile["timeout"]
        stealth = profile["stealth"]
        
        self.logger.scan_start("directory_busting", normalized_url)
        self.logger.info(f"📁 Using wordlist: {Path(wordlist).name}")
        self.logger.info(f"⚡ Profile: {profile['name']}")
        self.logger.info(f"🔄 Threads: {threads}, Timeout: {timeout}s")
        
        # Run quick manual checks first
        self.logger.info("🔍 Running quick manual checks...")
        quick_results = self.engine.quick_manual_check(normalized_url)
        
        # Run main feroxbuster scan
        self.logger.info("🚀 Starting main directory busting scan...")
        scan_results = self.engine.run_feroxbuster_scan(
            url=normalized_url,
            wordlist=wordlist,
            threads=threads,
            timeout=timeout,
            stealth=stealth
        )
        
        if "error" in scan_results:
            return {
                "success": False,
                "error": scan_results["error"]
            }
        
        # Combine results
        combined_results = {
            "success": True,
            "target": normalized_url,
            "profile": profile,
            "wordlist": wordlist,
            "wordlist_name": Path(wordlist).name,
            "scan_config": {
                "threads": threads,
                "timeout": timeout,
                "stealth": stealth
            },
            "quick_check_results": quick_results,
            "main_scan_results": scan_results,
            "summary": self._generate_summary(scan_results, quick_results),
            "timestamp": datetime.now().isoformat()
        }
        
        self.logger.scan_complete("directory_busting", normalized_url, 
                                combined_results["summary"]["total_interesting_findings"])
        
        return combined_results
    
    def _generate_summary(self, scan_results: Dict, quick_results: List) -> Dict[str, Any]:
        """Generate summary of findings"""
        main_results = scan_results.get("results", [])
        
        # Count by category
        categories = {}
        for result in main_results:
            category = result.get("category", "Unknown")
            categories[category] = categories.get(category, 0) + 1
        
        # Count interesting findings
        interesting_findings = [r for r in main_results if r.get("interesting", 0) >= 5]
        
        # Count by status code
        status_codes = {}
        for result in main_results:
            status = result.get("status", 0)
            status_codes[status] = status_codes.get(status, 0) + 1
        
        return {
            "total_found": len(main_results),
            "total_interesting_findings": len(interesting_findings),
            "quick_check_findings": len(quick_results),
            "categories": categories,
            "status_codes": status_codes,
            "scan_duration": scan_results.get("scan_duration", 0)
        }
    
    def generate_scan_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable scan report"""
        
        if not results.get("success", False):
            return f"❌ Scan failed: {results.get('error', 'Unknown error')}"
        
        report = []
        report.append("=" * 70)
        report.append("📁 DIRECTORY BUSTING SCAN REPORT")
        report.append("=" * 70)
        report.append(f"Target: {results.get('target', 'Unknown')}")
        report.append(f"Profile: {results.get('profile', {}).get('name', 'Unknown')}")
        report.append(f"Wordlist: {results.get('wordlist_name', 'Unknown')}")
        report.append(f"Scan Date: {results.get('timestamp', 'Unknown')}")
        report.append("")
        
        # Summary section
        summary = results.get("summary", {})
        report.append("📊 SCAN SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Items Found: {summary.get('total_found', 0)}")
        report.append(f"Interesting Findings: {summary.get('total_interesting_findings', 0)}")
        report.append(f"Quick Check Findings: {summary.get('quick_check_findings', 0)}")
        report.append(f"Scan Duration: {summary.get('scan_duration', 0)} seconds")
        report.append("")
        
        # Categories breakdown
        categories = summary.get('categories', {})
        if categories:
            report.append("📂 FINDINGS BY CATEGORY")
            report.append("-" * 30)
            for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                report.append(f"  {category}: {count}")
            report.append("")
        
        # Quick check results
        quick_results = results.get("quick_check_results", [])
        if quick_results:
            report.append("🔍 QUICK CHECK RESULTS")
            report.append("-" * 30)
            for result in quick_results:
                status_color = "🟢" if result.get('status') == 200 else "🟡" if result.get('status') in [301, 302] else "🔴"
                report.append(f"  {status_color} {result.get('url', 'Unknown')} -> {result.get('status', 'Error')}")
            report.append("")
        
        # Main interesting findings
        main_results = results.get("main_scan_results", {}).get("results", [])
        interesting_findings = [r for r in main_results if r.get("interesting", 0) >= 5]
        
        if interesting_findings:
            report.append("🎯 INTERESTING FINDINGS")
            report.append("-" * 30)
            report.append("  URL                                 Status  Size     Category")
            report.append("  ---                                 ------  ----     --------")
            
            for finding in interesting_findings[:20]:  # Show top 20
                url = finding.get("path", "")[:40].ljust(40)
                status = str(finding.get("status", 0)).ljust(6)
                size = str(finding.get("content_length", 0)).ljust(8)
                category = finding.get("category", "Unknown")
                
                report.append(f"  {url} {status} {size} {category}")
            
            if len(interesting_findings) > 20:
                report.append(f"  ... and {len(interesting_findings) - 20} more interesting findings")
            report.append("")
        
        # All findings table (condensed)
        if main_results:
            report.append("📋 ALL FINDINGS (Condensed)")
            report.append("-" * 30)
            
            # Group by status code
            status_groups = {}
            for result in main_results:
                status = result.get("status", 0)
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(result)
            
            for status, items in sorted(status_groups.items()):
                report.append(f"  HTTP {status} ({len(items)} items):")
                # Show first 3 paths for each status
                for item in items[:3]:
                    report.append(f"    • {item.get('path', '')}")
                if len(items) > 3:
                    report.append(f"    ... and {len(items) - 3} more")
                report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 30)
        
        total_findings = summary.get('total_found', 0)
        if total_findings == 0:
            report.append("  ✅ No directories/files found - target appears well secured")
        elif total_findings < 10:
            report.append("  🔍 Few findings - consider using a larger wordlist or different profile")
        elif total_findings > 100:
            report.append("  🚨 Many findings discovered - review all results carefully")
        
        interesting_count = summary.get('total_interesting_findings', 0)
        if interesting_count > 0:
            report.append(f"  ⚠️  {interesting_count} interesting findings need immediate attention")
        
        report.append("  📝 Manual verification of all findings is recommended")
        report.append("")
        
        report.append("=" * 70)
        report.append("💡 Note: This scan discovers exposed resources. Review findings for security issues.")
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def save_scan_results(self, results: Dict[str, Any], filename: str = None):
        """Save scan results to file"""
        from datetime import datetime
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = results.get('target', 'unknown').replace('://', '_').replace('/', '_').replace('.', '_')
            filename = f"dirbust_{safe_target}_{timestamp}.json"
        
        # Ensure scans directory exists
        scans_dir = self.config.home_dir / "scans"
        scans_dir.mkdir(exist_ok=True)
        
        file_path = scans_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 Directory busting results saved to: {file_path}")
            return str(file_path)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save directory busting results: {str(e)}")
            return None

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    scanner = DirectoryBuster(config, logger)
    
    print("🧪 Testing Directory Buster...")
    
    # Show available profiles
    profiles = scanner.get_scan_profiles()
    print("\n📋 Available Scan Profiles:")
    for profile in profiles:
        print(f"  • {profile['name']}: {profile['description']}")
    
    # Test with a safe target
    test_url = "https://httpbin.org"
    
    print(f"\n🔍 Testing quick scan on {test_url}...")
    results = scanner.run_directory_scan(test_url, "quick")
    
    if results.get('success'):
        report = scanner.generate_scan_report(results)
        print("\n" + report)
        
        # Save results
        saved_path = scanner.save_scan_results(results)
        if saved_path:
            print(f"\n💾 Results saved to: {saved_path}")
    else:
        print(f"❌ Scan failed: {results.get('error')}")
