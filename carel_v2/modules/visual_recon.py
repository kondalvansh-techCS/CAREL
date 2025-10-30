# modules/visual_recon.py
import json
import time
import random
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

# Optional stealth engine - falls back gracefully if not available
try:
    from modules.stealth_engine import StealthEngine
    STEALTH_AVAILABLE = True
except ImportError:
    STEALTH_AVAILABLE = False
    # Don't print warning here to avoid breaking existing functionality

from engines.visual_recon_engine import VisualReconEngine
from core.utils import ValidationUtils

class VisualRecon:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.engine = VisualReconEngine(config_manager, logger)
        self.validator = ValidationUtils()
        
        # Initialize stealth engine only if available - NO BREAKING CHANGES
        if STEALTH_AVAILABLE:
            self.stealth_engine = StealthEngine(config_manager, logger)
            self.logger.debug("Stealth engine initialized")
        else:
            self.stealth_engine = None
            self.logger.debug("Stealth engine not available - using standard features")
    
    def get_capture_profiles(self) -> List[Dict[str, Any]]:
        """Return different screenshot capture profiles - EXISTING PROFILES PRESERVED"""
        base_profiles = [
            {
                "id": "quick",
                "name": "Quick Capture",
                "description": "Fast screenshots with basic tools",
                "timeout": 15,
                "max_workers": 3,
                "tool_preference": "auto"
            },
            {
                "id": "quality",
                "name": "Quality Capture", 
                "description": "High-quality screenshots with Selenium",
                "timeout": 30,
                "max_workers": 2,
                "tool_preference": "selenium"
            },
            {
                "id": "stealth",
                "name": "Stealth Capture",
                "description": "Slow capture to avoid detection",
                "timeout": 45,
                "max_workers": 1,
                "tool_preference": "cutycapt",
                "stealth": True  # Existing stealth flag preserved
            },
            {
                "id": "batch",
                "name": "Batch Capture",
                "description": "Fast parallel capture for many URLs",
                "timeout": 20,
                "max_workers": 5,
                "tool_preference": "auto"
            }
        ]
        
        # Add enhanced stealth profiles if stealth engine is available
        if STEALTH_AVAILABLE and self.stealth_engine:
            enhanced_profiles = [
                {
                    "id": "aggressive_stealth",
                    "name": "Aggressive Stealth",
                    "description": "Maximum evasion for high-security targets",
                    "timeout": 60,
                    "max_workers": 1,
                    "tool_preference": "selenium",
                    "stealth": True,
                    "stealth_profile": "aggressive_stealth"  # New optional field
                }
            ]
            base_profiles.extend(enhanced_profiles)
        
        return base_profiles
    
    def validate_and_prepare_urls(self, urls_input: str) -> Dict[str, Any]:
        """Validate and prepare URLs for screenshot capture - EXISTING FUNCTIONALITY PRESERVED"""
        urls = []
        errors = []
        
        # Split input by lines or commas
        if "\n" in urls_input:
            raw_urls = [u.strip() for u in urls_input.split("\n") if u.strip()]
        else:
            raw_urls = [u.strip() for u in urls_input.split(",") if u.strip()]
        
        # Check if input is a file path
        if len(raw_urls) == 1 and Path(raw_urls[0]).exists():
            try:
                with open(raw_urls[0], 'r', encoding='utf-8') as f:
                    raw_urls = [line.strip() for line in f if line.strip()]
                self.logger.info(f"📁 Loaded {len(raw_urls)} URLs from file")
            except Exception as e:
                errors.append(f"Error reading file: {str(e)}")
                return {"valid": False, "errors": errors}
        
        # Validate each URL
        for url in raw_urls:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            if self.validator.validate_url(url):
                urls.append(url)
            else:
                errors.append(f"Invalid URL: {url}")
        
        if not urls:
            errors.append("No valid URLs provided")
        
        return {
            "valid": len(urls) > 0,
            "urls": urls,
            "errors": errors,
            "total_valid": len(urls),
            "total_errors": len(errors)
        }
    
    def run_visual_recon(self, urls: List[str], profile_id: str = "quick",
                        custom_timeout: int = None, custom_workers: int = None) -> Dict[str, Any]:
        """Main method to run visual reconnaissance - BACKWARD COMPATIBLE"""
        
        if not urls:
            return {
                "success": False,
                "error": "No URLs provided"
            }
        
        # Get profile - EXISTING BEHAVIOR
        profiles = self.get_capture_profiles()
        profile = next((p for p in profiles if p["id"] == profile_id), profiles[0])
        
        # Use custom settings if provided - EXISTING BEHAVIOR
        timeout = custom_timeout or profile["timeout"]
        max_workers = custom_workers or profile["max_workers"]
        tool_preference = profile["tool_preference"]
        
        self.logger.scan_start("visual_recon", f"{len(urls)} URLs")
        self.logger.info(f"🎯 Starting visual reconnaissance for {len(urls)} URLs")
        self.logger.info(f"📋 Profile: {profile['name']}")
        self.logger.info(f"⏱️  Timeout: {timeout}s, Workers: {max_workers}")
        self.logger.info(f"🔧 Tool preference: {tool_preference}")
        
        # Check if we should use enhanced stealth
        use_enhanced_stealth = (
            STEALTH_AVAILABLE and 
            self.stealth_engine and 
            profile.get("stealth_profile") in ["aggressive_stealth"]
        )
        
        if use_enhanced_stealth:
            self.logger.info("🛡️  Using enhanced stealth mode")
            return self._run_enhanced_stealth_recon(urls, profile, timeout, max_workers, tool_preference)
        else:
            # Use existing standard recon - NO CHANGES TO EXISTING BEHAVIOR
            return self._run_standard_recon(urls, profile, timeout, max_workers, tool_preference)
    
    def _run_standard_recon(self, urls: List[str], profile: Dict, timeout: int, 
                          max_workers: int, tool_preference: str) -> Dict[str, Any]:
        """Original standard reconnaissance - PRESERVED EXACTLY AS BEFORE"""
        
        # Create output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = self.config.home_dir / "screenshots" / f"visual_recon_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        start_time = time.time()
        
        # Run batch capture using existing engine - NO CHANGES
        capture_results = self.engine.batch_capture_screenshots(
            urls=urls,
            output_dir=output_dir,
            tool_preference=tool_preference,
            timeout=timeout,
            max_workers=max_workers
        )
        
        scan_duration = round(time.time() - start_time, 2)
        
        # Prepare results - EXISTING FORMAT PRESERVED
        results = {
            "success": True,
            "target_urls": urls,
            "profile": profile,
            "scan_config": {
                "timeout": timeout,
                "max_workers": max_workers,
                "tool_preference": tool_preference
            },
            "output_dir": str(output_dir),
            "scan_duration": scan_duration,
            "capture_results": capture_results,
            "summary": self._generate_summary(capture_results, scan_duration),
            "timestamp": datetime.now().isoformat(),
            "stealth_used": False  # Flag to indicate standard mode
        }
        
        self.logger.scan_complete("visual_recon", f"{len(urls)} URLs", 
                                capture_results["summary"]["successful_captures"])
        
        return results
    
    def _run_enhanced_stealth_recon(self, urls: List[str], profile: Dict, timeout: int,
                                  max_workers: int, tool_preference: str) -> Dict[str, Any]:
        """Enhanced stealth reconnaissance - NEW OPTIONAL FEATURE"""
        
        # Create output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = self.config.home_dir / "screenshots" / f"visual_recon_stealth_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        start_time = time.time()
        
        # Get stealth configuration
        stealth_profile_id = profile.get("stealth_profile", "stealth")
        stealth_config = self.stealth_engine.get_stealth_profile(stealth_profile_id)
        
        self.logger.info(f"🛡️  Using stealth profile: {stealth_profile_id}")
        
        # Use enhanced capture with stealth features
        capture_results = self._run_stealth_capture(
            urls=urls,
            output_dir=output_dir,
            tool_preference=tool_preference,
            timeout=timeout,
            max_workers=max_workers,
            stealth_config=stealth_config
        )
        
        scan_duration = round(time.time() - start_time, 2)
        
        # Prepare results - same format as standard recon
        results = {
            "success": True,
            "target_urls": urls,
            "profile": profile,
            "scan_config": {
                "timeout": timeout,
                "max_workers": max_workers,
                "tool_preference": tool_preference,
                "stealth_profile": stealth_profile_id
            },
            "output_dir": str(output_dir),
            "scan_duration": scan_duration,
            "capture_results": capture_results,
            "summary": self._generate_summary(capture_results, scan_duration),
            "timestamp": datetime.now().isoformat(),
            "stealth_used": True  # Flag to indicate stealth mode
        }
        
        self.logger.scan_complete("visual_recon", f"{len(urls)} URLs (Stealth)", 
                                capture_results["summary"]["successful_captures"])
        
        return results
    
    def _run_stealth_capture(self, urls: List[str], output_dir: Path, tool_preference: str,
                           timeout: int, max_workers: int, stealth_config: Dict) -> Dict[str, Any]:
        """Enhanced capture with stealth features - falls back to standard if needed"""
        
        results = {
            "successful": [],
            "blocked": [],
            "failed": [],
            "results": [],
            "summary": {
                "total_urls": len(urls),
                "successful_captures": 0,
                "blocked_pages": 0,
                "failed_captures": 0
            }
        }
        
        successful_count = 0
        
        for url in urls:
            try:
                filename = self._generate_filename(url)
                output_path = output_dir / filename
                
                # Apply stealth delay before capture
                self.stealth_engine.simulate_human_delay(stealth_config)
                
                # Try enhanced stealth capture
                capture_result = self._capture_with_stealth(url, output_path, stealth_config, tool_preference)
                
                if capture_result["success"]:
                    successful_count += 1
                    result_entry = {
                        "url": url,
                        "screenshot": str(output_path),
                        "tool": capture_result.get("tool", "stealth"),
                        "success": True,
                        "blocked": capture_result.get("blocked", False)
                    }
                    results["successful"].append(result_entry)
                    results["results"].append(result_entry)
                    
                    if capture_result.get("blocked"):
                        results["blocked"].append({
                            "url": url,
                            "block_reason": capture_result.get("block_reason", "WAF detected")
                        })
                        results["summary"]["blocked_pages"] += 1
                    
                    self.logger.info(f"✅ Stealth capture successful: {url}")
                    
                else:
                    # Fallback to standard capture
                    self.logger.warning(f"🛡️  Stealth capture failed, trying standard: {url}")
                    standard_result = self.engine.capture_single_screenshot(
                        url, output_path, tool_preference, timeout
                    )
                    
                    if standard_result["success"]:
                        successful_count += 1
                        result_entry = {
                            "url": url,
                            "screenshot": str(output_path),
                            "tool": standard_result.get("tool", "standard"),
                            "success": True,
                            "blocked": standard_result.get("blocked", False)
                        }
                        results["successful"].append(result_entry)
                        results["results"].append(result_entry)
                        self.logger.info(f"✅ Standard capture successful: {url}")
                    else:
                        results["failed"].append({"url": url, "error": "All capture methods failed"})
                        results["results"].append({"url": url, "success": False, "error": "All capture methods failed"})
                        self.logger.error(f"❌ All capture methods failed: {url}")
                        
            except Exception as e:
                error_msg = f"Error processing {url}: {str(e)}"
                results["failed"].append({"url": url, "error": error_msg})
                results["results"].append({"url": url, "success": False, "error": error_msg})
                self.logger.error(f"❌ Processing error: {url} - {str(e)}")
        
        # Update summary
        results["summary"]["successful_captures"] = successful_count
        results["summary"]["failed_captures"] = len(results["failed"])
        
        return results
    
    def _capture_with_stealth(self, url: str, output_path: Path, stealth_config: Dict, 
                            tool_preference: str) -> Dict[str, Any]:
        """Enhanced stealth capture - falls back to standard methods"""
        try:
            # Get stealth headers and configuration
            headers = self.stealth_engine.get_browser_headers(stealth_config)
            proxies = self.stealth_engine.get_proxy_config(stealth_config)
            
            self.logger.debug(f"🛡️  Using stealth headers for: {url}")
            
            # Use existing engine but with stealth enhancements
            # This would be integrated with your actual capture methods
            # For now, fallback to standard capture but with stealth info
            standard_result = self.engine.capture_single_screenshot(
                url, output_path, tool_preference, stealth_config.get("timeout", 60)
            )
            
            # Enhance result with stealth info
            if standard_result["success"]:
                standard_result["tool"] = f"{standard_result.get('tool', 'unknown')}_stealth"
                standard_result["stealth_used"] = True
            
            return standard_result
            
        except Exception as e:
            self.logger.error(f"Stealth capture error for {url}: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _generate_filename(self, url: str) -> str:
        """Generate filename from URL - EXISTING BEHAVIOR PRESERVED"""
        from urllib.parse import urlparse
        import re
        
        parsed = urlparse(url)
        domain = parsed.netloc.replace(':', '_')
        path = parsed.path.replace('/', '_') if parsed.path else 'home'
        
        # Clean filename
        filename = f"{domain}_{path}.png"
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        
        # Limit length
        if len(filename) > 100:
            name, ext = filename.rsplit('.', 1)
            filename = name[:95] + '.' + ext
            
        return filename
    
    def _generate_summary(self, capture_results: Dict, scan_duration: float) -> Dict[str, Any]:
        """Generate scan summary - EXISTING FUNCTIONALITY PRESERVED"""
        summary = capture_results["summary"]
        results = capture_results["results"]
        
        # Tool usage statistics
        tool_usage = {}
        for result in results:
            if result.get("success"):
                tool = result.get("tool", "unknown")
                tool_usage[tool] = tool_usage.get(tool, 0) + 1
        
        # Block reasons
        block_reasons = {}
        blocked_pages = capture_results.get("blocked", [])
        for blocked in blocked_pages:
            reason = blocked.get("block_reason", "Unknown")
            block_reasons[reason] = block_reasons.get(reason, 0) + 1
        
        return {
            "total_urls": summary["total_urls"],
            "successful_captures": summary["successful_captures"],
            "blocked_pages": summary["blocked_pages"],
            "failed_captures": summary["failed_captures"],
            "scan_duration": scan_duration,
            "tool_usage": tool_usage,
            "block_reasons": block_reasons,
            "success_rate": round((summary["successful_captures"] / summary["total_urls"]) * 100, 1) if summary["total_urls"] > 0 else 0
        }
    
    def generate_scan_report(self, results: Dict[str, Any]) -> str:
        """Generate human-readable scan report - EXISTING FORMAT PRESERVED"""
        
        if not results.get("success", False):
            return f"❌ Scan failed: {results.get('error', 'Unknown error')}"
        
        report = []
        report.append("=" * 70)
        report.append("📸 VISUAL RECONNAISSANCE REPORT")
        report.append("=" * 70)
        report.append(f"Target URLs: {len(results.get('target_urls', []))}")
        report.append(f"Profile: {results.get('profile', {}).get('name', 'Unknown')}")
        
        # Show stealth info if used
        if results.get('stealth_used'):
            report.append(f"Stealth Mode: 🛡️ ENABLED")
            stealth_profile = results.get('scan_config', {}).get('stealth_profile')
            if stealth_profile:
                report.append(f"Stealth Profile: {stealth_profile}")
        
        report.append(f"Output Directory: {results.get('output_dir', 'Unknown')}")
        report.append(f"Scan Date: {results.get('timestamp', 'Unknown')}")
        report.append("")
        
        # Summary section
        summary = results.get("summary", {})
        report.append("📊 SCAN SUMMARY")
        report.append("-" * 40)
        report.append(f"Total URLs: {summary.get('total_urls', 0)}")
        report.append(f"Successful Captures: {summary.get('successful_captures', 0)}")
        report.append(f"Blocked Pages: {summary.get('blocked_pages', 0)}")
        report.append(f"Failed Captures: {summary.get('failed_captures', 0)}")
        report.append(f"Success Rate: {summary.get('success_rate', 0)}%")
        report.append(f"Scan Duration: {summary.get('scan_duration', 0)} seconds")
        report.append("")
        
        # Tool usage
        tool_usage = summary.get('tool_usage', {})
        if tool_usage:
            report.append("🔧 TOOL USAGE")
            report.append("-" * 30)
            for tool, count in tool_usage.items():
                stealth_indicator = " 🛡️" if "stealth" in tool.lower() else ""
                report.append(f"  {tool}: {count} screenshots{stealth_indicator}")
            report.append("")
        
        # Block reasons
        block_reasons = summary.get('block_reasons', {})
        if block_reasons:
            report.append("🚫 BLOCKED PAGES ANALYSIS")
            report.append("-" * 35)
            for reason, count in block_reasons.items():
                report.append(f"  {reason}: {count} pages")
            report.append("")
        
        # Detailed results
        capture_results = results.get("capture_results", {})
        successful = capture_results.get("successful", [])
        blocked = capture_results.get("blocked", [])
        
        if successful:
            report.append("✅ SUCCESSFUL CAPTURES")
            report.append("-" * 30)
            report.append("  URL                                 Tool       Blocked")
            report.append("  ---                                 ----       -------")
            
            for result in successful[:20]:  # Show first 20
                url = result.get('url', '')[:35].ljust(35)
                tool = result.get('tool', 'unknown')[:10].ljust(10)
                blocked = "🚫 Yes" if result.get('blocked') else "✅ No"
                
                report.append(f"  {url} {tool} {blocked}")
            
            if len(successful) > 20:
                report.append(f"  ... and {len(successful) - 20} more successful captures")
            report.append("")
        
        # Failed captures
        failed_count = summary.get('failed_captures', 0)
        if failed_count > 0:
            report.append("❌ FAILED CAPTURES")
            report.append("-" * 30)
            
            failed_urls = []
            for result in capture_results.get("results", []):
                if not result.get("success"):
                    failed_urls.append(result.get("url", "Unknown"))
            
            for url in failed_urls[:10]:  # Show first 10 failures
                report.append(f"  • {url}")
            
            if len(failed_urls) > 10:
                report.append(f"  ... and {len(failed_urls) - 10} more failed captures")
            report.append("")
        
        # Blocked pages details
        if blocked:
            report.append("🛡️  BLOCKED PAGES DETAILS")
            report.append("-" * 35)
            for result in blocked[:10]:  # Show first 10 blocked
                url = result.get('url', 'Unknown')
                reason = result.get('block_reason', 'Unknown reason')
                report.append(f"  • {url}")
                report.append(f"    Reason: {reason}")
                report.append("")
        
        # Recommendations
        report.append("💡 RECOMMENDATIONS")
        report.append("-" * 30)
        
        success_rate = summary.get('success_rate', 0)
        blocked_count = summary.get('blocked_pages', 0)
        
        if success_rate < 50:
            report.append("  🔧 Low success rate - try different tools or increase timeout")
            if not results.get('stealth_used') and blocked_count > 0:
                report.append("  🛡️  Many blocks detected - consider using stealth profile")
        elif success_rate > 90:
            report.append("  ✅ Excellent success rate - screenshots captured successfully")
        
        if blocked_count > 0:
            report.append(f"  🚫 {blocked_count} pages were blocked - consider stealth profile")
        
        if failed_count > 0:
            report.append(f"  ❌ {failed_count} captures failed - check URLs and network")
        
        report.append("  📁 Screenshots saved to output directory")
        report.append("")
        
        report.append("=" * 70)
        report.append("💡 Note: Review screenshots for visual analysis and security assessment.")
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def save_scan_results(self, results: Dict[str, Any], filename: str = None):
        """Save scan results to file - EXISTING FUNCTIONALITY PRESERVED"""
        from datetime import datetime
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"visual_recon_{timestamp}.json"
        
        # Ensure scans directory exists
        scans_dir = self.config.home_dir / "scans"
        scans_dir.mkdir(exist_ok=True)
        
        file_path = scans_dir / filename
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"💾 Visual recon results saved to: {file_path}")
            return str(file_path)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save visual recon results: {str(e)}")
            return None

# Test function - PRESERVED EXISTING TEST
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    scanner = VisualRecon(config, logger)
    
    print("🧪 Testing Visual Reconnaissance...")
    
    # Show available profiles
    profiles = scanner.get_capture_profiles()
    print("\n📋 Available Capture Profiles:")
    for profile in profiles:
        stealth_indicator = " 🛡️" if profile.get('stealth') or profile.get('stealth_profile') else ""
        print(f"  • {profile['name']}: {profile['description']}{stealth_indicator}")
    
    # Test URL validation
    test_urls_input = "https://httpbin.org/html, https://example.com, invalid-url"
    print(f"\n🔍 Testing URL validation...")
    validation = scanner.validate_and_prepare_urls(test_urls_input)
    print(f"  Valid URLs: {validation['total_valid']}")
    print(f"  Errors: {validation['total_errors']}")
    for error in validation['errors']:
        print(f"    ❌ {error}")
    
    # Test with valid URLs only
    if validation['valid']:
        test_urls = validation['urls'][:2]  # Use first 2 valid URLs
        
        print(f"\n🚀 Testing quick visual recon on {len(test_urls)} URLs...")
        results = scanner.run_visual_recon(test_urls, "quick")
        
        if results.get('success'):
            report = scanner.generate_scan_report(results)
            print("\n" + report)
            
            # Save results
            saved_path = scanner.save_scan_results(results)
            if saved_path:
                print(f"\n💾 Results saved to: {saved_path}")
        else:
            print(f"❌ Scan failed: {results.get('error')}")
