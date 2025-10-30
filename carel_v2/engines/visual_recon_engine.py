# engines/visual_recon_engine.py
import os
import time
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VisualReconEngine:
    def __init__(self, config_manager, logger):
        self.config = config_manager
        self.logger = logger
        self.screenshot_tools = []
        self._detect_tools()
    
    def _detect_tools(self):
        """Detect available screenshot tools"""
        self.screenshot_tools = []
        
        # Check cutycapt
        if self._check_tool_installed("cutycapt"):
            self.screenshot_tools.append({
                "id": "cutycapt",
                "name": "CutyCapt",
                "description": "Command-line webpage capture",
                "priority": 1
            })
        
        # Check Aquatone
        if self._check_tool_installed("aquatone"):
            self.screenshot_tools.append({
                "id": "aquatone", 
                "name": "Aquatone",
                "description": "Advanced visual reconnaissance tool",
                "priority": 2
            })
        
        # Check Selenium
        if self._check_selenium_available():
            self.screenshot_tools.append({
                "id": "selenium",
                "name": "Selenium Chrome",
                "description": "Headless browser automation",
                "priority": 3
            })
        
        self.logger.info(f"🔧 Detected {len(self.screenshot_tools)} screenshot tools: {[t['name'] for t in self.screenshot_tools]}")
    
    def _check_tool_installed(self, tool: str) -> bool:
        """Check if a tool is installed"""
        try:
            result = subprocess.run(
                ["which", tool], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _check_selenium_available(self) -> bool:
        """Check if Selenium is available"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            return True
        except ImportError:
            return False
    
    def get_available_tools(self) -> List[Dict[str, Any]]:
        """Return available screenshot tools"""
        return sorted(self.screenshot_tools, key=lambda x: x["priority"])
    
    def capture_with_cutycapt(self, url: str, output_file: Path, timeout: int = 30) -> Dict[str, Any]:
        """Capture screenshot using cutycapt"""
        try:
            # Ensure output directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            cmd = [
                "cutycapt",
                f"--url={url}",
                f"--out={output_file}",
                "--delay=3000",
                f"--max-wait={timeout * 1000}",
                "--insecure",
                "--print-backgrounds=1",
                "--javascript=on"
            ]
            
            self.logger.debug(f"Running cutycapt: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10
            )
            
            # Check if file was created and has content
            success = False
            if output_file.exists():
                file_size = output_file.stat().st_size
                success = file_size > 1000  # Reasonable minimum size for a screenshot
                self.logger.debug(f"cutycapt output file size: {file_size} bytes")
            
            result = {
                "success": success,
                "output_file": str(output_file),
                "stdout": process.stdout,
                "stderr": process.stderr,
                "return_code": process.returncode
            }
            
            if success:
                self.logger.info(f"✅ cutycapt captured {url} -> {output_file}")
            else:
                self.logger.warning(f"❌ cutycapt failed for {url}: returncode={process.returncode}, stderr={process.stderr}")
                if output_file.exists():
                    output_file.unlink()  # Clean up empty file
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"cutycapt timeout for {url}")
            return {"error": "Timeout", "success": False}
        except Exception as e:
            self.logger.error(f"cutycapt error for {url}: {str(e)}")
            return {"error": str(e), "success": False}
    
    def capture_with_selenium(self, url: str, output_file: Path, timeout: int = 30) -> Dict[str, Any]:
        """Capture screenshot using Selenium"""
        if not self._check_selenium_available():
            return {"error": "Selenium not available", "success": False}
        
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.common.by import By
            from selenium.common.exceptions import TimeoutException
            
            # Ensure output directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Setup Chrome options
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--disable-gpu")
            
            driver = None
            try:
                # Try to use Chrome
                driver = webdriver.Chrome(options=options)
                driver.set_page_load_timeout(timeout)
                
                self.logger.debug(f"Selenium loading: {url}")
                driver.get(url)
                
                # Wait for page to load
                WebDriverWait(driver, timeout).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
                
                # Additional wait for dynamic content
                time.sleep(2)
                
                # Take screenshot
                driver.save_screenshot(str(output_file))
                
                # Verify screenshot was created
                success = output_file.exists() and output_file.stat().st_size > 1000
                
                result = {
                    "success": success,
                    "output_file": str(output_file)
                }
                
                if success:
                    self.logger.info(f"✅ Selenium captured {url} -> {output_file}")
                else:
                    self.logger.warning(f"❌ Selenium produced empty file for {url}")
                
                return result
                
            except TimeoutException:
                self.logger.warning(f"Selenium timeout for {url}")
                return {"error": "Page load timeout", "success": False}
            except Exception as e:
                self.logger.warning(f"Selenium error for {url}: {str(e)}")
                return {"error": str(e), "success": False}
            finally:
                if driver:
                    try:
                        driver.quit()
                    except:
                        pass
                    
        except Exception as e:
            self.logger.error(f"Selenium setup error: {str(e)}")
            return {"error": f"Setup error: {str(e)}", "success": False}
    
    def run_aquatone_scan(self, urls: List[str], output_dir: Path, timeout: int = 300) -> Dict[str, Any]:
        """Run Aquatone scan on multiple URLs"""
        if not self._check_tool_installed("aquatone"):
            return {"error": "Aquatone not installed", "success": False}
        
        self.logger.info(f"🚀 Starting Aquatone scan for {len(urls)} URLs")
        
        # Create input file for Aquatone
        input_file = output_dir / "aquatone_input.txt"
        with open(input_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        try:
            cmd = [
                "aquatone",
                "-ports", "large",
                "-scan-timeout", str(timeout * 1000),
                "-screenshot-timeout", "30000",
                "-out", str(output_dir),
                "-threads", "3"
            ]
            
            self.logger.debug(f"Aquatone command: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                input="\n".join(urls),
                capture_output=True,
                text=True,
                timeout=timeout + 30
            )
            
            results = {
                "success": process.returncode == 0,
                "output_dir": str(output_dir),
                "stdout": process.stdout,
                "stderr": process.stderr,
                "return_code": process.returncode
            }
            
            # Check for results regardless of return code (Aquatone sometimes returns non-zero but still works)
            report_file = output_dir / "aquatone_report.html"
            screenshot_dir = output_dir / "screenshots"
            
            if report_file.exists():
                results["report_file"] = str(report_file)
                self.logger.info(f"✅ Aquatone report generated: {report_file}")
            
            if screenshot_dir.exists():
                screenshots = list(screenshot_dir.glob("*.png"))
                results["screenshots"] = [str(s) for s in screenshots]
                results["screenshot_count"] = len(screenshots)
                self.logger.info(f"📸 Aquatone captured {len(screenshots)} screenshots")
            
            if not results.get("screenshots"):
                self.logger.warning("Aquatone produced no screenshots")
            
            return results
            
        except subprocess.TimeoutExpired:
            self.logger.error("Aquatone scan timed out")
            return {"error": "Aquatone scan timed out", "success": False}
        except Exception as e:
            self.logger.error(f"Aquatone error: {str(e)}")
            return {"error": f"Aquatone error: {str(e)}", "success": False}
    
    def capture_screenshot(self, url: str, output_dir: Path, 
                          tool_preference: str = "auto",
                          timeout: int = 30) -> Dict[str, Any]:
        """Capture screenshot using preferred tool"""
        # Create safe filename from URL
        safe_name = self._url_to_safe_filename(url)
        output_file = output_dir / f"{safe_name}.png"
        
        # If file already exists, add timestamp
        if output_file.exists():
            timestamp = int(time.time())
            output_file = output_dir / f"{safe_name}_{timestamp}.png"
        
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        tools_priority = ["cutycapt", "selenium"]
        
        # Reorder based on preference
        if tool_preference != "auto" and tool_preference in tools_priority:
            tools_priority.remove(tool_preference)
            tools_priority.insert(0, tool_preference)
        
        # Try each tool in order
        for tool in tools_priority:
            if tool == "cutycapt" and self._check_tool_installed("cutycapt"):
                result = self.capture_with_cutycapt(url, output_file, timeout)
                if result.get("success"):
                    result["tool"] = "cutycapt"
                    return result
            elif tool == "selenium" and self._check_selenium_available():
                result = self.capture_with_selenium(url, output_file, timeout)
                if result.get("success"):
                    result["tool"] = "selenium"
                    return result
        
        return {"error": "No screenshot tool available or all failed", "success": False}
    
    def _url_to_safe_filename(self, url: str) -> str:
        """Convert URL to safe filename"""
        import re
        # Remove protocol
        clean_url = re.sub(r'^https?://', '', url)
        # Replace special characters
        clean_url = re.sub(r'[^a-zA-Z0-9.-]', '_', clean_url)
        # Limit length
        if len(clean_url) > 100:
            clean_url = clean_url[:100]
        return clean_url
    
    def batch_capture_screenshots(self, urls: List[str], output_dir: Path,
                                tool_preference: str = "auto",
                                timeout: int = 30,
                                max_workers: int = 3) -> Dict[str, Any]:
        """Capture screenshots for multiple URLs"""
        self.logger.info(f"📸 Starting batch screenshot capture for {len(urls)} URLs")
        
        output_dir.mkdir(parents=True, exist_ok=True)
        results = []
        
        def process_url(url):
            self.logger.debug(f"Capturing screenshot for: {url}")
            result = self.capture_screenshot(url, output_dir, tool_preference, timeout)
            result["url"] = url
            return result
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(process_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                result = future.result()
                results.append(result)
                
                if result.get("success"):
                    self.logger.info(f"✅ {result['url']} - {result.get('tool', 'unknown')}")
                else:
                    self.logger.warning(f"❌ {result['url']} - {result.get('error', 'Unknown error')}")
        
        # Generate summary
        successful = [r for r in results if r.get("success")]
        
        summary = {
            "total_urls": len(urls),
            "successful_captures": len(successful),
            "failed_captures": len(urls) - len(successful),
            "output_dir": str(output_dir)
        }
        
        self.logger.info(f"📊 Batch capture complete: {len(successful)}/{len(urls)} successful")
        
        return {
            "summary": summary,
            "results": results,
            "successful": successful
        }

# Test function
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    config = ConfigManager()
    logger = CarelLogger(config)
    
    engine = VisualReconEngine(config, logger)
    
    print("🧪 Testing Fixed Visual Recon Engine...")
    
    # Test tool detection
    tools = engine.get_available_tools()
    print(f"\n📸 Available Tools: {len(tools)}")
    for tool in tools:
        print(f"  • {tool['name']}: {tool['description']}")
    
    # Test single URL capture
    test_urls = ["https://httpbin.org/html", "https://example.com"]
    
    print(f"\n🔍 Testing single URL capture...")
    for url in test_urls[:1]:
        result = engine.capture_screenshot(url, Path("/tmp/test_screenshots"), timeout=20)
        print(f"  {url}: {result.get('success', False)} - {result.get('tool', 'N/A')}")
        if result.get("success"):
            print(f"    Saved to: {result.get('output_file')}")
        else:
            print(f"    Error: {result.get('error', 'Unknown')}")
    
    # Test batch capture
    print(f"\n🚀 Testing batch capture with {len(test_urls)} URLs...")
    batch_result = engine.batch_capture_screenshots(
        test_urls, 
        Path("/tmp/test_batch_screenshots"),
        timeout=20,
        max_workers=2
    )
    
    summary = batch_result["summary"]
    print(f"  📊 Summary: {summary['successful_captures']}/{summary['total_urls']} successful")
