#!/usr/bin/env python3
"""
Quick test for fixed visual reconnaissance
"""

from core.config_manager import ConfigManager
from core.logger import CarelLogger
from engines.visual_recon_engine import VisualReconEngine
from pathlib import Path

def main():
    print("🧪 QUICK VISUAL RECON TEST")
    print("=" * 40)
    
    config = ConfigManager()
    logger = CarelLogger(config)
    engine = VisualReconEngine(config, logger)
    
    # Test URLs
    test_urls = [
        "https://httpbin.org/html",
        "https://example.com", 
        "https://httpbin.org/json"
    ]
    
    print(f"Testing with {len(test_urls)} URLs...")
    
    # Test batch capture
    results = engine.batch_capture_screenshots(
        test_urls,
        Path("/tmp/visual_recon_test"),
        timeout=25,
        max_workers=2
    )
    
    print("\n📊 RESULTS:")
    print("-" * 20)
    for result in results["results"]:
        status = "✅ SUCCESS" if result.get("success") else "❌ FAILED"
        tool = result.get("tool", "N/A")
        print(f"{status} {result['url']} - {tool}")
        
        if result.get("success"):
            file_path = result.get("output_file", "N/A")
            file_size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
            print(f"   📁 {file_path} ({file_size} bytes)")
        else:
            print(f"   💥 Error: {result.get('error', 'Unknown')}")
    
    summary = results["summary"]
    print(f"\n🎯 SUMMARY: {summary['successful_captures']}/{summary['total_urls']} successful")
    print(f"📁 Output directory: {summary['output_dir']}")

if __name__ == "__main__":
    main()
