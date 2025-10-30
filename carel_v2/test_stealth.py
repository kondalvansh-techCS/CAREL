#!/usr/bin/env python3
"""
Test stealth functionality
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.config_manager import ConfigManager
from core.logger import CarelLogger

def test_stealth_engine():
    """Test if stealth engine works"""
    print("🧪 Testing Stealth Engine...")
    
    try:
        from modules.stealth_engine import StealthEngine
        
        config = ConfigManager()
        logger = CarelLogger(config)
        stealth = StealthEngine(config, logger)
        
        print("✅ StealthEngine imported successfully!")
        
        # Test profiles
        profiles = config.get("stealth_profiles", {})
        print(f"📋 Found {len(profiles)} stealth profiles:")
        
        for profile_id, profile in profiles.items():
            print(f"  • {profile_id}: {profile.get('delay', 'N/A')} delay")
        
        return True
        
    except ImportError as e:
        print(f"❌ StealthEngine import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ StealthEngine test failed: {e}")
        return False

def test_visual_recon_stealth():
    """Test visual recon with stealth"""
    print("\n🧪 Testing Visual Recon with Stealth...")
    
    try:
        from modules.visual_recon import VisualRecon
        
        config = ConfigManager()
        logger = CarelLogger(config)
        scanner = VisualRecon(config, logger)
        
        # Check if stealth is available
        if hasattr(scanner, 'stealth_engine') and scanner.stealth_engine:
            print("✅ Stealth engine is available in VisualRecon!")
            
            # Test profiles
            profiles = scanner.get_capture_profiles()
            stealth_profiles = [p for p in profiles if p.get('stealth') or p.get('stealth_profile')]
            print(f"📋 Found {len(stealth_profiles)} stealth capture profiles")
            
            for profile in stealth_profiles:
                print(f"  • {profile['name']}: {profile['description']}")
                
            return True
        else:
            print("❌ Stealth engine not available in VisualRecon")
            return False
            
    except Exception as e:
        print(f"❌ Visual recon stealth test failed: {e}")
        return False

if __name__ == "__main__":
    print("🛡️ CAREL v2.0 Stealth System Test")
    print("=" * 50)
    
    stealth_ok = test_stealth_engine()
    visual_ok = test_visual_recon_stealth()
    
    if stealth_ok and visual_ok:
        print("\n🎉 ALL STEALTH TESTS PASSED! Your stealth system is ready.")
        print("💡 You can now use stealth profiles in visual reconnaissance.")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")
