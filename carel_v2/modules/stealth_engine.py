#!/usr/bin/env python3
"""
Stealth Engine for CAREL v2.0
Advanced anti-detection and evasion techniques
"""

import random
import time
import requests
import socket
from pathlib import Path
from typing import Dict, Optional, List

class StealthEngine:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.current_user_agent = None
        
    def get_stealth_profile(self, profile_id: str) -> Dict:
        """Get stealth profile configuration"""
        profiles = self.config.get("stealth_profiles", {})
        return profiles.get(profile_id, profiles.get("standard", {}))
    
    def rotate_user_agent(self) -> str:
        """Rotate to a random user agent"""
        user_agents = self.config.get("anti_detection.user_agents", [])
        if not user_agents:
            # Fallback to stealth user agents
            user_agents = self.config.get("stealth.user_agents", [])
        
        if user_agents:
            self.current_user_agent = random.choice(user_agents)
        else:
            # Final fallback - realistic user agents
            self.current_user_agent = random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ])
        
        self.logger.debug(f"🛡️ Rotated User-Agent: {self.current_user_agent}")
        return self.current_user_agent
    
    def get_random_delay(self, delay_range: str) -> float:
        """Get random delay from range string like '10-30'"""
        try:
            if isinstance(delay_range, str) and '-' in delay_range:
                min_delay, max_delay = map(float, delay_range.split('-'))
                return random.uniform(min_delay, max_delay)
            else:
                return random.uniform(3, 10)  # Default fallback
        except Exception as e:
            self.logger.warning(f"Invalid delay range '{delay_range}', using default: {e}")
            return random.uniform(3, 10)
    
    def is_tor_available(self) -> bool:
        """Check if Tor proxy is available"""
        try:
            tor_proxy = self.config.get("anti_detection.tor_proxy", "socks5://127.0.0.1:9050")
            proxies = {
                'http': tor_proxy,
                'https': tor_proxy
            }
            # Test Tor connection with shorter timeout
            response = requests.get('http://check.torproject.org', 
                                  proxies=proxies, timeout=10)
            return 'Congratulations' in response.text
        except Exception as e:
            self.logger.debug(f"Tor not available: {e}")
            return False
    
    def rotate_tor_circuit(self) -> bool:
        """Rotate Tor circuit for new IP"""
        try:
            # Send NEWNYM signal to Tor control port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', 9051))
                s.send(b'AUTHENTICATE ""\r\n')
                response = s.recv(1024)
                if b'250' in response:
                    s.send(b'SIGNAL NEWNYM\r\n')
                    response = s.recv(1024)
                    if b'250' in response:
                        self.logger.info("🛡️ Tor circuit rotated successfully")
                        return True
        except Exception as e:
            self.logger.warning(f"Tor circuit rotation failed: {e}")
        
        return False
    
    def get_browser_headers(self, profile: Dict) -> Dict:
        """Generate realistic browser headers"""
        # Rotate user agent if enabled
        if profile.get('user_agent_rotation', True):
            user_agent = self.rotate_user_agent()
        else:
            user_agent = self.config.get("anti_detection.user_agents", [""])[0] or \
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if profile.get('javascript_rendering', True):
            headers.update({
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Cache-Control': 'max-age=0'
            })
        
        return headers
    
    def get_proxy_config(self, profile: Dict) -> Optional[Dict]:
        """Get proxy configuration based on profile"""
        if profile.get('tor_rotation', False) and self.is_tor_available():
            tor_proxy = self.config.get("anti_detection.tor_proxy", "socks5://127.0.0.1:9050")
            self.logger.debug("🛡️ Using Tor proxy for requests")
            return {
                'http': tor_proxy,
                'https': tor_proxy
            }
        return None
    
    def simulate_human_delay(self, profile: Dict):
        """Simulate human-like delays"""
        if delay_range := profile.get('delay'):
            delay = self.get_random_delay(delay_range)
            self.logger.debug(f"🛡️ Human delay: {delay:.2f}s")
            time.sleep(delay)
        else:
            # Small random delay even if not specified
            time.sleep(random.uniform(1, 3))
    
    def get_stealth_summary(self, profile_id: str) -> str:
        """Get human-readable stealth summary"""
        profile = self.get_stealth_profile(profile_id)
        summary = [
            f"Profile: {profile_id.upper()}",
            f"Delay: {profile.get('delay', 'N/A')}",
            f"Workers: {profile.get('workers', 'N/A')}",
            f"User-Agent Rotation: {profile.get('user_agent_rotation', False)}",
            f"Tor Rotation: {profile.get('tor_rotation', False)}",
            f"JavaScript Rendering: {profile.get('javascript_rendering', False)}"
        ]
        return "\n".join(f"  • {line}" for line in summary)
    
    def enhance_request_kwargs(self, profile: Dict, **kwargs) -> Dict:
        """Enhance request arguments with stealth features"""
        stealth_kwargs = kwargs.copy()
        
        # Add headers if not provided
        if 'headers' not in stealth_kwargs:
            stealth_kwargs['headers'] = self.get_browser_headers(profile)
        
        # Add proxies if Tor is enabled
        if profile.get('tor_rotation', False):
            proxies = self.get_proxy_config(profile)
            if proxies and 'proxies' not in stealth_kwargs:
                stealth_kwargs['proxies'] = proxies
        
        # Add timeout if not provided
        if 'timeout' not in stealth_kwargs:
            stealth_kwargs['timeout'] = profile.get('timeout', 30)
        
        return stealth_kwargs

# Test the stealth engine
if __name__ == "__main__":
    from core.config_manager import ConfigManager
    from core.logger import CarelLogger
    
    print("🧪 Testing Stealth Engine...")
    
    config = ConfigManager()
    logger = CarelLogger(config)
    stealth = StealthEngine(config, logger)
    
    # Test profiles
    profiles = ["quick", "standard", "stealth", "aggressive_stealth"]
    
    for profile_id in profiles:
        print(f"\n📋 Testing {profile_id} profile:")
        profile = stealth.get_stealth_profile(profile_id)
        print(f"  Delay: {profile.get('delay')}")
        print(f"  User-Agent Rotation: {profile.get('user_agent_rotation')}")
        print(f"  Tor Rotation: {profile.get('tor_rotation')}")
    
    # Test user agent rotation
    print(f"\n🔄 User-Agent Test: {stealth.rotate_user_agent()}")
    
    # Test Tor availability
    tor_available = stealth.is_tor_available()
    print(f"🔌 Tor Available: {tor_available}")
    
    print("✅ Stealth Engine test completed!")
