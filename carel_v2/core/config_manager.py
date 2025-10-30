# core/config_manager.py
import json
import os
from pathlib import Path
from typing import Dict, Any

class ConfigManager:
    def __init__(self):
        self.home_dir = Path.home() / ".carel_v2"
        self.config_path = self.home_dir / "config.json"
        self.default_config = {
            "nvd_api_key": "3cd88818-06a2-470e-bd6e-f2453998887b",
            "threads": 20,
            "timeouts": {
                "nmap": 1800,
                "feroxbuster": 300,
                "dns": 5,
                "http": 30,
                "screenshot": 60
            },
            "tools": {
                "nmap_args": "-sV --open",
                "feroxbuster_path": "feroxbuster",
                "sublist3r_path": ""
            },
            "stealth": {
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                ],
                "delay_between_requests": 1,
                "max_retries": 3
            },
            "wordlists": {
                "subdomains": "wordlists/subdomains.txt",
                "directories": "wordlists/directories.txt"
            },
             "stealth_profiles": {
            "quick": {
                "delay": "1-3",
                "workers": 5,
                "timeout": 30,
                "user_agent_rotation": False,
                "tor_rotation": False,
                "javascript_rendering": False
            },
            "standard": {
                "delay": "3-10", 
                "workers": 3,
                "timeout": 45,
                "user_agent_rotation": True,
                "tor_rotation": False,
                "javascript_rendering": True
            },
            "stealth": {
                "delay": "10-30",
                "workers": 2,
                "timeout": 60,
                "user_agent_rotation": True,
                "tor_rotation": True,
                "javascript_rendering": True
            }
        },
        
        # NEW: Add anti-detection settings (optional)
        "anti_detection": {
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ],
            "screen_resolutions": ["1920x1080", "1366x768"],
            "tor_proxy": "socks5://127.0.0.1:9050"
        }
        }
        self._ensure_directories()
        self.config = self._load_config()
    
    def _ensure_directories(self):
        """Create necessary directories"""
        directories = [
            self.home_dir,
            self.home_dir / "scans",
            self.home_dir / "screenshots", 
            self.home_dir / "wordlists",
            self.home_dir / "logs",
            self.home_dir / "reports"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load config from file or create default"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                
                # Merge with default config (deep merge)
                return self._deep_merge(self.default_config, user_config)
            except Exception as e:
                print(f"⚠️  Config error: {e}. Using defaults.")
                return self.default_config.copy()
        else:
            self._save_config(self.default_config)
            return self.default_config.copy()
    
    def _deep_merge(self, default: Dict, user: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = default.copy()
        
        for key, value in user.items():
            if (key in result and isinstance(result[key], dict) 
                and isinstance(value, dict)):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
                
        return result
    
    def _save_config(self, config: Dict):
        """Save config to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save config: {e}")
    
    def get(self, key: str, default=None):
        """Get config value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Set config value using dot notation"""
        keys = key.split('.')
        config_ref = self.config
        
        # Navigate to the parent of the final key
        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]
        
        # Set the final key
        config_ref[keys[-1]] = value
        self._save_config(self.config)
    
    def show_config(self):
        """Display current configuration"""
        print("🔧 Current Configuration:")
        print(json.dumps(self.config, indent=2))

# Test the config manager
if __name__ == "__main__":
    config = ConfigManager()
    config.show_config()
