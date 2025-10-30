#!/usr/bin/env python3
"""
Interactive test for CAREL v2.0 foundation
"""

from core.config_manager import ConfigManager
from core.logger import CarelLogger
from core.utils import ValidationUtils, NetworkUtils

def interactive_test():
    print("🔍 CAREL v2.0 - Interactive Foundation Test\n")
    
    # Initialize modules
    config = ConfigManager()
    logger = CarelLogger(config)
    
    while True:
        print("\n" + "="*50)
        print("Choose an option:")
        print("1. Test domain validation")
        print("2. Test URL validation") 
        print("3. Test host connectivity")
        print("4. View current config")
        print("5. Change a config setting")
        print("6. Exit")
        
        choice = input("\nEnter your choice (1-6): ").strip()
        
        if choice == "1":
            domain = input("Enter domain to validate: ").strip()
            is_valid = ValidationUtils.validate_domain(domain)
            print(f"✅ Domain '{domain}' is valid" if is_valid else f"❌ Domain '{domain}' is invalid")
            logger.info(f"Domain validation test: {domain} -> {is_valid}")
            
        elif choice == "2":
            url = input("Enter URL to validate: ").strip()
            is_valid = ValidationUtils.validate_url(url)
            print(f"✅ URL '{url}' is valid" if is_valid else f"❌ URL '{url}' is invalid")
            logger.info(f"URL validation test: {url} -> {is_valid}")
            
        elif choice == "3":
            host = input("Enter host to check (domain or IP): ").strip()
            is_alive = NetworkUtils.is_host_alive(host)
            print(f"✅ Host '{host}' is reachable" if is_alive else f"❌ Host '{host}' is not reachable")
            logger.info(f"Host connectivity test: {host} -> {is_alive}")
            
        elif choice == "4":
            config.show_config()
            
        elif choice == "5":
            key = input("Enter config key to change (e.g., 'threads' or 'timeouts.nmap'): ").strip()
            current_value = config.get(key)
            print(f"Current value: {current_value}")
            new_value = input("Enter new value: ").strip()
            
            # Convert to int if it's a number
            if new_value.isdigit():
                new_value = int(new_value)
                
            config.set(key, new_value)
            print(f"✅ Updated {key} to {new_value}")
            logger.info(f"Config changed: {key} = {new_value}")
            
        elif choice == "6":
            logger.info("Interactive test completed")
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please enter 1-6.")

if __name__ == "__main__":
    interactive_test()
