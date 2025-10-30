#!/usr/bin/env python3
"""
CAREL v2.0 - Main Application with Port Scanner
Complete updated version
"""
from modules.service_fingerprinter import ServiceFingerprinter
from modules.report_generator import ReportGenerator
from modules.subdomain_enum import SubdomainEnum
import asyncio  
from modules.visual_recon import VisualRecon
from pathlib import Path  
from modules.directory_buster import DirectoryBuster
from modules.web_vuln_scanner import WebVulnScanner
from core.config_manager import ConfigManager
from core.logger import CarelLogger
from modules.port_scanner import PortScanner
import sys
import os

def display_banner():
    """Display application banner"""
    banner = r"""
    ╔══════════════════════════════════════════════╗
    ║              🛡️ CAREL v2.0 🛡️               ║
    ║   Comprehensive Automated Reconnaissance     ║
    ║           & Exploitation Launcher           ║
    ║                                              ║
    ║         🔍 Port Scanner Module Active       ║
    ╚══════════════════════════════════════════════╝
    """
    print(banner)

def port_scan_menu(scanner: PortScanner):
    """Port scanning menu - COMPLETE VERSION"""
    print("\n🎯 PORT SCANNING MENU")
    print("=" * 50)
    
    while True:
        # Get target
        target = input("\nEnter target (domain or IP) or 'back' to return: ").strip()
        
        if target.lower() in ['back', 'exit', 'quit']:
            return
        
        if not target:
            print("❌ No target provided")
            continue
        
        # Show scan types
        scan_types = scanner.get_scan_types()
        print("\n📋 Select Scan Type:")
        for i, st in enumerate(scan_types, 1):
            print(f"  {i}. {st['name']} - {st['desc']}")
        
        try:
            choice_input = input(f"\nChoose (1-{len(scan_types)}) or 'back': ").strip()
            
            if choice_input.lower() in ['back', 'exit']:
                continue
                
            choice = int(choice_input)
            if 1 <= choice <= len(scan_types):
                selected_type = scan_types[choice - 1]["id"]
            else:
                print("❌ Invalid choice, using Quick Scan")
                selected_type = "quick"
        except ValueError:
            print("❌ Invalid input, using Quick Scan")
            selected_type = "quick"
        
        # Get custom ports if needed
        custom_ports = ""
        if selected_type == "custom":
            custom_ports = input("Enter port range (e.g., 80,443 or 1-1000): ").strip()
            if not custom_ports:
                print("⚠️  No custom ports provided, using quick scan instead")
                selected_type = "quick"
        
        # Get threads
        try:
            threads_input = input("Enter threads (default 10): ").strip()
            threads = int(threads_input) if threads_input else 10
            threads = max(1, min(threads, 50))  # Limit between 1-50
        except ValueError:
            print("⚠️  Invalid threads, using 10")
            threads = 10
        
        # Get timeout
        try:
            timeout_input = input("Enter timeout in seconds (default 300): ").strip()
            timeout = int(timeout_input) if timeout_input else 300
            timeout = max(30, min(timeout, 3600))  # Limit between 30-3600 seconds
        except ValueError:
            print("⚠️  Invalid timeout, using 300 seconds")
            timeout = 300
        
        # Show scan summary
        print(f"\n📋 SCAN SUMMARY:")
        print(f"   Target: {target}")
        print(f"   Scan Type: {selected_type}")
        if custom_ports:
            print(f"   Ports: {custom_ports}")
        print(f"   Threads: {threads}")
        print(f"   Timeout: {timeout} seconds")
        
        confirm = input("\n🚀 Start scan? (y/n): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("❌ Scan cancelled")
            continue
        
        # Run scan
        print(f"\n🚀 Starting {selected_type} scan on {target}...")
        print("⏳ This may take a few minutes...")
        print("💡 Press Ctrl+C to cancel the scan\n")
        
        try:
            results = scanner.scan_target(
                target=target,
                scan_type=selected_type,
                custom_ports=custom_ports,
                threads=threads,
                timeout=timeout
            )
            
            # Display results
            report = scanner.generate_scan_report(results)
            print("\n" + "="*60)
            print("📊 SCAN RESULTS")
            print("="*60)
            print(report)
            
            # Ask to save results
            save = input("\n💾 Save results to file? (y/n): ").strip().lower()
            if save in ['y', 'yes']:
                filename = input("Enter filename (or press Enter for auto-name): ").strip()
                if not filename:
                    filename = None
                saved_path = scanner.save_scan_results(results, filename)
                if saved_path:
                    print(f"✅ Results saved to: {saved_path}")
                else:
                    print("❌ Failed to save results")
            
            # Ask if user wants to scan another target
            another = input("\n🔍 Scan another target? (y/n): ").strip().lower()
            if another not in ['y', 'yes']:
                break
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan cancelled by user")
            break
        except Exception as e:
            print(f"\n💥 Error during scan: {e}")
            scanner.logger.error(f"Scan error: {e}")

def web_vuln_menu(scanner: WebVulnScanner):
    """Web vulnerability scanning menu"""
    print("\n🌐 WEB VULNERABILITY SCANNING")
    print("=" * 50)
    
    while True:
        # Get target
        target = input("\nEnter website URL (e.g., example.com) or 'back' to return: ").strip()
        
        if target.lower() in ['back', 'exit', 'quit']:
            return
        
        if not target:
            print("❌ No target provided")
            continue
        
        # Show scan types
        print("\n📋 Select Scan Depth:")
        print("  1. Basic Scan - Headers and basic recon (Fast)")
        print("  2. Advanced Scan - + Common endpoints (Medium)")
        print("  3. Full Scan - + HTTP methods and deep analysis (Slow)")
        
        try:
            choice = input("\nChoose depth (1-3): ").strip()
            if choice == "1":
                scan_depth = "basic"
            elif choice == "2":
                scan_depth = "advanced" 
            elif choice == "3":
                scan_depth = "full"
            else:
                print("⚠️  Invalid choice, using Basic Scan")
                scan_depth = "basic"
        except:
            scan_depth = "basic"
        
        # Get timeout
        try:
            timeout = int(input("Enter timeout in seconds (default 30): ").strip() or "30")
            timeout = max(10, min(timeout, 300))  # Limit 10-300 seconds
        except:
            timeout = 30
        
        # Show scan summary
        print(f"\n📋 SCAN SUMMARY:")
        print(f"   Target: {target}")
        print(f"   Depth: {scan_depth.upper()}")
        print(f"   Timeout: {timeout} seconds")
        
        confirm = input("\n🚀 Start web vulnerability scan? (y/n): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("❌ Scan cancelled")
            continue
        
        # Run scan
        print(f"\n🚀 Starting {scan_depth} web vulnerability scan...")
        print("⏳ This may take a moment...")
        print("💡 Press Ctrl+C to cancel the scan\n")
        
        try:
            results = scanner.scan_website(
                url=target,
                scan_depth=scan_depth,
                timeout=timeout
            )
            
            # Display results
            report = scanner.generate_scan_report(results)
            print("\n" + "="*70)
            print("📊 WEB SCAN RESULTS")
            print("="*70)
            print(report)
            
            # Ask to save results
            save = input("\n💾 Save results to file? (y/n): ").strip().lower()
            if save in ['y', 'yes']:
                filename = input("Enter filename (or press Enter for auto-name): ").strip()
                if not filename:
                    filename = None
                saved_path = scanner.save_scan_results(results, filename)
                if saved_path:
                    print(f"✅ Results saved to: {saved_path}")
                else:
                    print("❌ Failed to save results")
            
            # Ask if user wants to scan another target
            another = input("\n🔍 Scan another website? (y/n): ").strip().lower()
            if another not in ['y', 'yes']:
                break
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan cancelled by user")
            break
        except Exception as e:
            print(f"\n💥 Error during scan: {e}")
            scanner.logger.error(f"Web scan error: {e}")
            
def directory_buster_menu(buster: DirectoryBuster):
    """Directory busting menu"""
    print("\n📁 DIRECTORY BUSTING")
    print("=" * 50)
    
    while True:
        # Get target
        target = input("\nEnter website URL (e.g., example.com) or 'back' to return: ").strip()
        
        if target.lower() in ['back', 'exit', 'quit']:
            return
        
        if not target:
            print("❌ No target provided")
            continue
        
        # Show scan profiles
        profiles = buster.get_scan_profiles()
        print("\n📋 Select Scan Profile:")
        for i, profile in enumerate(profiles, 1):
            print(f"  {i}. {profile['name']} - {profile['description']}")
            print(f"     Threads: {profile['threads']}, Timeout: {profile['timeout']}s, Stealth: {profile['stealth']}")
        
        try:
            choice = input(f"\nChoose profile (1-{len(profiles)}): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(profiles):
                selected_profile = profiles[int(choice) - 1]["id"]
            else:
                print("⚠️  Invalid choice, using Standard Scan")
                selected_profile = "standard"
        except:
            selected_profile = "standard"
        
        # Show available wordlists
        wordlists = buster.engine.get_available_wordlists()
        if wordlists:
            print(f"\n📁 Available Wordlists ({len(wordlists)}):")
            for i, wl in enumerate(wordlists[:5], 1):  # Show first 5
                print(f"  {i}. {wl['description']}")
            print("  *. Use custom wordlist path")
        
        wordlist_choice = input("\nChoose wordlist (number or custom path): ").strip()
        custom_wordlist = None
        
        if wordlist_choice and wordlist_choice != "*":
            if wordlist_choice.isdigit() and 1 <= int(wordlist_choice) <= len(wordlists):
                custom_wordlist = wordlists[int(wordlist_choice) - 1]["path"]
            else:
                # Treat as custom path
                custom_wordlist = wordlist_choice
                if not Path(custom_wordlist).exists():
                    print(f"❌ Wordlist not found: {custom_wordlist}")
                    continue
        
        # Custom settings
        try:
            custom_threads = input(f"Enter custom threads (or Enter for default): ").strip()
            custom_threads = int(custom_threads) if custom_threads else None
        except:
            custom_threads = None
        
        try:
            custom_timeout = input(f"Enter custom timeout in seconds (or Enter for default): ").strip()
            custom_timeout = int(custom_timeout) if custom_timeout else None
        except:
            custom_timeout = None
        
        # Show scan summary
        profile = next(p for p in profiles if p["id"] == selected_profile)
        print(f"\n📋 SCAN SUMMARY:")
        print(f"   Target: {target}")
        print(f"   Profile: {profile['name']}")
        print(f"   Wordlist: {Path(custom_wordlist).name if custom_wordlist else 'Auto-selected'}")
        print(f"   Threads: {custom_threads or profile['threads']}")
        print(f"   Timeout: {custom_timeout or profile['timeout']}s")
        print(f"   Stealth: {profile['stealth']}")
        
        confirm = input("\n🚀 Start directory busting scan? (y/n): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("❌ Scan cancelled")
            continue
        
        # Run scan
        print(f"\n🚀 Starting {profile['name']} directory busting...")
        print("⏳ This may take several minutes...")
        print("💡 Press Ctrl+C to cancel the scan\n")
        
        try:
            results = buster.run_directory_scan(
                target=target,
                profile_id=selected_profile,
                custom_wordlist=custom_wordlist,
                custom_threads=custom_threads,
                custom_timeout=custom_timeout
            )
            
            # Display results
            report = buster.generate_scan_report(results)
            print("\n" + "="*70)
            print("📊 DIRECTORY BUSTING RESULTS")
            print("="*70)
            print(report)
            
            # Ask to save results
            save = input("\n💾 Save results to file? (y/n): ").strip().lower()
            if save in ['y', 'yes']:
                filename = input("Enter filename (or press Enter for auto-name): ").strip()
                if not filename:
                    filename = None
                saved_path = buster.save_scan_results(results, filename)
                if saved_path:
                    print(f"✅ Results saved to: {saved_path}")
                else:
                    print("❌ Failed to save results")
            
            # Ask if user wants to scan another target
            another = input("\n🔍 Scan another website? (y/n): ").strip().lower()
            if another not in ['y', 'yes']:
                break
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan cancelled by user")
            break
        except Exception as e:
            print(f"\n💥 Error during scan: {e}")
            buster.logger.error(f"Directory busting error: {e}") 
            
def subdomain_enum_menu(enum: SubdomainEnum):
    """Subdomain enumeration menu"""
    print("\n🌐 SUBDOMAIN ENUMERATION")
    print("=" * 50)
    
    while True:
        # Get target domain
        domain = input("\nEnter target domain (e.g., example.com) or 'back' to return: ").strip()
        
        if domain.lower() in ['back', 'exit', 'quit']:
            return
        
        if not domain:
            print("❌ No domain provided")
            continue
        
        # Show enumeration profiles
        profiles = enum.get_enumeration_profiles()
        print("\n📋 Select Enumeration Profile:")
        for i, profile in enumerate(profiles, 1):
            print(f"  {i}. {profile['name']} - {profile['description']}")
            print(f"     Methods: {', '.join(profile['methods'])}")
            print(f"     Timeout: {profile['timeout']}s, Workers: {profile['max_workers']}")
        
        try:
            choice = input(f"\nChoose profile (1-{len(profiles)}): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(profiles):
                selected_profile = profiles[int(choice) - 1]["id"]
            else:
                print("⚠️  Invalid choice, using Standard Enumeration")
                selected_profile = "standard"
        except:
            selected_profile = "standard"
        
        # Show available wordlists
        wordlists = enum.engine.get_available_wordlists()
        if wordlists:
            print(f"\n📁 Available Wordlists ({len(wordlists)}):")
            for i, wl in enumerate(wordlists[:5], 1):  # Show first 5
                print(f"  {i}. {wl['description']}")
            print("  *. Use custom wordlist path")
        
        wordlist_choice = input("\nChoose wordlist (number or custom path): ").strip()
        custom_wordlist = None
        
        if wordlist_choice and wordlist_choice != "*":
            if wordlist_choice.isdigit() and 1 <= int(wordlist_choice) <= len(wordlists):
                custom_wordlist = wordlists[int(wordlist_choice) - 1]["path"]
            else:
                # Treat as custom path
                custom_wordlist = wordlist_choice
                if not os.path.exists(custom_wordlist):
                    print(f"❌ Wordlist not found: {custom_wordlist}")
                    continue
        
        # Live verification option
        verify_live = input("\n🌐 Verify live subdomains? (y/n, default y): ").strip().lower()
        verify_live = verify_live not in ['n', 'no']
        
        # Show scan summary
        profile = next(p for p in profiles if p["id"] == selected_profile)
        print(f"\n📋 SCAN SUMMARY:")
        print(f"   Domain: {domain}")
        print(f"   Profile: {profile['name']}")
        
        # Handle wordlist name display
        if custom_wordlist:
            wordlist_name = custom_wordlist.split('/')[-1]  # Get filename only
        else:
            wordlist_name = 'Auto-selected'
        print(f"   Wordlist: {wordlist_name}")
        
        print(f"   Methods: {', '.join(profile['methods'])}")
        print(f"   Workers: {profile['max_workers']}")
        print(f"   Verify Live: {'Yes' if verify_live else 'No'}")
        
        confirm = input("\n🚀 Start subdomain enumeration? (y/n): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("❌ Scan cancelled")
            continue
        
        # Run scan
        print(f"\n🚀 Starting {profile['name']} subdomain enumeration...")
        print("⏳ This may take several minutes...")
        print("💡 Press Ctrl+C to cancel the scan\n")
        
        try:
            # Run async function
            async def run_scan():
                return await enum.run_subdomain_enumeration(
                    domain=domain,
                    profile_id=selected_profile,
                    custom_wordlist=custom_wordlist,
                    verify_live=verify_live
                )
            
            results = asyncio.run(run_scan())
            
            # Display results
            report = enum.generate_scan_report(results)
            print("\n" + "="*70)
            print("📊 SUBDOMAIN ENUMERATION RESULTS")
            print("="*70)
            print(report)
            
            # Ask to save results
            save = input("\n💾 Save results to file? (y/n): ").strip().lower()
            if save in ['y', 'yes']:
                filename = input("Enter filename (or press Enter for auto-name): ").strip()
                if not filename:
                    filename = None
                saved_path = enum.save_scan_results(results, filename)
                if saved_path:
                    print(f"✅ Results saved to: {saved_path}")
                else:
                    print("❌ Failed to save results")
            
            # Ask if user wants to scan another domain
            another = input("\n🔍 Scan another domain? (y/n): ").strip().lower()
            if another not in ['y', 'yes']:
                break
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan cancelled by user")
            break
        except Exception as e:
            print(f"\n💥 Error during scan: {e}")
            enum.logger.error(f"Subdomain enumeration error: {e}")
            
def visual_recon_menu(recon: VisualRecon):
    """Visual reconnaissance menu"""
    print("\n📸 VISUAL RECONNAISSANCE")
    print("=" * 50)
    
    
     # Show stealth availability status
    if hasattr(recon, 'stealth_engine') and recon.stealth_engine:
        print("🛡️  STEALTH MODE: AVAILABLE")
        # Show stealth profiles briefly
        stealth_profiles = [p for p in recon.get_capture_profiles() if p.get('stealth_profile')]
        if stealth_profiles:
            print("   Enhanced profiles available for protected targets")
    else:
        print("🛡️  STEALTH MODE: NOT CONFIGURED")
        print("   Standard profiles work perfectly for most targets")
    
    while True:
        # Get URLs input
        print("\n📝 Enter URLs (one per line, comma-separated, or file path):")
        print("   Examples:")
        print("   - https://example.com")
        print("   - https://example.com, https://test.com") 
        print("   - /path/to/urls.txt")
        urls_input = input("\nURLs: ").strip()
        
        if not urls_input:
            print("❌ No URLs provided")
            continue
        
        if urls_input.lower() in ['back', 'exit', 'quit']:
            return
        
        # Validate URLs
        validation = recon.validate_and_prepare_urls(urls_input)
        if not validation["valid"]:
            print("❌ URL validation failed:")
            for error in validation["errors"]:
                print(f"   • {error}")
            continue
        
        valid_urls = validation["urls"]
        print(f"✅ Valid URLs: {len(valid_urls)}")
        if validation["errors"]:
            print("⚠️  Errors (skipped):")
            for error in validation["errors"][:5]:  # Show first 5 errors
                print(f"   • {error}")
        
        # Show capture profiles
        profiles = recon.get_capture_profiles()
        print("\n📋 Select Capture Profile:")
        for i, profile in enumerate(profiles, 1):
            stealth_indicator = " 🛡️" if profile.get('stealth_profile') else ""
            print(f"  {i}. {profile['name']} - {profile['description']}{stealth_indicator}")
            print(f"  {i}. {profile['name']} - {profile['description']}")
            print(f"     Timeout: {profile['timeout']}s, Workers: {profile['max_workers']}")
        
        try:
            choice = input(f"\nChoose profile (1-{len(profiles)}): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(profiles):
                selected_profile = profiles[int(choice) - 1]["id"]
            else:
                print("⚠️  Invalid choice, using Quick Capture")
                selected_profile = "quick"
        except:
            selected_profile = "quick"
        
        # Custom settings
        try:
            custom_timeout = input(f"Enter custom timeout in seconds (or Enter for default): ").strip()
            custom_timeout = int(custom_timeout) if custom_timeout else None
        except:
            custom_timeout = None
        
        try:
            custom_workers = input(f"Enter custom workers (or Enter for default): ").strip()
            custom_workers = int(custom_workers) if custom_workers else None
        except:
            custom_workers = None
        
        # Show scan summary
        profile = next(p for p in profiles if p["id"] == selected_profile)
        print(f"\n📋 SCAN SUMMARY:")
        print(f"   URLs: {len(valid_urls)}")
        print(f"   Profile: {profile['name']}")
        print(f"   Timeout: {custom_timeout or profile['timeout']}s")
        print(f"   Workers: {custom_workers or profile['max_workers']}")
        print(f"   Tool: {profile['tool_preference']}")
        
        confirm = input("\n🚀 Start visual reconnaissance? (y/n): ").strip().lower()
        if confirm not in ['y', 'yes']:
            print("❌ Scan cancelled")
            continue
        
        # Run scan
        print(f"\n🚀 Starting {profile['name']} visual reconnaissance...")
        print("📸 Capturing screenshots...")
        print("⏳ This may take several minutes...")
        print("💡 Press Ctrl+C to cancel the scan\n")
        
        try:
            results = recon.run_visual_recon(
                urls=valid_urls,
                profile_id=selected_profile,
                custom_timeout=custom_timeout,
                custom_workers=custom_workers
            )
            
            # Display results
            report = recon.generate_scan_report(results)
            print("\n" + "="*70)
            print("📊 VISUAL RECONNAISSANCE RESULTS")
            print("="*70)
            print(report)
            
            # Show screenshot directory
            output_dir = results.get('output_dir', 'Unknown')
            print(f"\n📁 Screenshots saved to: {output_dir}")
            
            # Ask to save results
            save = input("\n💾 Save results to file? (y/n): ").strip().lower()
            if save in ['y', 'yes']:
                filename = input("Enter filename (or press Enter for auto-name): ").strip()
                if not filename:
                    filename = None
                saved_path = recon.save_scan_results(results, filename)
                if saved_path:
                    print(f"✅ Results saved to: {saved_path}")
                else:
                    print("❌ Failed to save results")
            
            # Ask if user wants to scan more URLs
            another = input("\n🔍 Capture more screenshots? (y/n): ").strip().lower()
            if another not in ['y', 'yes']:
                break
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan cancelled by user")
            break
        except Exception as e:
            print(f"\n💥 Error during scan: {e}")
            recon.logger.error(f"Visual recon error: {e}")     
            
        
def service_fingerprint_menu(fingerprinter: ServiceFingerprinter, report_gen: ReportGenerator):
    """Service fingerprinting menu"""
    print("\n🔍 NETWORK SERVICE FINGERPRINTING")
    print("=" * 55)
    
    while True:
        target = input("\nEnter target (IP or domain) or 'back' to return: ").strip()
        
        if target.lower() in ['back', 'exit', 'quit']:
            return
        
        # Get ports to scan
        ports_input = input("Enter ports to scan (comma-separated, or 'common' for common ports): ").strip()
        
        if ports_input.lower() == 'common':
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900]
        else:
            try:
                ports = [int(p.strip()) for p in ports_input.split(',')]
            except:
                print("❌ Invalid ports, using common ports")
                ports = [21, 22, 23, 80, 443, 3389]
        
        print(f"\n🎯 Scanning {len(ports)} services on {target}...")
        print("⏳ This may take a few minutes...")
        
        try:
            results = fingerprinter.scan_multiple_services(target, ports)
            
            # Generate and display report
            report = report_gen.generate_service_scan_report(results)
            print("\n" + report)
            
            # Save options
            print("\n💾 Save Options:")
            print("1. Save as text report")
            print("2. Save as HTML report") 
            print("3. Save both")
            print("4. Don't save")
            
            save_choice = input("Select option (1-4): ").strip()
            
            if save_choice in ['1', '2', '3']:
                base_name = f"service_scan_{target.replace('.', '_')}"
                
                if save_choice in ['1', '3']:
                    txt_file = f"{base_name}.txt"
                    with open(txt_file, 'w') as f:
                        f.write(report)
                    print(f"✅ Text report saved: {txt_file}")
                
                if save_choice in ['2', '3']:
                    html_file = f"{base_name}.html"
                    saved_path = report_gen.save_html_report(results, html_file)
                    if saved_path:
                        print(f"✅ HTML report saved: {saved_path}")
            
        except Exception as e:
            print(f"❌ Service fingerprinting failed: {e}")                                          
            
def configuration_menu(config: ConfigManager, logger: CarelLogger):
    """Configuration management menu"""
    while True:
        print("\n⚙️  CONFIGURATION MENU")
        print("=" * 40)
        print("1. View Current Configuration")
        print("2. Set NVD API Key")
        print("3. Change Default Threads")
        print("4. Change Timeout Settings")
        print("5. Reset to Defaults")
        print("6. Back to Main Menu")
        
        choice = input("\nSelect an option (1-6): ").strip()
        
        if choice == "1":
            config.show_config()
            
        elif choice == "2":
            current_key = config.get("nvd_api_key")
            print(f"\nCurrent NVD API Key: {current_key or 'Not set'}")
            new_key = input("Enter new NVD API Key (or press Enter to clear): ").strip()
            config.set("nvd_api_key", new_key)
            if new_key:
                print("✅ NVD API Key updated")
                logger.info("NVD API Key updated")
            else:
                print("✅ NVD API Key cleared")
                logger.info("NVD API Key cleared")
                
        elif choice == "3":
            current_threads = config.get("threads")
            print(f"\nCurrent default threads: {current_threads}")
            try:
                new_threads = int(input("Enter new default threads: ").strip())
                if 1 <= new_threads <= 50:
                    config.set("threads", new_threads)
                    print(f"✅ Default threads updated to {new_threads}")
                    logger.info(f"Default threads updated to {new_threads}")
                else:
                    print("❌ Threads must be between 1-50")
            except ValueError:
                print("❌ Invalid number")
                
        elif choice == "4":
            print("\n⏱️  Current Timeout Settings:")
            timeouts = config.get("timeouts", {})
            for key, value in timeouts.items():
                print(f"   {key}: {value} seconds")
            
            print("\nAvailable timeouts: nmap, feroxbuster, dns, http, screenshot")
            timeout_key = input("Enter timeout to change: ").strip()
            if timeout_key in timeouts:
                try:
                    new_timeout = int(input(f"Enter new timeout for {timeout_key} (seconds): ").strip())
                    if new_timeout > 0:
                        config.set(f"timeouts.{timeout_key}", new_timeout)
                        print(f"✅ {timeout_key} timeout updated to {new_timeout} seconds")
                        logger.info(f"{timeout_key} timeout updated to {new_timeout}")
                    else:
                        print("❌ Timeout must be positive")
                except ValueError:
                    print("❌ Invalid number")
            else:
                print("❌ Invalid timeout key")
                
        elif choice == "5":
            confirm = input("⚠️  Reset all settings to defaults? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                # Recreate default config
                default_config = ConfigManager().default_config
                for key, value in default_config.items():
                    config.set(key, value)
                print("✅ Configuration reset to defaults")
                logger.info("Configuration reset to defaults")
                
        elif choice == "6":
            break
            
        else:
            print("❌ Invalid option")
        
        input("\nPress Enter to continue...")

def view_logs_menu(config: ConfigManager):
    """Log viewing menu"""
    log_dir = config.home_dir / "logs"
    
    if not log_dir.exists():
        print("❌ Log directory not found")
        return
    
    log_files = list(log_dir.glob("*.log"))
    
    if not log_files:
        print("❌ No log files found")
        return
    
    print(f"\n📊 LOG FILES in {log_dir}:")
    print("=" * 50)
    
    for i, log_file in enumerate(sorted(log_files, reverse=True), 1):
        size = log_file.stat().st_size
        print(f"{i}. {log_file.name} ({size} bytes)")
    
    try:
        choice = input(f"\nSelect log file to view (1-{len(log_files)}) or 'back': ").strip()
        
        if choice.lower() in ['back', 'exit']:
            return
            
        choice_num = int(choice)
        if 1 <= choice_num <= len(log_files):
            selected_log = log_files[choice_num - 1]
            
            print(f"\n📄 Contents of {selected_log.name}:")
            print("=" * 60)
            
            try:
                with open(selected_log, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content:
                        print(content)
                    else:
                        print("(Empty log file)")
            except Exception as e:
                print(f"❌ Error reading log file: {e}")
                
            # Show last few lines option
            if input("\n📜 Show last 20 lines only? (y/n): ").strip().lower() in ['y', 'yes']:
                print("\n" + "=" * 60)
                print("📜 LAST 20 LINES:")
                print("=" * 60)
                try:
                    with open(selected_log, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        for line in lines[-20:]:
                            print(line, end='')
                except Exception as e:
                    print(f"❌ Error reading log file: {e}")
        else:
            print("❌ Invalid selection")
    except ValueError:
        print("❌ Invalid input")

def system_info_menu(config: ConfigManager, logger: CarelLogger):
    """Display system information"""
    import platform
    import shutil
    
    print("\n💻 SYSTEM INFORMATION")
    print("=" * 50)
    
    # Basic system info
    print(f"System: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print(f"CAREL Directory: {config.home_dir}")
    
    # Check required tools
    print("\n🔧 TOOL CHECK:")
    tools_to_check = [
        ("nmap", "Port scanning"),
        ("feroxbuster", "Directory busting"), 
        ("aquatone", "Screenshots"),
        ("cutycapt", "Screenshot fallback"),
        ("sublist3r", "Subdomain enumeration")
    ]
    
    for tool, description in tools_to_check:
        if shutil.which(tool):
            print(f"  ✅ {tool}: {description} - INSTALLED")
        else:
            print(f"  ❌ {tool}: {description} - MISSING")
    
    # Directory sizes
    print("\n📁 STORAGE INFO:")
    total_size = 0
    for item in config.home_dir.iterdir():
        if item.is_dir():
            dir_size = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())
            total_size += dir_size
            print(f"  {item.name}: {dir_size / (1024*1024):.2f} MB")
    
    print(f"  Total: {total_size / (1024*1024):.2f} MB")
    
    input("\nPress Enter to continue...")

def main_menu():
    """Main application menu - COMPLETE VERSION"""
    # Initialize core components
    config = ConfigManager()
    logger = CarelLogger(config)
    scanner = PortScanner(config, logger)
    web_scanner = WebVulnScanner(config, logger)
    dir_buster = DirectoryBuster(config, logger)
    subdomain_enum = SubdomainEnum(config, logger)
    visual_recon = VisualRecon(config, logger)
    fingerprinter = ServiceFingerprinter(config, logger)
    report_gen = ReportGenerator(config, logger)
    
    logger.info("CAREL v2.0 started successfully")
    
    while True:
        display_banner()
        
        print("\n📋 MAIN MENU")
        print("1. 🎯 Port Scanning")
        print("2. 🌐 Web Vulnerability Scanning")
        print("3. 📁 Directory Busting")
        print("4. 🌐 Subdomain Enumeration")
        print("5. 📸 Visual Reconnaissance")
        print("6. 🔍 Service Fingerprinting") 
        print("7. ⚙️  Configuration")
        print("8. 📊 View Logs") 
        print("9. 💻 System Info")
        print("10. 🚪 Exit")
        
        choice = input("\nSelect an option (1-5): ").strip()
        
        if choice == "1":
            port_scan_menu(scanner)
        elif choice == "2":  
            web_vuln_menu(web_scanner)
        elif choice == "3":  
            directory_buster_menu(dir_buster)
        elif choice == "4": 
            subdomain_enum_menu(subdomain_enum)
        elif choice == "5":  
            visual_recon_menu(visual_recon)  
        elif choice == "6":
            service_fingerprint_menu(fingerprinter, report_gen)              
        elif choice == "7":
            configuration_menu(config, logger)
        elif choice == "8":
            view_logs_menu(config)
        elif choice == "9":
            system_info_menu(config, logger)
        elif choice == "10":
            logger.info("User exited CAREL v2.0")
            print("\n👋 Thank you for using CAREL v2.0!")
            print("🔒 Stay secure!")
            break
        else:
            print("❌ Invalid option. Please choose 1-5.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
