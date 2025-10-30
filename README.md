# CAREL

🛡️ CAREL v2.0 - Comprehensive Automated Reconnaissance & Exploitation Launcher
https://img.shields.io/badge/Python-3.8+-blue.svg
https://img.shields.io/badge/Platform-Linux%2520%257C%2520Kali%2520Linux-green.svg
https://img.shields.io/badge/License-MIT-orange.svg

Enterprise-Grade Security Reconnaissance Platform - Automating penetration testing reconnaissance with advanced evasion and real-time vulnerability intelligence.

📖 Table of Contents
Overview

Features

Quick Start

Modules

Installation

Usage

Demo Targets

Output & Reporting

Configuration

Contributing

Legal & Ethics

🚀 Overview
CAREL v2.0 is an advanced penetration testing platform that consolidates 10+ security tools into a unified framework. It automates comprehensive security reconnaissance with enterprise-grade stealth capabilities and real-time vulnerability intelligence from the National Vulnerability Database (NVD).

🎯 Why CAREL?
Saves Time: Automates what normally takes hours of manual work

Enterprise Ready: Bypasses modern WAFs and anti-bot protection

Intelligent: Live CVE correlation with discovered services

Professional: Client-ready reports in multiple formats

✨ Features
🔍 Core Capabilities
Port Scanning with NVD CVE integration

Web Vulnerability Assessment with technology fingerprinting

Service Fingerprinting with protocol analysis

Visual Reconnaissance with stealth screenshot capture

Directory Busting with multiple wordlists

Subdomain Enumeration with live verification

🛡️ Advanced Features
Stealth Engine - Evade WAFs and detection systems

Real-time Intelligence - Live NVD API integration

Multi-threading - Fast, parallel operations

Professional Reporting - HTML, Text, and JSON outputs

Modular Architecture - Easy to extend and customize

⚡ Quick Start
1. Installation
bash
# Clone the repository
git clone https://github.com/yourusername/carel_v2.git
cd carel_v2

# Install dependencies
pip install -r requirements.txt

# Install optional security tools
sudo apt update
sudo apt install nmap feroxbuster cutycapt
2. First Run
bash
python main.py
3. Quick Demo (2 minutes)
text
1. Choose "Service Fingerprinting"
2. Enter: scanme.nmap.org
3. Choose: common ports
4. View professional HTML report with CVEs!
🛠️ Modules
1. 🎯 Port Scanner
Advanced network service discovery with live CVE intelligence

bash
Features:
• Multi-threaded port scanning
• Service banner grabbing
• NVD CVE correlation
• Risk-prioritized results
• Custom port ranges

Demo Target: scanme.nmap.org
2. 🌐 Web Vulnerability Scanner
Comprehensive web application assessment

bash
Features:
• Technology stack detection
• Security header analysis
• Live CVE lookup
• Multiple scan depths
• Professional reporting

Demo Target: httpbin.org
3. 🔍 Service Fingerprinter
Advanced service identification and vulnerability assessment

bash
Features:
• Protocol-specific analysis
• Version extraction
• CVSS risk scoring
• Vulnerability correlation
• HTML reports

Demo Target: scanme.nmap.org
4. 📸 Visual Reconnaissance
Stealth website screenshot capture

bash
Features:
• Multiple capture tools
• Anti-detection evasion
• Batch processing
• Stealth profiles
• Visual evidence collection

Demo Target: httpbin.org/html
5. 📁 Directory Buster
Hidden endpoint discovery

bash
Features:
• Multiple wordlists
• Stealth scanning
• Custom profiles
• Results filtering
6. 🌐 Subdomain Enumerator
Attack surface expansion

bash
Features:
• Multiple enumeration methods
• Live verification
• DNS record analysis
• Comprehensive reporting
🔧 Installation
Prerequisites
Python 3.8+

Kali Linux (recommended) or Linux

Network connectivity for external scanning

Step-by-Step Setup
bash
# 1. Clone and setup
git clone https://github.com/yourusername/carel_v2.git
cd carel_v2

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install security tools
sudo apt update
sudo apt install nmap feroxbuster cutycapt aquatone

# 4. Configure NVD API (optional but recommended)
# Edit ~/.carel_v2/config.json and add your NVD API key
Optional Tools for Enhanced Features
bash
# For advanced stealth
sudo apt install tor

# For enhanced visual recon
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone /usr/local/bin/
🎮 Usage
Basic Operation
bash
python main.py
Then navigate through the intuitive menu system.

Module-Specific Examples
Port Scanning
bash
# Quick scan with CVE intelligence
Target: scanme.nmap.org
Scan Type: Quick Scan
Threads: 10
Timeout: 300 seconds
Web Vulnerability Assessment
bash
# Comprehensive web scan
Target: httpbin.org
Scan Depth: Advanced
Timeout: 30 seconds
Service Fingerprinting
bash
# Full service analysis
Target: 8.8.8.8
Ports: common (15 most used ports)
Command Line Options
bash
# Coming in future versions
python main.py --target example.com --module web --output html
🎯 Demo Targets
✅ Recommended Test Targets
Module	Target	Purpose
All	scanme.nmap.org	Official test site
Web Scanning	httpbin.org	Always accessible
Port Scanning	8.8.8.8	Multiple services
Service Fingerprinting	github.com:22	SSH analysis
Visual Recon	example.com	Reliable screenshot
🚀 Job Fair Demo Sequence
bash
# 2-Minute "Wow" Demo:
1. Service Fingerprinting: scanme.nmap.org
2. Web Scanning: httpbin.org  
3. Show HTML report with CVEs and risk scores
📊 Output & Reporting
File Structure
text
~/.carel_v2/
├── 📂 scans/          # JSON results and reports
├── 📂 screenshots/    # Visual reconnaissance images
├── 📂 logs/          # Application logs
└── 📄 config.json    # Configuration file
Report Types
HTML Reports: Professional client-ready format

Text Reports: Quick analysis and overview

JSON Data: API-friendly structured data

Screenshots: Visual evidence collection

Sample Output
bash
🔍 SERVICE FINGERPRINTING REPORT
================================
Target: scanme.nmap.org
Open Ports: 2
CVEs Identified: 3

🚪 OPEN PORTS:
🔓 Port 22 - SSH (OpenSSH 6.6.1)
   🚨 2 CVEs Found:
     🔴 CVE-2023-28531 (CVSS: 7.5)
     
🔓 Port 80 - Apache (2.4.7)
   🚨 1 CVE Found:
     🟡 CVE-2021-41773 (CVSS: 7.5)
⚙️ Configuration
NVD API Integration
Get your free API key from NVD API Portal and add to config:

json
{
  "nvd_api_key": "your-api-key-here",
  "stealth_profiles": {
    "quick": {"delay": "1-3", "workers": 5},
    "stealth": {"delay": "10-30", "workers": 2}
  }
}
Stealth Profiles
Quick: Fast scanning (1-3 second delays)

Standard: Balanced speed/stealth (3-10 seconds)

Stealth: Advanced evasion (10-30 seconds)

Aggressive: Maximum stealth (30-120 seconds)

🤝 Contributing
We welcome contributions! Here's how:

Fork the repository

Create a feature branch (git checkout -b feature/amazing-feature)

Commit your changes (git commit -m 'Add amazing feature')

Push to the branch (git push origin feature/amazing-feature)

Open a Pull Request

Development Setup
bash
# Set up development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
⚖️ Legal & Ethics
🛡️ Responsible Usage
CAREL v2.0 is designed for:

Authorized penetration testing

Security education and research

Corporate security assessments

Ethical hacking practice

❌ Strictly Prohibited
Unauthorized network scanning

Illegal penetration testing

Malicious attacks

Any unauthorized security testing

🔒 Compliance
Only use on networks you own or have explicit permission to test

Always follow responsible disclosure practices

Respect all applicable laws and regulations

Educational Purpose
This tool is primarily designed for:

Security professionals to enhance their skills

Students learning ethical hacking

Organizations improving their security posture

📞 Support & Community
Documentation
Full documentation available in /docs/

Example reports in ~/.carel_v2/scans/

Configuration guide in CONFIGURATION.md

Issues & Bugs
Report issues on our GitHub Issues page.

Feature Requests
Have an idea? Submit it through our Feature Requests page.

🏆 Acknowledgments
National Vulnerability Database for CVE intelligence

Nmap Project for port scanning capabilities

Security Community for continuous inspiration

📜 License
This project is licensed under the MIT License - see the LICENSE.md file for details.

🚀 Getting Help
bash
# Check the logs for detailed information
tail -f ~/.carel_v2/logs/carel_*.log

# View configuration
cat ~/.carel_v2/config.json

# Test basic functionality
python -c "from core.config_manager import ConfigManager; print('✅ CAREL configured correctly')"
⭐ Star this repository if you find CAREL v2.0 useful!

Happy ethical hacking! 🛡️

*CAREL v2.0 - Making professional security assessment accessible to everyone.*
