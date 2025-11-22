#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VulnScan Pro - Advanced Security Research Scanner
Comprehensive vulnerability detection including logical flaws
Author: Security Research Team
Version: 3.0 Professional
"""

import requests
import re
import ssl
import socket
import json
import datetime
import time
import random
import argparse
import os
import sys
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------------------------------------------
# Advanced Configuration
# ------------------------------------------------------------

CONFIG = {
    'timeout': 15,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ],
    'deep_scan': True,
    'follow_redirects': True
}

# ------------------------------------------------------------
# Display Functions - MUST BE DEFINED FIRST
# ------------------------------------------------------------

def display_banner(title=""):
    """Display beautiful banner"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print(Fore.CYAN + r"""
    ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
    ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
     ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
      ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """ + Fore.RED + r"""
    ██████╗ ██████╗  ██████╗      ██████╗ ██████╗ ███████╗██████╗ 
    ██╔══██╗██╔══██╗██╔═══██╗    ██╔════╝██╔═══██╗██╔════╝██╔══██╗
    ██████╔╝██████╔╝██║   ██║    ██║     ██║   ██║█████╗  ██████╔╝
    ██╔═══╝ ██╔══██╗██║   ██║    ██║     ██║   ██║██╔══╝  ██╔══██╗
    ██║     ██║  ██║╚██████╔╝    ╚██████╗╚██████╔╝███████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝      ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
    """ + Style.RESET_ALL)
    
    if title:
        print(Fore.GREEN + f"\n           {title}")
        print(Fore.WHITE + "           " + "=" * 60)
    else:
        print(Fore.GREEN + "           Advanced Security Research Scanner v3.0")
        print(Fore.WHITE + "           " + "=" * 60)
    print()

def info(msg):
    """Info message"""
    print(Fore.BLUE + "[i] " + Fore.WHITE + msg)

def warning(msg):
    """Warning message"""
    print(Fore.YELLOW + "[!] " + Fore.WHITE + msg)

def error(msg):
    """Error message"""
    print(Fore.RED + "[x] " + Fore.WHITE + msg)

def success(msg):
    """Success message"""
    print(Fore.GREEN + "[+] " + Fore.WHITE + msg)

def result(title, value):
    """Result display"""
    print(Fore.CYAN + "[>] " + Fore.WHITE + f"{title}: " + Fore.GREEN + str(value))

# ------------------------------------------------------------
# Results Storage
# ------------------------------------------------------------

scan_results = {
    "target": "",
    "scan_date": "",
    "vulnerabilities": [],
    "logical_flaws": [],
    "security_headers": [],
    "sensitive_files": [],
    "ssl_info": {},
    "risk_level": "Low",
    "scan_depth": "Standard"
}

class Vulnerability:
    def __init__(self, title, severity, description, risk_level, solution, vuln_type, confidence):
        self.id = len(scan_results["vulnerabilities"]) + 1
        self.title = title
        self.severity = severity
        self.description = description
        self.risk_level = risk_level
        self.solution = solution
        self.type = vuln_type
        self.confidence = confidence
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_vulnerability(title, severity, description, risk_level, solution, vuln_type="Basic", confidence="Medium"):
    """Add vulnerability to results"""
    vuln = Vulnerability(title, severity, description, risk_level, solution, vuln_type, confidence)
    scan_results["vulnerabilities"].append(vuln.__dict__)
    
    if vuln_type == "Logical":
        scan_results["logical_flaws"].append(vuln.__dict__)
    
    # Display finding
    color = Fore.RED if risk_level == "High" else Fore.YELLOW if risk_level == "Medium" else Fore.BLUE
    print(color + f"[{risk_level}] {title}")

# ------------------------------------------------------------
# Request Engine
# ------------------------------------------------------------

def advanced_get(url, headers=None):
    """Advanced HTTP request with error handling"""
    try:
        session = requests.Session()
        default_headers = {
            'User-Agent': random.choice(CONFIG['user_agents']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        if headers:
            default_headers.update(headers)
            
        response = session.get(
            url, 
            headers=default_headers,
            timeout=CONFIG['timeout'],
            verify=False,
            allow_redirects=CONFIG['follow_redirects']
        )
        return response
    except Exception as e:
        error(f"Request failed: {e}")
        return None

# ------------------------------------------------------------
# Scanner Modules
# ------------------------------------------------------------

def scan_security_headers(url):
    """Scan security headers"""
    info("Scanning Security Headers...")
    r = advanced_get(url)
    if not r:
        error("Failed to retrieve URL for header scanning")
        return

    headers_checks = {
        "Content-Security-Policy": {"risk": "High", "desc": "CSP missing - XSS protection"},
        "X-Frame-Options": {"risk": "Medium", "desc": "Clickjacking protection missing"},
        "Strict-Transport-Security": {"risk": "High", "desc": "HSTS missing - SSL stripping"},
        "X-Content-Type-Options": {"risk": "Medium", "desc": "MIME sniffing protection missing"}
    }

    for header, info_data in headers_checks.items():
        if header not in r.headers:
            add_vulnerability(
                f"Missing {header}",
                info_data["risk"],
                info_data["desc"],
                info_data["risk"],
                f"Implement {header} header",
                "Headers",
                "High"
            )
        else:
            success(f"{header} found: {r.headers[header]}")

def scan_business_logic(url):
    """Scan for business logic vulnerabilities"""
    info("Scanning for Business Logic Flaws...")
    
    # Test for IDOR
    info("Testing IDOR vulnerabilities...")
    test_patterns = ["/user/1", "/admin/1", "/order/100", "/api/users/1"]
    for pattern in test_patterns:
        test_url = url.rstrip("/") + pattern
        response = advanced_get(test_url)
        
        if response and response.status_code == 200:
            if any(keyword in response.text.lower() for keyword in ["password", "email", "admin"]):
                add_vulnerability(
                    "Insecure Direct Object Reference (IDOR)",
                    "High",
                    f"Direct object access possible at {test_url}",
                    "High",
                    "Implement proper authorization checks",
                    "Logical",
                    "Medium"
                )

def scan_input_validation(url):
    """Test input validation"""
    info("Testing Input Validation...")
    
    # Test for SQL Injection
    info("Testing SQL Injection vectors...")
    payloads = ["' OR '1'='1", "'; DROP TABLE users--", "' UNION SELECT 1,2,3--"]
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = advanced_get(test_url)
        if response and any(error in response.text.lower() for error in ["sql", "syntax", "mysql"]):
            add_vulnerability(
                "SQL Injection Vulnerability",
                "Critical",
                f"SQL injection detected with payload: {payload}",
                "High",
                "Use parameterized queries and input validation",
                "SQLi",
                "High"
            )

def scan_api_security(url):
    """Test API security"""
    info("Testing API Security...")
    
    api_endpoints = ["/api/users", "/api/data", "/graphql", "/rest/v1"]
    for endpoint in api_endpoints:
        test_url = url.rstrip("/") + endpoint
        response = advanced_get(test_url)
        if response and response.status_code == 200:
            add_vulnerability(
                "Public API Access",
                "Medium",
                f"API endpoint publicly accessible: {test_url}",
                "Medium",
                "Implement API authentication and rate limiting",
                "API Security",
                "Medium"
            )

def scan_sensitive_files(url):
    """Scan for sensitive files"""
    info("Scanning for Sensitive Files...")
    
    files = [
        "/.env", "/.git/config", "/backup.zip", "/database.sql",
        "/wp-config.php", "/config.php", "/.htaccess"
    ]
    
    for file in files:
        test_url = url.rstrip("/") + file
        response = advanced_get(test_url)
        if response and response.status_code == 200:
            add_vulnerability(
                "Sensitive File Exposure",
                "High",
                f"Sensitive file found: {test_url}",
                "High",
                "Restrict access to sensitive files",
                "Information Disclosure",
                "High"
            )

# ------------------------------------------------------------
# Comprehensive Scanning
# ------------------------------------------------------------

def quick_scan(url):
    """Quick security scan"""
    display_banner("Quick Security Scan")
    info(f"Starting quick scan: {url}")
    
    scan_security_headers(url)
    scan_sensitive_files(url)
    scan_input_validation(url)
    
    generate_report()

def deep_scan(url):
    """Deep comprehensive scan"""
    display_banner("Deep Security Scan")
    info(f"Starting deep scan: {url}")
    
    scan_security_headers(url)
    scan_business_logic(url)
    scan_input_validation(url)
    scan_api_security(url)
    scan_sensitive_files(url)
    
    generate_report()

def custom_scan(url):
    """Custom scan based on user selection"""
    display_banner("Custom Security Scan")
    
    print(Fore.WHITE + """
Select scan modules:
[1] Security Headers
[2] Business Logic
[3] Input Validation
[4] API Security
[5] Sensitive Files
[6] All Modules
""")
    
    choice = input(Fore.YELLOW + "[?] Select modules (comma separated): ")
    modules = choice.split(',')
    
    info(f"Starting custom scan: {url}")
    
    if '1' in modules or '6' in modules:
        scan_security_headers(url)
    if '2' in modules or '6' in modules:
        scan_business_logic(url)
    if '3' in modules or '6' in modules:
        scan_input_validation(url)
    if '4' in modules or '6' in modules:
        scan_api_security(url)
    if '5' in modules or '6' in modules:
        scan_sensitive_files(url)
    
    generate_report()

# ------------------------------------------------------------
# Reporting
# ------------------------------------------------------------

def generate_report():
    """Generate scan report"""
    print(Fore.CYAN + "\n" + "="*70)
    print(Fore.CYAN + "                 SCAN REPORT SUMMARY")
    print(Fore.CYAN + "="*70)
    
    total_vulns = len(scan_results["vulnerabilities"])
    high_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "High"])
    medium_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "Medium"])
    
    result("Target", scan_results["target"])
    result("Scan Date", scan_results["scan_date"])
    result("Total Vulnerabilities", total_vulns)
    result("High Risk", high_vulns)
    result("Medium Risk", medium_vulns)
    
    if total_vulns > 0:
        print(Fore.YELLOW + "\nDETAILED FINDINGS:")
        for vuln in scan_results["vulnerabilities"]:
            color = Fore.RED if vuln["risk_level"] == "High" else Fore.YELLOW
            print(color + f"  [{vuln['risk_level']}] {vuln['title']}")
    
    print(Fore.CYAN + "\n" + "="*70)

# ------------------------------------------------------------
# Main Menu System
# ------------------------------------------------------------

def main_menu():
    """Main menu"""
    display_banner()
    
    print(Fore.WHITE + " Input    Description")
    print(Fore.WHITE + "=======  ==============================")
    print(Fore.CYAN + "  [1]    Quick Security Scan")
    print(Fore.CYAN + "  [2]    Deep Comprehensive Scan") 
    print(Fore.CYAN + "  [3]    Custom Module Scan")
    print(Fore.CYAN + "  [4]    Business Logic Testing")
    print(Fore.CYAN + "  [5]    API Security Testing")
    print(Fore.YELLOW + "  [U]    Update Scanner")
    print(Fore.YELLOW + "  [H]    Help & Documentation")
    print(Fore.RED + "  [0]    Exit Scanner\n")

def main():
    """Main function"""
    
    # Argument parsing
    parser = argparse.ArgumentParser(prog='vulnscan.py', add_help=False)
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan')
    parser.add_argument('-d', '--deep', action='store_true', help='Deep scan')
    parser.add_argument('--update', action='store_true', help='Update scanner')
    args = parser.parse_args()
    
    # Handle command line arguments
    if args.update:
        info("Update functionality would be implemented here")
        return
        
    if args.url:
        if args.quick:
            quick_scan(args.url)
        elif args.deep:
            deep_scan(args.url)
        else:
            quick_scan(args.url)
        return
    
    # Interactive mode
    while True:
        main_menu()
        choice = input(Fore.GREEN + "[?] Select option: ").lower().strip()
        
        if choice == '0':
            success("Thank you for using VulnScan Pro!")
            break
            
        elif choice == 'u':
            info("Update functionality would be implemented here")
            input(Fore.YELLOW + "[?] Press ENTER to continue...")
            
        elif choice == 'h':
            display_banner("Help & Documentation")
            print(Fore.WHITE + """
Quick Scan: Basic security headers and common vulnerabilities
Deep Scan: Comprehensive testing including business logic flaws
Custom Scan: Select specific modules to run
Business Logic: Test for IDOR, access control issues
API Security: Test API endpoints and authentication
            """)
            input(Fore.YELLOW + "[?] Press ENTER to continue...")
            
        elif choice in ['1', '2', '3', '4', '5']:
            target = input(Fore.BLUE + "[?] Enter target URL: ").strip()
            if not target:
                error("No URL provided!")
                continue
                
            target = target if target.startswith('http') else 'http://' + target
            
            # Initialize scan results for new target
            scan_results.update({
                "target": target,
                "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "vulnerabilities": [],
                "logical_flaws": [],
                "security_headers": [],
                "sensitive_files": [],
                "ssl_info": {},
                "risk_level": "Low",
                "scan_depth": "Standard"
            })
            
            if choice == '1':
                quick_scan(target)
            elif choice == '2':
                deep_scan(target)
            elif choice == '3':
                custom_scan(target)
            elif choice == '4':
                display_banner("Business Logic Testing")
                scan_business_logic(target)
                generate_report()
            elif choice == '5':
                display_banner("API Security Testing")
                scan_api_security(target)
                generate_report()
                
            input(Fore.YELLOW + "\n[?] Press ENTER to continue...")
            
        else:
            error("Invalid option!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        error("\nScan interrupted by user!")
        sys.exit(1)