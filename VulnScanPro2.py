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

# Suppress warnings
import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

init(autoreset=True)

# ------------------------------------------------------------
# Advanced Configuration
# ------------------------------------------------------------

CONFIG = {
    'timeout': 15,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
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
    def __init__(self, title, severity, description, risk_level, solution, vuln_type, confidence, url=""):
        self.id = len(scan_results["vulnerabilities"]) + 1
        self.title = title
        self.severity = severity
        self.description = description
        self.risk_level = risk_level
        self.solution = solution
        self.type = vuln_type
        self.confidence = confidence
        self.url = url
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_vulnerability(title, severity, description, risk_level, solution, vuln_type="Basic", confidence="Medium", url=""):
    """Add vulnerability to results"""
    vuln = Vulnerability(title, severity, description, risk_level, solution, vuln_type, confidence, url)
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
# Scanner Modules - IMPROVED WITH DETAILED REPORTING
# ------------------------------------------------------------

def scan_security_headers(url):
    """Scan security headers with detailed info"""
    info("Scanning Security Headers...")
    r = advanced_get(url)
    if not r:
        error("Failed to retrieve URL for header scanning")
        return

    headers_checks = {
        "Content-Security-Policy": {
            "risk": "High", 
            "desc": "Content Security Policy missing - allows XSS attacks",
            "solution": "Implement CSP header to prevent XSS"
        },
        "X-Frame-Options": {
            "risk": "Medium", 
            "desc": "Clickjacking protection missing",
            "solution": "Add X-Frame-Options: DENY or SAMEORIGIN"
        },
        "Strict-Transport-Security": {
            "risk": "High", 
            "desc": "HSTS missing - allows SSL stripping attacks",
            "solution": "Implement HSTS header: max-age=31536000; includeSubDomains"
        },
        "X-Content-Type-Options": {
            "risk": "Medium", 
            "desc": "MIME sniffing protection missing",
            "solution": "Add X-Content-Type-Options: nosniff"
        },
        "Referrer-Policy": {
            "risk": "Low",
            "desc": "Referrer policy not set",
            "solution": "Implement Referrer-Policy header"
        }
    }

    found_headers = 0
    missing_headers = 0

    for header, info_data in headers_checks.items():
        if header not in r.headers:
            add_vulnerability(
                f"Missing {header}",
                info_data["risk"],
                f"{info_data['desc']} - Header not present in response from {url}",
                info_data["risk"],
                info_data["solution"],
                "Security Headers",
                "High",
                url
            )
            missing_headers += 1
        else:
            success(f"✓ {header}: {r.headers[header]}")
            found_headers += 1

    result("Security Headers Found", f"{found_headers} headers")
    result("Security Headers Missing", f"{missing_headers} headers")

def scan_business_logic(url):
    """Scan for business logic vulnerabilities"""
    info("Scanning for Business Logic Flaws...")
    
    # Test for IDOR
    info("Testing IDOR vulnerabilities...")
    test_patterns = [
        "/user/1", "/admin/1", "/order/100", "/api/users/1",
        "/profile/1", "/account/1", "/settings/1", "/download/1"
    ]
    
    for pattern in test_patterns:
        test_url = url.rstrip("/") + pattern
        response = advanced_get(test_url)
        
        if response and response.status_code == 200:
            if any(keyword in response.text.lower() for keyword in ["password", "email", "admin", "private", "secret"]):
                add_vulnerability(
                    "Insecure Direct Object Reference (IDOR)",
                    "High",
                    f"Direct object access possible at: {test_url} - Sensitive data exposed",
                    "High",
                    "Implement proper authorization checks and use indirect object references",
                    "Logical",
                    "Medium",
                    test_url
                )

def scan_input_validation(url):
    """Test input validation with detailed reporting"""
    info("Testing Input Validation...")
    
    # Test for SQL Injection
    info("Testing SQL Injection vectors...")
    payloads = [
        "' OR '1'='1", 
        "'; DROP TABLE users--", 
        "' UNION SELECT 1,2,3--",
        "1' AND 1=1--",
        "1' AND SLEEP(5)--"
    ]
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        start_time = time.time()
        response = advanced_get(test_url)
        response_time = time.time() - start_time
        
        if response:
            # Check for error-based SQL injection
            if any(error in response.text.lower() for error in ["sql", "syntax", "mysql", "ora-", "postgresql"]):
                add_vulnerability(
                    "SQL Injection Vulnerability",
                    "Critical",
                    f"SQL injection detected at: {test_url} - Error messages revealed",
                    "High",
                    "Use parameterized queries and input validation, implement WAF",
                    "SQLi",
                    "High",
                    test_url
                )
            
            # Check for time-based SQL injection
            if response_time > 4:
                add_vulnerability(
                    "Time-Based SQL Injection",
                    "Critical", 
                    f"Time-based SQL injection detected at: {test_url} - Response delay: {response_time:.2f}s",
                    "High",
                    "Implement input validation and use prepared statements",
                    "SQLi",
                    "Medium",
                    test_url
                )

def scan_api_security(url):
    """Test API security with detailed endpoints"""
    info("Testing API Security...")
    
    api_endpoints = [
        "/api/users", "/api/data", "/graphql", "/rest/v1",
        "/api/v1/users", "/api/v1/data", "/api/admin", "/api/config",
        "/v1/api/users", "/v2/api/data", "/api/user/list", "/api/data/all"
    ]
    
    for endpoint in api_endpoints:
        test_url = url.rstrip("/") + endpoint
        response = advanced_get(test_url)
        if response and response.status_code == 200:
            # Check for sensitive data in API response
            sensitive_keywords = ["password", "api_key", "token", "secret", "private_key", "email"]
            if any(keyword in response.text.lower() for keyword in sensitive_keywords):
                add_vulnerability(
                    "API Information Disclosure",
                    "High",
                    f"Sensitive data exposed in API endpoint: {test_url}",
                    "High", 
                    "Implement proper data filtering, authentication and access controls",
                    "API Security",
                    "High",
                    test_url
                )
            else:
                add_vulnerability(
                    "Public API Access",
                    "Medium",
                    f"API endpoint publicly accessible without authentication: {test_url}",
                    "Medium",
                    "Implement API authentication, rate limiting and access controls",
                    "API Security", 
                    "Medium",
                    test_url
                )

def scan_sensitive_files(url):
    """Scan for sensitive files with detailed reporting"""
    info("Scanning for Sensitive Files...")
    
    files = [
        "/.env", "/.git/config", "/backup.zip", "/database.sql",
        "/wp-config.php", "/config.php", "/.htaccess", "/robots.txt",
        "/.DS_Store", "/web.config", "/phpinfo.php", "/test.php",
        "/backup.tar.gz", "/dump.sql", "/config.json", "/.aws/credentials",
        "/admin.php", "/debug.php", "/phpmyadmin/", "/.svn/entries",
        "/.env.example", "/config/database.php", "/.bash_history"
    ]
    
    for file in files:
        test_url = url.rstrip("/") + file
        response = advanced_get(test_url)
        if response and response.status_code == 200:
            file_size = len(response.content)
            add_vulnerability(
                "Sensitive File Exposure",
                "High",
                f"Sensitive file publicly accessible: {test_url} (Status: {response.status_code}, Size: {file_size} bytes)",
                "High",
                f"Restrict access to {file} using .htaccess, server configuration, or remove from web root",
                "Information Disclosure",
                "High",
                test_url
            )

def scan_ssl_configuration(url):
    """Scan SSL/TLS configuration"""
    info("Testing SSL/TLS Configuration...")
    
    try:
        hostname = urlparse(url).hostname
        if hostname:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        exp_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (exp_date - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            add_vulnerability(
                                "SSL Certificate Expiring Soon",
                                "Medium",
                                f"SSL certificate expires in {days_until_expiry} days on {exp_date.strftime('%Y-%m-%d')}",
                                "Medium",
                                "Renew SSL certificate before expiration",
                                "SSL Security",
                                "High",
                                f"https://{hostname}"
                            )
                    
                    # Check SSL/TLS version
                    ssl_version = ssock.version()
                    if ssl_version in ['TLSv1', 'TLSv1.1']:
                        add_vulnerability(
                            "Weak SSL/TLS Version",
                            "Medium",
                            f"Using deprecated SSL/TLS version: {ssl_version}",
                            "Medium",
                            "Upgrade to TLSv1.2 or higher",
                            "SSL Security",
                            "High",
                            f"https://{hostname}"
                        )
                    
                    success(f"SSL Version: {ssl_version}")
                    
    except Exception as e:
        warning(f"SSL scan failed: {e}")

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
    scan_ssl_configuration(url)
    
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
[6] SSL Configuration
[7] All Modules
""")
    
    choice = input(Fore.YELLOW + "[?] Select modules (comma separated): ")
    modules = choice.split(',')
    
    info(f"Starting custom scan: {url}")
    
    if '1' in modules or '7' in modules:
        scan_security_headers(url)
    if '2' in modules or '7' in modules:
        scan_business_logic(url)
    if '3' in modules or '7' in modules:
        scan_input_validation(url)
    if '4' in modules or '7' in modules:
        scan_api_security(url)
    if '5' in modules or '7' in modules:
        scan_sensitive_files(url)
    if '6' in modules or '7' in modules:
        scan_ssl_configuration(url)
    
    generate_report()

# ------------------------------------------------------------
# Enhanced Reporting
# ------------------------------------------------------------

def generate_report():
    """Generate scan report with full details"""
    print(Fore.CYAN + "\n" + "="*80)
    print(Fore.CYAN + "                 VULNSCAN PRO - DETAILED SCAN REPORT")
    print(Fore.CYAN + "="*80)
    
    total_vulns = len(scan_results["vulnerabilities"])
    high_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "High"])
    medium_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "Medium"])
    low_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "Low"])
    
    result("Target", scan_results["target"])
    result("Scan Date", scan_results["scan_date"]) 
    result("Scan Depth", scan_results["scan_depth"])
    result("Total Vulnerabilities", total_vulns)
    result("High Risk Vulnerabilities", high_vulns)
    result("Medium Risk Vulnerabilities", medium_vulns)
    result("Low Risk Vulnerabilities", low_vulns)
    
    # Calculate risk score
    risk_score = (high_vulns * 3) + (medium_vulns * 2) + (low_vulns * 1)
    if risk_score >= 10:
        risk_level = "Critical"
    elif risk_score >= 5:
        risk_level = "High" 
    elif risk_score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"
        
    result("Overall Risk Score", f"{risk_score} ({risk_level})")
    
    if total_vulns > 0:
        print(Fore.YELLOW + "\n🔍 DETAILED VULNERABILITY FINDINGS:")
        print(Fore.WHITE + "=" * 80)
        
        for i, vuln in enumerate(scan_results["vulnerabilities"], 1):
            color = Fore.RED if vuln["risk_level"] == "High" else Fore.YELLOW if vuln["risk_level"] == "Medium" else Fore.BLUE
            
            print(f"\n{color}📌 VULNERABILITY #{i}: {vuln['title']}")
            print(Fore.WHITE + f"   🔸 Risk Level: {vuln['risk_level']}")
            print(Fore.WHITE + f"   🔸 Type: {vuln['type']}")
            print(Fore.WHITE + f"   🔸 Confidence: {vuln['confidence']}")
            print(Fore.WHITE + f"   🔸 URL: {vuln.get('url', 'N/A')}")
            print(Fore.WHITE + f"   🔸 Description: {vuln['description']}")
            print(Fore.WHITE + f"   🔸 Solution: {vuln['solution']}")
            print(Fore.WHITE + f"   🔸 Timestamp: {vuln['timestamp']}")
            print(Fore.WHITE + "   " + "-" * 60)
    
    else:
        success("🎉 No vulnerabilities found! The target appears to be secure.")
    
    print(Fore.CYAN + "\n" + "="*80)
    
    # Save report to file
    save_report_to_file()

def save_report_to_file():
    """Save scan report to file"""
    try:
        filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("VULNSCAN PRO - SECURITY SCAN REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            for vuln in scan_results["vulnerabilities"]:
                f.write(f"VULNERABILITY: {vuln['title']}\n")
                f.write(f"Risk Level: {vuln['risk_level']}\n")
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                f.write(f"Description: {vuln['description']}\n")
                f.write(f"Solution: {vuln['solution']}\n")
                f.write(f"Timestamp: {vuln['timestamp']}\n")
                f.write("-" * 50 + "\n\n")
                
        success(f"Report saved to: {filename}")
    except Exception as e:
        error(f"Failed to save report: {e}")

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
    print(Fore.CYAN + "  [6]    Sensitive Files Scan")
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
    parser.add_argument('-c', '--custom', action='store_true', help='Custom scan')
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
        elif args.custom:
            custom_scan(args.url)
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
QUICK SCAN: Basic security headers, input validation, and sensitive files
DEEP SCAN: Comprehensive testing including business logic and API security  
CUSTOM SCAN: Select specific modules to run
BUSINESS LOGIC: Test for IDOR, access control issues
API SECURITY: Test API endpoints and authentication
SENSITIVE FILES: Scan for exposed configuration and backup files

FEATURES:
• Detailed vulnerability reporting with exact URLs
• Risk scoring and prioritization  
• Report export to text file
• No annoying SSL warnings
• Professional output formatting
            """)
            input(Fore.YELLOW + "[?] Press ENTER to continue...")
            
        elif choice in ['1', '2', '3', '4', '5', '6']:
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
                scan_results["scan_depth"] = "Quick"
                quick_scan(target)
            elif choice == '2':
                scan_results["scan_depth"] = "Deep"
                deep_scan(target)
            elif choice == '3':
                scan_results["scan_depth"] = "Custom"
                custom_scan(target)
            elif choice == '4':
                display_banner("Business Logic Testing")
                scan_results["scan_depth"] = "Business Logic"
                scan_business_logic(target)
                generate_report()
            elif choice == '5':
                display_banner("API Security Testing")
                scan_results["scan_depth"] = "API Security"
                scan_api_security(target)
                generate_report()
            elif choice == '6':
                display_banner("Sensitive Files Scan")
                scan_results["scan_depth"] = "Sensitive Files"
                scan_sensitive_files(target)
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