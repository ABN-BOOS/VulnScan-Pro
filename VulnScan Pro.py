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
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------------------------------------------
# Advanced Logo
# ------------------------------------------------------------

def display_logo():
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
    print(Fore.GREEN + "           Advanced Security Research Scanner v3.0")
    print(Fore.WHITE + "           " + "=" * 60)
    print()

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
# Advanced Results Storage
# ------------------------------------------------------------

scan_results = {
    "target": "",
    "scan_date": "",
    "vulnerabilities": [],
    "logical_flaws": [],
    "security_headers": [],
    "sensitive_files": [],
    "ssl_info": {},
    "cms_detected": "",
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

# ------------------------------------------------------------
# Advanced Request Engine
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
        print(Fore.RED + f"[!] Request failed: {e}")
        return None

# ------------------------------------------------------------
# Advanced Logical Flaw Detection
# ------------------------------------------------------------

def scan_business_logic(url):
    """Scan for business logic vulnerabilities"""
    print(Fore.CYAN + "\n[+] Scanning for Business Logic Flaws...\n")
    
    # Test for IDOR (Insecure Direct Object Reference)
    test_idor(url)
    
    # Test for Broken Access Control
    test_access_control(url)
    
    # Test for Price Manipulation
    test_price_manipulation(url)
    
    # Test for Workflow Bypasses
    test_workflow_bypass(url)

def test_idor(base_url):
    """Test for Insecure Direct Object References"""
    print(Fore.YELLOW + "[*] Testing IDOR vulnerabilities...")
    
    test_patterns = [
        "/user/1/profile", "/admin/1", "/order/100", "/invoice/1",
        "/api/users/1", "/download/1", "/file/1", "/message/1"
    ]
    
    for pattern in test_patterns:
        test_url = base_url.rstrip("/") + pattern
        response = advanced_get(test_url)
        
        if response and response.status_code == 200:
            # Check if sensitive data is accessible
            sensitive_keywords = ["password", "email", "address", "phone", "credit", "ssn"]
            content_lower = response.text.lower()
            
            for keyword in sensitive_keywords:
                if keyword in content_lower:
                    add_vulnerability(
                        "Insecure Direct Object Reference (IDOR)",
                        "High",
                        f"Direct object access possible at {test_url} with sensitive data exposure",
                        "High",
                        "Implement proper authorization checks and use indirect object references",
                        "Logical",
                        "Medium"
                    )
                    print(Fore.RED + f"[High] Potential IDOR at: {test_url}")
                    break

def test_access_control(base_url):
    """Test for broken access control"""
    print(Fore.YELLOW + "[*] Testing Access Control...")
    
    admin_paths = [
        "/admin", "/administrator", "/wp-admin", "/dashboard",
        "/console", "/webadmin", "/management"
    ]
    
    for path in admin_paths:
        test_url = base_url.rstrip("/") + path
        response = advanced_get(test_url)
        
        if response and response.status_code == 200:
            # Check if admin panel is publicly accessible
            if any(keyword in response.text.lower() for keyword in ["login", "admin", "dashboard", "panel"]):
                add_vulnerability(
                    "Public Admin Panel Access",
                    "High",
                    f"Admin panel accessible without authentication: {test_url}",
                    "High",
                    "Restrict access to admin panels using IP whitelisting or proper authentication",
                    "Logical",
                    "High"
                )
                print(Fore.RED + f"[Critical] Public admin panel: {test_url}")

def test_price_manipulation(base_url):
    """Test for price manipulation vulnerabilities"""
    print(Fore.YELLOW + "[*] Testing Price Manipulation...")
    
    # Look for forms with price fields
    response = advanced_get(base_url)
    if response:
        price_patterns = [
            r'name=["\']price["\']',
            r'name=["\']amount["\']',
            r'name=["\']total["\']',
            r'name=["\']cost["\']'
        ]
        
        for pattern in price_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                add_vulnerability(
                    "Potential Price Manipulation",
                    "High",
                    "Price-related parameters found in forms - client-side validation only",
                    "Medium",
                    "Implement server-side price validation and use checksums",
                    "Logical",
                    "Low"
                )
                print(Fore.YELLOW + "[Medium] Price parameters detected - manual review recommended")

def test_workflow_bypass(base_url):
    """Test for workflow bypass vulnerabilities"""
    print(Fore.YELLOW + "[*] Testing Workflow Bypasses...")
    
    # Test common workflow endpoints
    workflow_endpoints = [
        "/checkout/confirm", "/payment/process", "/order/complete",
        "/api/order/finalize", "/cart/checkout"
    ]
    
    for endpoint in workflow_endpoints:
        test_url = base_url.rstrip("/") + endpoint
        response = advanced_get(test_url)
        
        if response and response.status_code == 200:
            add_vulnerability(
                "Potential Workflow Bypass",
                "Medium",
                f"Workflow endpoint accessible without proper validation: {test_url}",
                "Medium",
                "Implement proper state management and workflow validation",
                "Logical",
                "Low"
            )
            print(Fore.YELLOW + f"[Medium] Workflow endpoint accessible: {test_url}")

# ------------------------------------------------------------
# Advanced Input Validation Testing
# ------------------------------------------------------------

def scan_input_validation(url):
    """Test for input validation flaws"""
    print(Fore.CYAN + "\n[+] Testing Input Validation...\n")
    
    # Test parameters in URL
    test_parameters(url)
    
    # Test for SQL Injection vectors
    test_advanced_sqli(url)
    
    # Test for XSS vectors
    test_advanced_xss(url)

def test_parameters(base_url):
    """Test URL parameters for injection points"""
    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query)
    
    if query_params:
        for param in query_params.keys():
            # Test for basic injection patterns
            test_url = base_url + f"&{param}=test'OR'1'='1"
            response = advanced_get(test_url)
            
            if response:
                # Check for error-based SQL injection indicators
                error_indicators = [
                    "sql", "syntax", "mysql", "ora-", "postgresql"
                ]
                
                for error in error_indicators:
                    if error in response.text.lower():
                        add_vulnerability(
                            "Error-Based SQL Injection Vector",
                            "High",
                            f"Parameter '{param}' shows SQL error messages",
                            "High",
                            "Implement proper input validation and use parameterized queries",
                            "Input Validation",
                            "High"
                        )
                        print(Fore.RED + f"[High] SQL Injection vector in parameter: {param}")

def test_advanced_sqli(base_url):
    """Advanced SQL Injection detection"""
    print(Fore.YELLOW + "[*] Testing Advanced SQL Injection...")
    
    # Time-based SQL injection test
    payloads = [
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--",
        "' OR IF(1=1,SLEEP(5),0)--"
    ]
    
    for payload in payloads:
        test_url = base_url + payload
        start_time = time.time()
        response = advanced_get(test_url)
        end_time = time.time()
        
        if response and (end_time - start_time) > 4:
            add_vulnerability(
                "Time-Based SQL Injection",
                "Critical",
                f"Time delay detected with payload: {payload}",
                "High",
                "Use parameterized queries and input validation",
                "SQL Injection",
                "Medium"
            )
            print(Fore.RED + f"[Critical] Time-based SQLi detected!")

def test_advanced_xss(base_url):
    """Advanced XSS detection"""
    print(Fore.YELLOW + "[*] Testing Advanced XSS Vectors...")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "onmouseover=alert('XSS')"
    ]
    
    for payload in xss_payloads:
        test_url = base_url + payload
        response = advanced_get(test_url)
        
        if response and payload in response.text:
            add_vulnerability(
                "Reflected XSS Vulnerability",
                "High",
                f"XSS payload reflected without sanitization: {payload}",
                "High",
                "Implement proper output encoding and input validation",
                "XSS",
                "High"
            )
            print(Fore.RED + f"[High] Reflected XSS detected with payload: {payload}")

# ------------------------------------------------------------
# API Security Testing
# ------------------------------------------------------------

def scan_api_security(url):
    """Test API endpoints for security issues"""
    print(Fore.CYAN + "\n[+] Testing API Security...\n")
    
    api_endpoints = [
        "/api/users", "/api/data", "/api/admin", "/api/config",
        "/graphql", "/rest/v1", "/api/v1/users", "/api/v1/data"
    ]
    
    for endpoint in api_endpoints:
        test_url = url.rstrip("/") + endpoint
        
        # Test without authentication
        response = advanced_get(test_url)
        if response:
            analyze_api_response(test_url, response)
        
        # Test with different HTTP methods
        test_http_methods(test_url)

def analyze_api_response(url, response):
    """Analyze API responses for security issues"""
    
    # Check for information disclosure
    if response.status_code == 200:
        sensitive_info = ["password", "api_key", "token", "secret", "private"]
        content_lower = response.text.lower()
        
        for info in sensitive_info:
            if info in content_lower:
                add_vulnerability(
                    "API Information Disclosure",
                    "High",
                    f"Sensitive information exposed in API response: {url}",
                    "High",
                    "Implement proper data filtering and access controls",
                    "API Security",
                    "High"
                )
                print(Fore.RED + f"[High] API info disclosure: {url}")

def test_http_methods(url):
    """Test different HTTP methods on API endpoints"""
    methods = ['PUT', 'DELETE', 'PATCH', 'OPTIONS']
    
    for method in methods:
        try:
            response = requests.request(
                method, 
                url, 
                timeout=10, 
                verify=False,
                headers={'User-Agent': random.choice(CONFIG['user_agents'])}
            )
            
            if response.status_code in [200, 201, 204]:
                add_vulnerability(
                    "Unrestricted HTTP Methods",
                    "Medium",
                    f"HTTP {method} method allowed without proper authorization: {url}",
                    "Medium",
                    "Restrict HTTP methods based on user roles and requirements",
                    "API Security",
                    "Medium"
                )
                print(Fore.YELLOW + f"[Medium] {method} method allowed: {url}")
                
        except:
            pass

# ------------------------------------------------------------
# Enhanced Existing Scanners (Updated)
# ------------------------------------------------------------

def scan_security_headers(url):
    print(Fore.CYAN + "\n[+] Scanning Security Headers...\n")
    r = advanced_get(url)
    if not r:
        return

    headers_checks = {
        "Content-Security-Policy": {"risk": "High", "desc": "CSP missing - XSS protection"},
        "X-Frame-Options": {"risk": "Medium", "desc": "Clickjacking protection missing"},
        "Strict-Transport-Security": {"risk": "High", "desc": "HSTS missing - SSL stripping"}
    }

    for header, info in headers_checks.items():
        if header not in r.headers:
            add_vulnerability(
                f"Missing {header}",
                info["risk"],
                info["desc"],
                info["risk"],
                f"Implement {header} header",
                "Headers",
                "High"
            )

# ------------------------------------------------------------
# Comprehensive Reporting
# ------------------------------------------------------------

def generate_advanced_report():
    """Generate professional security research report"""
    print(Fore.CYAN + "\n" + "="*70)
    print(Fore.CYAN + "           VULNSCAN PRO - ADVANCED SECURITY REPORT")
    print(Fore.CYAN + "="*70)
    
    # Vulnerability Statistics
    vuln_types = {}
    for vuln in scan_results["vulnerabilities"]:
        vuln_type = vuln["type"]
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    print(Fore.YELLOW + "\nVULNERABILITY DISTRIBUTION:")
    for vuln_type, count in vuln_types.items():
        print(Fore.WHITE + f"  {vuln_type}: {count}")
    
    # Logical Flaws Summary
    if scan_results["logical_flaws"]:
        print(Fore.RED + "\nCRITICAL LOGICAL FLAWS:")
        for flaw in scan_results["logical_flaws"]:
            print(Fore.WHITE + f"  • {flaw['title']} - {flaw['risk_level']} Risk")

def advanced_full_scan(url):
    """Perform comprehensive advanced scan"""
    global scan_results
    scan_results = {
        "target": url,
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": [],
        "logical_flaws": [],
        "security_headers": [],
        "sensitive_files": [],
        "ssl_info": {},
        "cms_detected": "",
        "risk_level": "Low",
        "scan_depth": "Advanced"
    }
    
    print(Fore.GREEN + f"\n[*] Starting Advanced Security Research Scan: {url}")
    
    # Run all advanced scanners
    scan_security_headers(url)
    scan_business_logic(url)
    scan_input_validation(url)
    scan_api_security(url)
    
    # Generate comprehensive report
    generate_advanced_report()

# ------------------------------------------------------------
# Advanced Menu System
# ------------------------------------------------------------

def advanced_menu():
    print(Fore.CYAN + """
======================================================================
 VULNSCAN PRO - ADVANCED SECURITY RESEARCH SCANNER
======================================================================
""" + Fore.WHITE + """
1.  Business Logic Flaw Scanner
2.  Input Validation Testing
3.  API Security Assessment
4.  Advanced SQL Injection Detection
5.  Advanced XSS Detection
6.  IDOR Vulnerability Scanner
7.  Access Control Testing
8.  COMPREHENSIVE ADVANCED SCAN
9.  Generate Research Report
10. Exit
""")

def main():
    display_logo()
    
    while True:
        advanced_menu()
        choice = input(Fore.YELLOW + "\n[?] Select research option: ").strip()

        if choice == "10":
            print(Fore.GREEN + "[+] Thank you for using VulnScan Pro!")
            break

        target = input(Fore.BLUE + "[?] Research Target URL: ").strip()
        if not target:
            continue
            
        target = target if target.startswith("http") else "http://" + target

        if choice == "1": scan_business_logic(target)
        elif choice == "2": scan_input_validation(target)
        elif choice == "3": scan_api_security(target)
        elif choice == "4": test_advanced_sqli(target)
        elif choice == "5": test_advanced_xss(target)
        elif choice == "6": test_idor(target)
        elif choice == "7": test_access_control(target)
        elif choice == "8": advanced_full_scan(target)
        elif choice == "9": generate_advanced_report()
        else:
            print(Fore.RED + "[!] Invalid option.")

if __name__ == "__main__":
    main()