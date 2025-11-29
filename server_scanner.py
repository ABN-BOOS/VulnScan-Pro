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
import re
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
        self.baseline_response = None
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

    def test_endpoint(self, url, method="GET", data=None, headers=None):
        """Test a single endpoint with error handling"""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
                
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True, headers=request_headers)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, headers=request_headers)
            return response
        except requests.exceptions.RequestException as e:
            self.print_status(f"Request failed for {url}: {str(e)}", "DEBUG")
            return None

    def get_baseline_response(self, url):
        """Get baseline response for comparison"""
        self.print_status("Getting baseline response...", "INFO")
        self.baseline_response = self.test_endpoint(url)
        return self.baseline_response

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
                content = response.text
                # Specific indicators for different file types
                indicators = {
                    "/etc/passwd": ["root:", "daemon:", "bin:", "sys:"],
                    "/etc/hosts": ["localhost", "127.0.0.1"],
                    "win.ini": ["[boot loader]", "[extensions]"],
                    "system.ini": ["[drivers]", "[386enh]"]
                }
                
                for file_type, file_indicators in indicators.items():
                    if file_type in payload:
                        if any(indicator in content for indicator in file_indicators):
                            return {
                                'type': 'LFI/Path Traversal',
                                'level': 'HIGH',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'File content found: {file_type}',
                                'response_code': response.status_code
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
                # Check if it's not an error page and has meaningful content
                content = response.text
                if (len(content) > 10 and 
                    not any(error in content.lower() for error in ['error', 'not found', '404', 'page not found']) and
                    not '<html>' in content.lower()[:500]):  # Not a regular HTML page
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
                content_lower = response.text.lower()
                
                # Strong indicators of admin panels
                strong_indicators = [
                    'admin', 'login', 'dashboard', 'control panel', 'cpanel',
                    'username', 'password', 'sign in', 'administrator',
                    'phpmyadmin', 'webmin', 'plesk'
                ]
                
                # Check for multiple strong indicators
                indicator_count = sum(1 for indicator in strong_indicators if indicator in content_lower)
                
                if (indicator_count >= 2 or 
                    response.status_code in [401, 403] or
                    any(word in title.lower() for word in ['admin', 'login', 'dashboard'])):
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
        """Intelligent RCE detection with reduced false positives"""
        self.print_status("Starting intelligent RCE scan...", "INFO")
        
        # Get baseline for comparison
        if not self.baseline_response:
            self.get_baseline_response(base_url)
        
        baseline_text = self.baseline_response.text.lower() if self.baseline_response else ""
        
        rce_test_cases = [
            # Command injection with unique expected outputs
            {
                'payload': "echo XRCE_TEST_123", 
                'expected': "XRCE_TEST_123",
                'type': 'unix_command'
            },
            {
                'payload': "whoami", 
                'expected': "root",  # Only if actually executed
                'type': 'command_execution',
                'conditional': True
            },
            # Template injection with mathematical operations
            {
                'payload': "{{7*7}}", 
                'expected': "49",
                'type': 'template_engine'
            },
            {
                'payload': "${7*7}", 
                'expected': "49", 
                'type': 'expression_language'
            },
            {
                'payload': "#{7*7}", 
                'expected': "49",
                'type': 'ruby_template'
            },
            # PHP code execution
            {
                'payload': "<?php echo 'XRCE_PHP_TEST'; ?>", 
                'expected': "XRCE_PHP_TEST",
                'type': 'php_code'
            },
            # Python code execution
            {
                'payload': "__import__('os').popen('echo XRCE_PYTHON_TEST').read()", 
                'expected': "XRCE_PYTHON_TEST",
                'type': 'python_code'
            }
        ]
        
        confirmed_vulnerabilities = []
        
        def test_rce_payload(param, test_case):
            try:
                # Test GET request
                test_url = f"{base_url}?{param}={urllib.parse.quote(test_case['payload'])}"
                response = self.test_endpoint(test_url)
                
                if response and response.status_code == 200:
                    response_text = response.text
                    
                    # Advanced detection logic
                    if self.is_confirmed_rce(response_text, test_case, baseline_text):
                        return {
                            'type': f'RCE - {test_case["type"]}',
                            'level': 'CRITICAL',
                            'parameter': param,
                            'payload': test_case['payload'],
                            'evidence': f"Confirmed command execution - Expected: {test_case['expected']}",
                            'response_code': response.status_code,
                            'confidence': 'HIGH'
                        }
                        
            except Exception as e:
                return None
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for test_case in rce_test_cases:
                    futures.append(executor.submit(test_rce_payload, param, test_case))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    confirmed_vulnerabilities.append(result)
                    self.print_status(f"✅ CONFIRMED RCE in {result['parameter']} - {result['type']}", "CRITICAL")
        
        return confirmed_vulnerabilities

    def is_confirmed_rce(self, response_text, test_case, baseline_text):
        """Intelligent RCE confirmation with multiple verification methods"""
        
        expected = test_case['expected']
        payload = test_case['payload']
        
        # Skip conditional tests that might cause false positives
        if test_case.get('conditional') and expected in baseline_text:
            return False
        
        # Method 1: Direct expected output match (not in baseline)
        if (expected in response_text and 
            expected not in baseline_text and
            expected not in payload):  # Avoid self-detection
            return True
        
        # Method 2: Mathematical operation result
        if test_case['type'] in ['template_engine', 'expression_language', 'ruby_template']:
            if expected in response_text and expected not in baseline_text:
                # Additional check: make sure it's not just the numbers 7*7 in the page
                if "7*7" not in response_text or response_text.count("49") > response_text.count("7*7"):
                    return True
        
        # Method 3: Payload reflection analysis
        if self.analyze_payload_reflection(response_text, payload, baseline_text):
            return True
        
        return False

    def analyze_payload_reflection(self, response_text, payload, baseline_text):
        """Analyze how payload is reflected in response"""
        # If payload is directly reflected without encoding, might be vulnerable
        if (payload in response_text and 
            payload not in baseline_text and
            len(payload) > 5):  # Avoid short payload false positives
            return True
        
        # Check for specific RCE patterns in response
        rce_patterns = [
            r'root:\w*:\d+:\d+:',
            r'www-data',
            r'administrator',
            r'command not found',
            r'permission denied',
            r'syntax error'
        ]
        
        for pattern in rce_patterns:
            if (re.search(pattern, response_text, re.IGNORECASE) and 
                not re.search(pattern, baseline_text, re.IGNORECASE)):
                return True
        
        return False

    def check_sql_injection(self, base_url, parameters):
        """Scan for SQL Injection vulnerabilities"""
        self.print_status("Scanning for SQL Injection vulnerabilities...", "INFO")
        
        sql_payloads = [
            "' OR '1'='1", 
            "' OR 1=1--", 
            "' UNION SELECT 1,2,3--",
            "' AND 1=1", 
            "' AND 1=2", 
            "' WAITFOR DELAY '0:0:5'--",
            "'; DROP TABLE users--", 
            "' OR SLEEP(5)--"
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
                
                # Error-based SQLi
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
                
                # Time-based SQLi
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
            "<script>alert('XSS_TEST')</script>",
            "\"><script>alert('XSS_TEST')</script>",
            "javascript:alert('XSS_TEST')",
            "<img src=x onerror=alert('XSS_TEST')>",
            "<svg onload=alert('XSS_TEST')>"
        ]
        
        xss_vulns = []
        
        def test_xss_payload(param, payload):
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            response = self.test_endpoint(test_url)
            
            if response and response.status_code == 200:
                # Check if payload is reflected without proper encoding
                if (payload in response.text or 
                    payload.replace('<', '&lt;') not in response.text):  # Not properly encoded
                    return {
                        'type': 'Cross-Site Scripting (XSS)',
                        'level': 'MEDIUM',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'XSS payload reflected in response without proper sanitization',
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
            # Get baseline response
            self.get_baseline_response(target_url)
            if not self.baseline_response:
                self.print_status("Target is not accessible", "ERROR")
                return
            
            self.print_status(f"Target responded with status code: {self.baseline_response.status_code}", "INFO")
            
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
                print(f"    Parameter: {vuln.get('parameter', 'N/A')}")
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