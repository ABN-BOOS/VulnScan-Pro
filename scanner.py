#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner
High Accuracy Detection - Same Output Format
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
import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedVulnScanner:
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
        self.session_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
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
║                ADVANCED VULNERABILITY SCANNER v4.0                          ║
║               High Accuracy - Low False Positives                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def print_status(self, message, level="INFO"):
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m",
            "DEBUG": "\033[90m"
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

    def get_baseline(self, url):
        """Get baseline response with unique marker check"""
        self.print_status("Getting baseline response...", "INFO")
        response = self.send_request(url)
        if response:
            self.baseline_response = response.text
            # Generate unique test marker
            self.unique_marker = f"VULN_TEST_{self.session_id}"
            
            # Check if marker already exists in baseline (avoid false positives)
            if self.unique_marker in self.baseline_response:
                self.unique_marker = f"SCAN_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
            
            return response
        return None

    def send_request(self, url, method="GET"):
        """Send HTTP request"""
        try:
            if method.upper() == "GET":
                return self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return None
        except:
            return None

    def check_rce_vulnerabilities(self, base_url, parameters):
        """Intelligent RCE detection with SAME OUTPUT FORMAT but higher accuracy"""
        self.print_status("Starting RCE vulnerability scan...", "INFO")
        
        vulnerabilities = []
        
        # Generate unique markers for each test type
        test_markers = {
            'COMMAND_EXECUTION': f'RCE_CMD_{self.session_id}',
            'UNIX_COMMAND': f'RCE_UNIX_{self.session_id}',
            'PYTHON_CODE': f'RCE_PYTHON_{self.session_id}',
            'EXPRESSION_LANGUAGE': f'RCE_EL_{self.session_id}',
            'TEMPLATE_ENGINE': f'RCE_TMPL_{self.session_id}',
            'RUBY_TEMPLATE': f'RCE_RUBY_{self.session_id}'
        }
        
        rce_test_cases = [
            {
                'type': 'COMMAND_EXECUTION',
                'payload': f"whoami",
                'expected': 'root',
                'marker': test_markers['COMMAND_EXECUTION'],
                'severity': 'CRITICAL'
            },
            {
                'type': 'UNIX_COMMAND',
                'payload': f"echo {test_markers['UNIX_COMMAND']}",
                'expected': test_markers['UNIX_COMMAND'],
                'marker': test_markers['UNIX_COMMAND'],
                'severity': 'CRITICAL'
            },
            {
                'type': 'EXPRESSION_LANGUAGE',
                'payload': "${7*7}",
                'expected': "49",
                'marker': test_markers['EXPRESSION_LANGUAGE'],
                'severity': 'CRITICAL'
            },
            {
                'type': 'TEMPLATE_ENGINE',
                'payload': "{{7*7}}",
                'expected': "49",
                'marker': test_markers['TEMPLATE_ENGINE'],
                'severity': 'CRITICAL'
            },
            {
                'type': 'RUBY_TEMPLATE',
                'payload': "#{7*7}",
                'expected': "49",
                'marker': test_markers['RUBY_TEMPLATE'],
                'severity': 'CRITICAL'
            },
            {
                'type': 'PYTHON_CODE',
                'payload': f"__import__('os').popen('echo {test_markers['PYTHON_CODE']}').read()",
                'expected': test_markers['PYTHON_CODE'],
                'marker': test_markers['PYTHON_CODE'],
                'severity': 'CRITICAL'
            }
        ]
        
        def test_parameter(param, test_case):
            # First test: basic payload
            test_url = f"{base_url}?{param}={urllib.parse.quote(test_case['payload'])}"
            response = self.send_request(test_url)
            
            if not response or response.status_code != 200:
                return None
            
            # Check if expected output is in response
            if test_case['expected'] in response.text:
                # VERIFICATION: Test with different but similar command
                if self.verify_rce(base_url, param, test_case):
                    return {
                        'type': f'RCE - {test_case["type"]}',
                        'level': test_case['severity'],
                        'parameter': param,
                        'payload': test_case['payload'],
                        'evidence': f"Confirmed command execution - Expected: {test_case['expected']}",
                        'response_code': response.status_code
                    }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for test_case in rce_test_cases:
                    futures.append(executor.submit(test_parameter, param, test_case))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    self.print_status(f"✅ CONFIRMED RCE in {result['parameter']} - {result['type']}", "CRITICAL")
        
        return vulnerabilities

    def verify_rce(self, base_url, param, test_case):
        """Verify RCE with secondary test to reduce false positives"""
        # Generate verification payload (different but similar)
        if 'whoami' in test_case['payload']:
            verify_payload = "id"
            verify_expected = "uid="
        elif 'echo' in test_case['payload']:
            verify_payload = f"echo RCE_VERIFY_{self.session_id}"
            verify_expected = f"RCE_VERIFY_{self.session_id}"
        elif '__import__' in test_case['payload']:
            verify_payload = f"__import__('os').popen('echo VERIFY_{self.session_id}').read()"
            verify_expected = f"VERIFY_{self.session_id}"
        else:
            verify_payload = test_case['payload'].replace('7', '8')
            verify_expected = "56" if "49" in test_case['expected'] else test_case['expected']
        
        # Run verification test
        verify_url = f"{base_url}?{param}={urllib.parse.quote(verify_payload)}"
        response = self.send_request(verify_url)
        
        if response and response.status_code == 200:
            # Check for expected output AND make sure it's not in baseline
            if (verify_expected in response.text and 
                verify_expected not in self.baseline_response):
                return True
        
        return False

    def check_sql_injection(self, base_url, parameters):
        """SQL Injection detection"""
        self.print_status("Scanning for SQL Injection...", "INFO")
        
        vulnerabilities = []
        
        sql_payloads = [
            {"payload": "' OR '1'='1", "type": "Classic"},
            {"payload": "' UNION SELECT 1,2,3--", "type": "Union"},
            {"payload": "' OR SLEEP(5)--", "type": "Time-based"},
            {"payload": "' AND 1=1", "type": "Boolean"},
            {"payload": "'; DROP TABLE users--", "type": "Destructive"}
        ]
        
        def test_sql(param, payload_info):
            payload = payload_info['payload']
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            
            # Time-based detection
            start_time = time.time()
            response = self.send_request(test_url)
            elapsed = time.time() - start_time
            
            if not response:
                return None
            
            # Check for SQL errors
            sql_errors = [
                "sql syntax", "mysql_fetch", "ora-", "microsoft odbc",
                "postgresql", "sqlite3", "warning:", "mysql error"
            ]
            
            content = response.text.lower()
            
            if any(error in content for error in sql_errors):
                return {
                    'type': 'SQL Injection',
                    'level': 'CRITICAL',
                    'parameter': param,
                    'payload': payload,
                    'evidence': 'SQL error found in response',
                    'response_code': response.status_code
                }
            elif elapsed > 4 and 'SLEEP' in payload:
                return {
                    'type': 'SQL Injection',
                    'level': 'HIGH',
                    'parameter': param,
                    'payload': payload,
                    'evidence': f'Time delay detected: {elapsed:.2f}s',
                    'response_code': response.status_code
                }
            
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for payload_info in sql_payloads:
                    futures.append(executor.submit(test_sql, param, payload_info))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
        
        return vulnerabilities

    def check_xss_vulnerabilities(self, base_url, parameters):
        """XSS detection"""
        self.print_status("Scanning for XSS vulnerabilities...", "INFO")
        
        vulnerabilities = []
        
        xss_payloads = [
            f"<script>alert('XSS_{self.session_id}')</script>",
            f"<img src=x onerror=alert('XSS_{self.session_id}')>",
            f"javascript:alert('XSS_{self.session_id}')"
        ]
        
        def test_xss(param, payload):
            test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            response = self.send_request(test_url)
            
            if response and response.status_code == 200:
                if payload in response.text:
                    # Verify it's not in a comment or encoded
                    if not self.is_safe_context(response.text, payload):
                        return {
                            'type': 'Cross-Site Scripting (XSS)',
                            'level': 'MEDIUM',
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'XSS payload reflected without sanitization',
                            'response_code': response.status_code
                        }
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for param in parameters:
                for payload in xss_payloads:
                    futures.append(executor.submit(test_xss, param, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
        
        return vulnerabilities

    def is_safe_context(self, html, payload):
        """Check if payload is in safe context (comment, encoded, etc.)"""
        # Check if in HTML comment
        if f"<!--{payload}" in html or f"{payload}-->" in html:
            return True
        
        # Check if encoded
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in html:
            return True
        
        return False

    def scan_website(self, target_url):
        """Main scan function - SAME OUTPUT FORMAT"""
        self.print_status(f"Starting scan for: {target_url}", "INFO")
        
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().isoformat()
        
        try:
            # Get baseline
            self.get_baseline(target_url)
            if not self.baseline_response:
                self.print_status("Target not accessible", "ERROR")
                return
            
            # Common parameters
            parameters = ['id', 'page', 'file', 'path', 'view', 'load', 'url', 'dir', 'cmd', 'exec']
            
            # Run all scans
            scan_methods = [
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
                        self.print_status(f"Scan failed: {str(e)}", "ERROR")
            
            # Calculate statistics
            self.calculate_statistics()
            
        except Exception as e:
            self.print_status(f"Scan failed: {str(e)}", "ERROR")

    def calculate_statistics(self):
        """Calculate stats - SAME FORMAT"""
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
        """Generate report - SAME EXACT OUTPUT FORMAT AS BEFORE"""
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
        
        # Group by type EXACTLY LIKE BEFORE
        vuln_by_type = {}
        for vuln in self.results['vulnerabilities']:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Display in order - SAME AS BEFORE
        for vuln_type, vulnerabilities in vuln_by_type.items():
            print(f"\n🎯 {vuln_type}")
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

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-th', '--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    scanner = AdvancedVulnScanner(timeout=args.timeout, threads=args.threads)
    scanner.display_banner()
    
    print("🔐 Advanced Web Vulnerability Scanner - High Accuracy Version")
    print("⚠️  Always obtain proper authorization before scanning\n")
    
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
        
        if args.output or input("\n💾 Save report? (y/n): ").lower() == 'y':
            filename = args.output if args.output else f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            scanner.save_report(filename)
            
    except KeyboardInterrupt:
        scanner.print_status("Scan interrupted", "ERROR")
    except Exception as e:
        scanner.print_status(f"Scan failed: {str(e)}", "ERROR")

if __name__ == "__main__":
    main()