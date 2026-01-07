#!/usr/bin/env python3
"""
Professional Advanced Web Vulnerability Scanner
Vulnerability Detection with High Accuracy - Low False Positives
Developed for Authorized Security Testing Only
"""

import requests
import urllib.parse
import time
from datetime import datetime
import json
import re
import hashlib
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedSecurityScanner:
    def __init__(self, timeout=10, max_threads=5):
        self.results = {
            'target': '',
            'scan_time': '',
            'confirmed_vulnerabilities': [],
            'false_positives': [],
            'statistics': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        self.session = requests.Session()
        self.timeout = timeout
        self.max_threads = max_threads
        self.baseline_response = None
        self.baseline_hash = None
        
        # Unique session identifier to avoid false positives
        self.session_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def display_banner(self):
        """Display professional scanner banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██╗████████╗██╗   ██╗           ║
║    ██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██║╚══██╔══╝╚██╗ ██╔╝           ║
║    ███████╗██║     ██║   ██║██║   ██║█████╗  ██║   ██║    ╚████╔╝            ║
║    ╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██║   ██║     ╚██╔╝             ║
║    ███████║╚██████╗╚██████╔╝ ╚████╔╝ ██║     ██║   ██║      ██║              ║
║    ╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚═╝     ╚═╝   ╚═╝      ╚═╝              ║
║                                                                              ║
║          ADVANCED SECURITY SCANNER - HIGH ACCURACY DETECTION v4.0            ║
║                 Real Vulnerability Detection - Low False Positives           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def log_message(self, message, level="INFO"):
        """Professional logging system"""
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
        
        icons = {
            "INFO": "ℹ️",
            "SUCCESS": "✅",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "CRITICAL": "🚨",
            "DEBUG": "🔍"
        }
        
        print(f"{colors.get(level, '')}{icons.get(level, '')} [{timestamp}] {message}{reset}")

    def get_response_hash(self, text):
        """Generate hash for response comparison"""
        return hashlib.md5(text.encode()).hexdigest()

    def establish_baseline(self, url):
        """Establish baseline response for accurate comparison"""
        self.log_message("Establishing baseline response...", "INFO")
        
        # Get multiple baseline samples
        baseline_responses = []
        for _ in range(3):
            response = self.send_request(url)
            if response:
                baseline_responses.append(response.text)
            time.sleep(0.5)
        
        if baseline_responses:
            # Use the most common response as baseline
            from collections import Counter
            baseline_counter = Counter(baseline_responses)
            self.baseline_response = baseline_counter.most_common(1)[0][0]
            self.baseline_hash = self.get_response_hash(self.baseline_response)
            self.log_message(f"Baseline established (Hash: {self.baseline_hash[:8]})", "SUCCESS")
        else:
            self.log_message("Failed to establish baseline", "ERROR")

    def send_request(self, url, method="GET", data=None):
        """Send HTTP request with comprehensive error handling"""
        try:
            if method.upper() == "GET":
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
            return response
        except requests.exceptions.RequestException as e:
            self.log_message(f"Request failed: {str(e)[:50]}", "DEBUG")
            return None

    def generate_unique_payload(self, base_command):
        """Generate unique payload to avoid false positives"""
        unique_id = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        return f"{base_command}_{self.session_id}_{unique_id}"

    def advanced_rce_detection(self, base_url, parameters):
        """Advanced RCE detection with multiple verification layers"""
        self.log_message("Starting advanced RCE detection...", "INFO")
        
        confirmed_vulns = []
        
        # Layer 1: Basic command execution test
        basic_tests = self.test_basic_rce(base_url, parameters)
        
        # Layer 2: Advanced verification for positive results
        for vuln in basic_tests:
            if self.verify_rce_advanced(base_url, vuln):
                confirmed_vulns.append(vuln)
        
        return confirmed_vulns

    def test_basic_rce(self, base_url, parameters):
        """Basic RCE tests with unique payloads"""
        vulnerabilities = []
        
        test_cases = [
            {
                'name': 'UNIX_COMMAND_EXECUTION',
                'base_payload': 'echo',
                'verification': self.verify_command_output,
                'severity': 'CRITICAL'
            },
            {
                'name': 'PYTHON_CODE_EXECUTION',
                'base_payload': "__import__('os').popen('echo",
                'verification': self.verify_python_execution,
                'severity': 'CRITICAL'
            },
            {
                'name': 'SYSTEM_COMMAND_CHAINING',
                'base_payload': 'ls /tmp && echo',
                'verification': self.verify_command_chaining,
                'severity': 'CRITICAL'
            }
        ]
        
        for param in parameters:
            for test_case in test_cases:
                # Generate unique payload
                unique_marker = self.generate_unique_payload('SEC_TEST')
                full_payload = f"{test_case['base_payload']} {unique_marker}"
                
                test_url = f"{base_url}?{param}={urllib.parse.quote(full_payload)}"
                response = self.send_request(test_url)
                
                if response and response.status_code == 200:
                    if unique_marker in response.text:
                        # Initial detection
                        vuln = {
                            'type': test_case['name'],
                            'severity': test_case['severity'],
                            'parameter': param,
                            'initial_payload': full_payload,
                            'unique_marker': unique_marker,
                            'response_code': response.status_code,
                            'response_sample': response.text[:200]
                        }
                        vulnerabilities.append(vuln)
        
        return vulnerabilities

    def verify_rce_advanced(self, base_url, initial_vuln):
        """Advanced verification with multiple techniques"""
        param = initial_vuln['parameter']
        
        verification_tests = [
            self.test_different_commands,
            self.test_command_chaining,
            self.test_output_redirection,
            self.test_system_info_commands
        ]
        
        passed_tests = 0
        total_tests = len(verification_tests)
        
        for test_func in verification_tests:
            if test_func(base_url, param):
                passed_tests += 1
        
        # Require at least 2 different verification tests to pass
        return passed_tests >= 2

    def test_different_commands(self, base_url, param):
        """Test with completely different commands"""
        commands = [
            f"pwd_{self.session_id}",
            f"whoami_{self.session_id}",
            f"date_{self.session_id}"
        ]
        
        passed = 0
        for cmd in commands:
            test_url = f"{base_url}?{param}={urllib.parse.quote('echo ' + cmd)}"
            response = self.send_request(test_url)
            if response and cmd in response.text:
                passed += 1
        
        return passed >= 2  # At least 2 different commands must work

    def test_command_chaining(self, base_url, param):
        """Test command chaining (indicator of real RCE)"""
        chain_tests = [
            f"echo TEST1_{self.session_id} && echo TEST2_{self.session_id}",
            f"ls /tmp | grep test || echo NOTFOUND_{self.session_id}"
        ]
        
        for chain_cmd in chain_tests:
            test_url = f"{base_url}?{param}={urllib.parse.quote(chain_cmd)}"
            response = self.send_request(test_url)
            if response:
                # Check for both parts of the chain
                parts = chain_cmd.split('&&') if '&&' in chain_cmd else chain_cmd.split('||')
                expected_parts = [p.strip() for p in parts if self.session_id in p]
                
                if all(part in response.text for part in expected_parts):
                    return True
        
        return False

    def test_output_redirection(self, base_url, param):
        """Test output redirection (strong indicator of shell access)"""
        unique_file = f"/tmp/test_{self.session_id}.txt"
        cleanup_cmd = f"rm -f {unique_file}"
        
        # Try to create file
        create_cmd = f"echo REDIRECT_TEST_{self.session_id} > {unique_file}"
        test_url = f"{base_url}?{param}={urllib.parse.quote(create_cmd)}"
        self.send_request(test_url)
        time.sleep(0.5)
        
        # Try to read file
        read_cmd = f"cat {unique_file}"
        test_url = f"{base_url}?{param}={urllib.parse.quote(read_cmd)}"
        response = self.send_request(test_url)
        
        # Cleanup
        self.send_request(f"{base_url}?{param}={urllib.parse.quote(cleanup_cmd)}")
        
        if response and f"REDIRECT_TEST_{self.session_id}" in response.text:
            return True
        
        return False

    def test_system_info_commands(self, base_url, param):
        """Test system information commands"""
        info_commands = [
            ("uname -a", ["Linux", "Darwin", "Windows"]),
            ("cat /etc/issue", ["Ubuntu", "Debian", "CentOS"]),
            ("systeminfo", ["Host Name", "OS Name", "OS Version"])
        ]
        
        for cmd, indicators in info_commands:
            test_url = f"{base_url}?{param}={urllib.parse.quote(cmd)}"
            response = self.send_request(test_url)
            
            if response and any(indicator in response.text for indicator in indicators):
                # Also check that this wasn't in baseline
                if not any(indicator in self.baseline_response for indicator in indicators):
                    return True
        
        return False

    def detect_sql_injection(self, base_url, parameters):
        """Advanced SQL injection detection"""
        self.log_message("Starting SQL injection detection...", "INFO")
        
        confirmed_sqli = []
        
        # Test for different SQL injection types
        injection_types = {
            'ERROR_BASED': ["'", "\"", "' OR '1'='1"],
            'TIME_BASED': ["' OR SLEEP(5)--", "' WAITFOR DELAY '0:0:5'--"],
            'BOOLEAN_BASED': ["' AND 1=1--", "' AND 1=2--"]
        }
        
        for param in parameters:
            for inj_type, payloads in injection_types.items():
                for payload in payloads:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    
                    # Time-based detection
                    start_time = time.time()
                    response = self.send_request(test_url)
                    elapsed = time.time() - start_time
                    
                    if response:
                        # Error-based detection
                        sql_errors = [
                            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                            "SQLite", "Microsoft OLE DB", "Unclosed quotation"
                        ]
                        
                        if any(error.lower() in response.text.lower() for error in sql_errors):
                            confirmed_sqli.append({
                                'type': 'SQL_INJECTION',
                                'subtype': inj_type,
                                'severity': 'CRITICAL',
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'SQL error in response',
                                'response_code': response.status_code
                            })
                            break
                        
                        # Time-based detection
                        elif elapsed > 4:
                            confirmed_sqli.append({
                                'type': 'SQL_INJECTION',
                                'subtype': inj_type,
                                'severity': 'HIGH',
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'Time delay detected: {elapsed:.2f}s',
                                'response_code': response.status_code
                            })
                            break
        
        return confirmed_sqli

    def detect_xss_vulnerabilities(self, base_url, parameters):
        """Advanced XSS detection"""
        self.log_message("Starting XSS detection...", "INFO")
        
        xss_vulns = []
        
        # Generate unique XSS payload
        unique_alert = f"XSS_{self.session_id}_ALERT"
        xss_payloads = [
            f"<script>alert('{unique_alert}')</script>",
            f"<img src=x onerror=alert('{unique_alert}')>",
            f"javascript:alert('{unique_alert}')"
        ]
        
        for param in parameters:
            for payload in xss_payloads:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                response = self.send_request(test_url)
                
                if response and response.status_code == 200:
                    # Check if payload is reflected without encoding
                    if payload in response.text:
                        # Additional check: verify it's not in a comment
                        context = self.get_reflection_context(response.text, payload)
                        if context != 'comment':
                            xss_vulns.append({
                                'type': 'CROSS_SITE_SCRIPTING',
                                'severity': 'MEDIUM',
                                'parameter': param,
                                'payload': payload,
                                'evidence': 'XSS payload reflected without sanitization',
                                'context': context,
                                'response_code': response.status_code
                            })
        
        return xss_vulns

    def get_reflection_context(self, html, payload):
        """Get context where payload is reflected"""
        if f"<!--{payload}" in html or f"{payload}-->" in html:
            return 'comment'
        elif f"<script>{payload}" in html or f"{payload}</script>" in html:
            return 'script'
        elif f"<style>{payload}" in html or f"{payload}</style>" in html:
            return 'style'
        elif f"<{payload}" in html or f"{payload}>" in html:
            return 'tag'
        else:
            return 'text'

    def comprehensive_scan(self, target_url):
        """Perform comprehensive security scan"""
        self.log_message(f"Starting comprehensive scan: {target_url}", "INFO")
        
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().isoformat()
        
        try:
            # Establish baseline
            self.establish_baseline(target_url)
            
            if not self.baseline_response:
                self.log_message("Target unavailable", "ERROR")
                return
            
            # Common parameters to test
            parameters = ['id', 'page', 'file', 'path', 'cmd', 'exec', 'action']
            
            # Run all detection modules
            with ThreadPoolExecutor(max_workers=3) as executor:
                scan_tasks = [
                    executor.submit(self.advanced_rce_detection, target_url, parameters),
                    executor.submit(self.detect_sql_injection, target_url, parameters),
                    executor.submit(self.detect_xss_vulnerabilities, target_url, parameters)
                ]
                
                for task in as_completed(scan_tasks):
                    try:
                        vulnerabilities = task.result()
                        self.results['confirmed_vulnerabilities'].extend(vulnerabilities)
                    except Exception as e:
                        self.log_message(f"Scan task failed: {e}", "ERROR")
            
            # Generate statistics
            self.generate_statistics()
            
        except Exception as e:
            self.log_message(f"Scan failed: {e}", "ERROR")

    def generate_statistics(self):
        """Generate scan statistics"""
        for vuln in self.results['confirmed_vulnerabilities']:
            level = vuln['severity'].upper()
            if level == 'CRITICAL':
                self.results['statistics']['critical'] += 1
            elif level == 'HIGH':
                self.results['statistics']['high'] += 1
            elif level == 'MEDIUM':
                self.results['statistics']['medium'] += 1
            elif level == 'LOW':
                self.results['statistics']['low'] += 1

    def generate_report(self):
        """Generate professional scan report"""
        print("\n" + "="*80)
        print("🔒 SECURITY ASSESSMENT REPORT - HIGH CONFIDENCE FINDINGS")
        print("="*80)
        
        print(f"\n🎯 TARGET: {self.results['target']}")
        print(f"📅 SCAN TIME: {self.results['scan_time']}")
        print(f"🔢 BASELINE HASH: {self.baseline_hash[:16] if self.baseline_hash else 'N/A'}")
        
        stats = self.results['statistics']
        print(f"\n📊 VULNERABILITY STATISTICS:")
        print(f"   🚨 CRITICAL: {stats['critical']}")
        print(f"   ⚠️  HIGH: {stats['high']}")
        print(f"   🔶 MEDIUM: {stats['medium']}")
        print(f"   ℹ️  LOW: {stats['low']}")
        print(f"   📈 TOTAL CONFIRMED: {sum(stats.values())}")
        
        if not self.results['confirmed_vulnerabilities']:
            self.log_message("No confirmed vulnerabilities found!", "SUCCESS")
            print("\n✅ Target appears to be secure against tested vulnerabilities.")
            return
        
        print("\n" + "="*80)
        print("🔍 CONFIRMED VULNERABILITIES")
        print("="*80)
        
        # Group by severity
        vulns_by_severity = {}
        for vuln in self.results['confirmed_vulnerabilities']:
            severity = vuln['severity']
            if severity not in vulns_by_severity:
                vulns_by_severity[severity] = []
            vulns_by_severity[severity].append(vuln)
        
        # Display in severity order
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        for severity in severity_order:
            if severity in vulns_by_severity:
                color = {
                    'CRITICAL': '\033[91m',
                    'HIGH': '\033[93m',
                    'MEDIUM': '\033[94m',
                    'LOW': '\033[92m'
                }.get(severity, '')
                
                print(f"\n{color}▌ {severITY} SEVERITY ({len(vulns_by_severity[severity])} findings)\033[0m")
                print("-" * 60)
                
                for i, vuln in enumerate(vulns_by_severity[severity], 1):
                    print(f"\n{color}[{i}] {vuln['type']}\033[0m")
                    print(f"   • Parameter: {vuln.get('parameter', 'N/A')}")
                    print(f"   • Evidence: {vuln.get('evidence', 'N/A')}")
                    if 'payload' in vuln:
                        print(f"   • Payload: {vuln['payload'][:80]}...")
                    if 'context' in vuln:
                        print(f"   • Context: {vuln['context']}")
                    print(f"   • Response: HTTP {vuln.get('response_code', 'N/A')}")

    def save_report(self, filename=None):
        """Save report to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_scan_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            self.log_message(f"Report saved to: {filename}", "SUCCESS")
        except Exception as e:
            self.log_message(f"Failed to save report: {e}", "ERROR")

def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced Security Scanner - High Accuracy Detection')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-th', '--threads', type=int, default=5, help='Concurrent threads')
    parser.add_argument('-o', '--output', help='Output filename')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = AdvancedSecurityScanner(timeout=args.timeout, max_threads=args.threads)
    scanner.display_banner()
    
    print("\n🔐 PROFESSIONAL SECURITY SCANNER - AUTHORIZED TESTING ONLY")
    print("⚠️  Use only on systems you own or have explicit permission to test\n")
    
    # Validate target URL
    target = args.target.strip()
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    try:
        # Start scan
        start_time = time.time()
        scanner.comprehensive_scan(target)
        scan_duration = time.time() - start_time
        
        # Generate report
        scanner.generate_report()
        
        print(f"\n⏱️  SCAN DURATION: {scan_duration:.2f} seconds")
        
        # Save report
        if args.output:
            scanner.save_report(args.output)
        elif input("\n💾 Save detailed report? (y/n): ").lower() == 'y':
            scanner.save_report()
            
    except KeyboardInterrupt:
        scanner.log_message("Scan interrupted by user", "WARNING")
    except Exception as e:
        scanner.log_message(f"Critical error: {e}", "ERROR")

if __name__ == "__main__":
    main()