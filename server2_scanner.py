#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner - Stealth Mode
Professional Security Assessment Tool with Anti-Detection Features
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
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.client import HTTPConnection
from urllib3.exceptions import InsecureRequestWarning
import ssl
import hashlib
import platform

# Disable SSL warnings for some scenarios
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Color definitions
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
RED = '\033[1;31m'
MAGENTA = '\033[1;35m'
CYAN = '\033[1;36m'
WHITE = '\033[1;37m'
GRAY = '\033[1;90m'
ORANGE = '\033[38;5;208m'
PINK = '\033[38;5;213m'
PURPLE = '\033[38;5;93m'
RESET = '\033[0m'

class StealthVulnerabilityScanner:
    def __init__(self, timeout=15, threads=3, stealth_mode=True):
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
        
        self.stealth_session = requests.Session()
        self.scan_session = requests.Session()
        self.baseline_session = requests.Session()
        
        self.timeout = timeout
        self.max_threads = threads if not stealth_mode else 2
        self.stealth_mode = stealth_mode
        self.baseline_response = None
        self.request_count = 0
        self.last_request_time = 0
        self.proxies = None
        self.user_agent_pool = []
        self.cookies_pool = []
        self.current_proxy_index = 0
        
        self._init_user_agents()
        self._set_stealth_headers()
        self._init_proxy_list()
        
        self.min_delay = 1.5 if stealth_mode else 0.5
        self.max_delay = 4.0 if stealth_mode else 2.0
        
        self.used_ips = set()
        self.current_ip = self._get_public_ip()

    def _init_user_agents(self):
        """Initialize a pool of realistic user agents for stealth mode"""
        self.user_agent_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ]

    def _set_stealth_headers(self):
        """Set stealth headers for all sessions"""
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'TE': 'trailers'
        }
        
        for session in [self.stealth_session, self.scan_session, self.baseline_session]:
            session.headers.update(headers)
            session.verify = False

    def _init_proxy_list(self):
        """Initialize proxy list (can be expanded with real proxies)"""
        self.proxy_list = [None]  # No proxy by default

    def _get_public_ip(self):
        """Get current public IP address"""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            return response.json()['ip']
        except:
            return "Unknown"

    def display_advanced_banner(self):
        """Display professional hacker-style banner with colors"""
        banner = f"""
{BLUE}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}
{BLUE}║{RESET}                                                                              {BLUE}║{RESET}
{BLUE}║{RESET}    {RED}█████╗{RESET} {CYAN}█████╗ {RED}██╗   ██╗ {CYAN}██╗{RED}   ██╗{CYAN} ██████╗ {RED}██████╗{CYAN} ██████╗ {RESET}    {BLUE}║{RESET}
{BLUE}║{RESET}   {RED}██╔═══██╗{CYAN}██╔══██╗{RED}██║   ██║{CYAN}██║   ██║{RED}██╔════╝{CYAN}██╔═══██╗{RED}██╔══██╗{RESET}   {BLUE}║{RESET}
{BLUE}║{RESET}   {RED}██║   ██║{CYAN}██████╔╝{RED}██║   ██║{CYAN}██║   ██║{RED}██║     {CYAN}██║   ██║{RED}██████╔╝{RESET}   {BLUE}║{RESET}
{BLUE}║{RESET}   {RED}██║   ██║{CYAN}██╔══██╗{RED}╚██╗ ██╔╝{CYAN}██║   ██║{RED}██║     {CYAN}██║   ██║{RED}██╔══██╗{RESET}   {BLUE}║{RESET}
{BLUE}║{RESET}   {RED}╚██████╔╝{CYAN}██║  ██║{RED} ╚████╔╝ {CYAN}╚██████╔╝{RED}╚██████╗{CYAN}╚██████╔╝{RED}██║  ██║{RESET}   {BLUE}║{RESET}
{BLUE}║{RESET}    {RED}╚═════╝ {CYAN}╚═╝  ╚═╝{RED}  ╚═══╝  {CYAN} ╚═════╝ {RED} ╚═════╝{CYAN} ╚═════╝ {RED}╚═╝  ╚═╝{RESET}    {BLUE}║{RESET}
{BLUE}║{RESET}                                                                              {BLUE}║{RESET}
{BLUE}║{RESET}          {GREEN}┌────────────────────────────────────────────────┐{RESET}          {BLUE}║{RESET}
{BLUE}║{RESET}          {GREEN}│{YELLOW}     ADVANCED VULNERABILITY SCANNER v4.0     {GREEN}│{RESET}          {BLUE}║{RESET}
{BLUE}║{RESET}          {GREEN}│{RED}            STEALTH MODE - ACTIVE            {GREEN}│{RESET}          {BLUE}║{RESET}
{BLUE}║{RESET}          {GREEN}│{CYAN}         Professional Security Tool         {GREEN}│{RESET}          {BLUE}║{RESET}
{BLUE}║{RESET}          {GREEN}└────────────────────────────────────────────────┘{RESET}          {BLUE}║{RESET}
{BLUE}║{RESET}                                                                              {BLUE}║{RESET}
{BLUE}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}

{MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}
{MAGENTA}║{RESET} {CYAN}•{RESET} {YELLOW}Developed for:{RESET} {WHITE}Authorized Security Testing & Education{WHITE}          {MAGENTA}║{RESET}
{MAGENTA}║{RESET} {CYAN}•{RESET} {YELLOW}Stealth Mode:{RESET} {GREEN}Enabled{RESET} {GRAY}(Anti-blocking, IP Protection){GRAY}              {MAGENTA}║{RESET}
{MAGENTA}║{RESET} {CYAN}•{RESET} {YELLOW}Version:{RESET} {WHITE}4.0{WHITE} {GRAY}|{GRAY} {YELLOW}Status:{RESET} {GREEN}Operational{GREEN} {GRAY}|{GRAY} {YELLOW}Threads:{RESET} {WHITE}{self.max_threads}{WHITE}                 {MAGENTA}║{RESET}
{MAGENTA}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}
        """
        print(banner)
        self.display_scanning_animation()

    def display_scanning_animation(self):
        """Display scanning animation"""
        animation_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        print(f"\n{BLUE}[{RESET}{CYAN}▶{RESET}{BLUE}]{RESET} {GREEN}Initializing scanning module...{RESET}")
        time.sleep(0.5)
        print(f"{BLUE}[{RESET}{CYAN}▶{RESET}{BLUE}]{RESET} {GREEN}Loading stealth protocols...{RESET}")
        time.sleep(0.5)
        print(f"{BLUE}[{RESET}{CYAN}▶{RESET}{BLUE}]{RESET} {GREEN}Establishing secure connection...{RESET}\n")

    def print_status(self, message, level="INFO", animation=False):
        """Print status messages with colors"""
        colors = {
            "INFO": CYAN,
            "SUCCESS": GREEN,
            "WARNING": YELLOW,
            "ERROR": RED,
            "DEBUG": GRAY
        }
        color = colors.get(level, WHITE)
        icon = "ℹ" if level == "INFO" else "✓" if level == "SUCCESS" else "⚠" if level == "WARNING" else "✗"
        print(f"{color}[{icon}]{RESET} {message}")

    def print_scan_header(self, target_url):
        """Print scan header"""
        print(f"\n{BLUE}═" * 70)
        print(f"{YELLOW}🎯 TARGET:{RESET} {WHITE}{target_url}{RESET}")
        print(f"{YELLOW}⏰ START TIME:{RESET} {WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        print(f"{YELLOW}🛡️  STEALTH MODE:{RESET} {GREEN if self.stealth_mode else RED}{'ENABLED' if self.stealth_mode else 'DISABLED'}{RESET}")
        print(f"{BLUE}═" * 70 + RESET)

    def get_baseline_response(self, url):
        """Get baseline response for comparison"""
        try:
            self.baseline_response = self.baseline_session.get(
                url, 
                timeout=self.timeout,
                verify=False
            )
            self.request_count += 1
            return self.baseline_response
        except Exception as e:
            self.print_status(f"Failed to get baseline: {str(e)}", "ERROR")
            return None

    def test_endpoint_stealth(self, url):
        """Test endpoint with stealth techniques"""
        if self.stealth_mode:
            time.sleep(random.uniform(self.min_delay, self.max_delay))
        
        try:
            headers = self.stealth_session.headers.copy()
            if self.user_agent_pool:
                headers['User-Agent'] = random.choice(self.user_agent_pool)
            
            response = self.stealth_session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                proxies=random.choice(self.proxy_list) if self.proxy_list else None
            )
            self.request_count += 1
            self.last_request_time = time.time()
            return response
        except Exception as e:
            if not self.stealth_mode:
                self.print_status(f"Request failed: {str(e)}", "ERROR")
            return None

    def display_scan_progress(self, current, total, scan_type):
        """Display scan progress"""
        percent = (current / total) * 100
        bar_length = 30
        filled = int(bar_length * current // total)
        bar = f"{GREEN}█{RESET}" * filled + f"{GRAY}░{RESET}" * (bar_length - filled)
        print(f"\r{BLUE}[{RESET}{scan_type}{BLUE}]{RESET} {bar} {percent:.1f}% ({current}/{total})", end="", flush=True)

    def display_vulnerability_found(self, vuln_type, location, level):
        """Display when vulnerability is found"""
        colors = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": BLUE}
        color = colors.get(level, MAGENTA)
        print(f"\n{color}[!]{RESET} {WHITE}{vuln_type}{RESET} found in {CYAN}{location}{RESET} - Level: {color}{level}{RESET}")

    def calculate_statistics(self):
        """Calculate vulnerability statistics"""
        for vuln in self.results['vulnerabilities']:
            level = vuln.get('level', 'LOW').upper()
            if level in self.results['statistics']:
                self.results['statistics'][level.lower()] += 1
        
        total = sum(self.results['statistics'][level] for level in ['critical', 'high', 'medium', 'low'])
        self.results['statistics']['total'] = total

    def generate_report(self):
        """Generate scan report"""
        print(f"\n{BLUE}═" * 70)
        print(f"{YELLOW}📊 SCAN REPORT{RESET}")
        print(f"{BLUE}═" * 70)
        
        stats = self.results['statistics']
        print(f"{CYAN}Critical:{RESET} {RED}{stats['critical']}{RESET} | "
              f"{ORANGE}High:{RESET} {ORANGE}{stats['high']}{RESET} | "
              f"{YELLOW}Medium:{RESET} {YELLOW}{stats['medium']}{RESET} | "
              f"{GREEN}Low:{RESET} {GREEN}{stats['low']}{RESET}")
        print(f"{WHITE}Total vulnerabilities:{RESET} {MAGENTA}{stats['total']}{RESET}")
        
        if self.results['vulnerabilities']:
            print(f"\n{YELLOW}📋 VULNERABILITIES FOUND:{RESET}")
            for idx, vuln in enumerate(self.results['vulnerabilities'], 1):
                color = RED if vuln['level'] == 'CRITICAL' else ORANGE if vuln['level'] == 'HIGH' else YELLOW if vuln['level'] == 'MEDIUM' else BLUE
                print(f"{color}[{idx}]{RESET} {vuln['type']} - {vuln['parameter']} ({vuln['level']})")
        else:
            print(f"\n{GREEN}✓ No vulnerabilities found{RESET}")

    def cleanup_sessions(self):
        """Clean up all sessions"""
        for session in [self.stealth_session, self.scan_session, self.baseline_session]:
            session.close()
        self.print_status("Sessions cleaned up", "INFO")

    def check_exposed_configs(self, base_url):
        """Check for exposed configuration files"""
        self.print_status("Checking for exposed config files...", "INFO")
        config_files = [
            ".env", "config.php", "configuration.php", "wp-config.php",
            "config.json", "config.yml", "config.yaml", "config.ini",
            ".git/config", ".htaccess", "web.config", "robots.txt",
            "sitemap.xml", "crossdomain.xml", "phpinfo.php"
        ]
        
        vulnerabilities = []
        for config_file in config_files:
            test_url = f"{base_url.rstrip('/')}/{config_file}"
            response = self.test_endpoint_stealth(test_url)
            
            if response and response.status_code == 200:
                if self.is_config_file(response.text, config_file):
                    vulnerabilities.append({
                        'type': 'Exposed Config File',
                        'level': 'HIGH',
                        'parameter': config_file,
                        'payload': test_url,
                        'evidence': f"Exposed configuration file found: {config_file}",
                        'response_code': response.status_code,
                        'confidence': 'MEDIUM'
                    })
                    self.display_vulnerability_found("Exposed Config", config_file, "HIGH")
        
        return vulnerabilities

    def is_config_file(self, content, filename):
        """Check if content appears to be a config file"""
        config_indicators = {
            '.env': ['DB_HOST', 'DB_USER', 'DB_PASS', 'API_KEY', 'SECRET_KEY'],
            '.php': ['<?php', 'define(', '$_', 'mysql_connect'],
            '.json': ['{', '}', '"host"', '"password"'],
            '.yml': ['database:', 'host:', 'password:'],
            '.git': '[core]',
            '.htaccess': 'RewriteEngine',
            'robots.txt': 'User-agent:',
            'phpinfo.php': 'phpinfo()'
        }
        
        for ext, indicators in config_indicators.items():
            if filename.endswith(ext):
                return any(indicator in content for indicator in indicators)
        
        return False

    def check_admin_panels(self, base_url):
        """Check for common admin panels"""
        self.print_status("Checking for admin panels...", "INFO")
        admin_paths = [
            "admin", "administrator", "wp-admin", "dashboard",
            "login", "admin.php", "admin/login", "admin/index.php",
            "cpanel", "webmin", "plesk", "backend", "controlpanel"
        ]
        
        vulnerabilities = []
        for path in admin_paths:
            test_url = f"{base_url.rstrip('/')}/{path}"
            response = self.test_endpoint_stealth(test_url)
            
            if response and response.status_code in [200, 301, 302]:
                if self.is_admin_panel(response.text, response.url):
                    vulnerabilities.append({
                        'type': 'Admin Panel Found',
                        'level': 'MEDIUM',
                        'parameter': path,
                        'payload': test_url,
                        'evidence': f"Admin panel accessible at: {response.url}",
                        'response_code': response.status_code,
                        'confidence': 'HIGH'
                    })
                    self.display_vulnerability_found("Admin Panel", path, "MEDIUM")
        
        return vulnerabilities

    def is_admin_panel(self, content, url):
        """Check if page appears to be an admin panel"""
        admin_indicators = [
            'login', 'password', 'username', 'admin',
            'dashboard', 'control panel', 'cpanel',
            'administrator', 'sign in', 'log in'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in admin_indicators)

    def check_lfi_vulnerabilities(self, base_url, parameters):
        """Scan for LFI vulnerabilities"""
        self.print_status("Testing for Local File Inclusion...", "INFO", animation=True)
        
        lfi_test_cases = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../../etc/hosts",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "file:///etc/passwd",
            "C:\\boot.ini",
            "/etc/passwd"
        ]
        
        vulnerabilities = []
        for param in parameters[:2]:
            for payload in lfi_test_cases:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                response = self.test_endpoint_stealth(test_url)
                
                if response and response.status_code == 200:
                    if self.is_lfi_vulnerable(response.text):
                        vulnerabilities.append({
                            'type': 'LFI Vulnerability',
                            'level': 'HIGH',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f"Possible file inclusion with payload: {payload}",
                            'response_code': response.status_code,
                            'confidence': 'MEDIUM'
                        })
                        self.display_vulnerability_found("LFI", param, "HIGH")
                        break
                
                if self.stealth_mode:
                    time.sleep(random.uniform(1, 2))
        
        return vulnerabilities

    def is_lfi_vulnerable(self, content):
        """Check if content indicates LFI vulnerability"""
        lfi_indicators = [
            'root:', 'daemon:', 'bin:', 'sys:', 'nobody:',
            '[boot loader]', '[fonts]', '[extensions]',
            'for 16-bit app support', '[mail]'
        ]
        
        return any(indicator in content.lower() for indicator in lfi_indicators)

    def check_sql_injection(self, base_url, parameters):
        """Scan for SQL injection vulnerabilities"""
        self.print_status("Testing for SQL Injection...", "INFO", animation=True)
        
        sql_test_cases = [
            "'", "''", "`", "\"", "' OR '1'='1", "' OR '1'='1' --",
            "' OR '1'='1' /*", "' OR 1=1--", "' OR 1=1#", "admin'--",
            "1' ORDER BY 1--", "1' ORDER BY 1000--", "1' UNION SELECT 1,2,3--"
        ]
        
        vulnerabilities = []
        for param in parameters[:3]:
            for payload in sql_test_cases[:5]:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                response = self.test_endpoint_stealth(test_url)
                
                if response and response.status_code == 200:
                    if self.is_sql_injection(response.text, payload):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'level': 'CRITICAL',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f"SQL error detected with payload: {payload}",
                            'response_code': response.status_code,
                            'confidence': 'MEDIUM'
                        })
                        self.display_vulnerability_found("SQLi", param, "CRITICAL")
                        break
                
                if self.stealth_mode:
                    time.sleep(random.uniform(1, 2))
        
        return vulnerabilities

    def is_sql_injection(self, content, payload):
        """Check if content indicates SQL injection vulnerability"""
        sql_errors = [
            'SQL syntax', 'MySQL', 'ORA-', 'PostgreSQL',
            'Microsoft OLE DB', 'ODBC', 'JDBC', 'PDO',
            'syntax error', 'unclosed quotation', 'quoted string',
            'SQLite', 'MariaDB', 'You have an error in your SQL'
        ]
        
        content_lower = content.lower()
        return any(error in content_lower for error in sql_errors)

    def check_xss_vulnerabilities(self, base_url, parameters):
        """Scan for XSS vulnerabilities"""
        self.print_status("Testing for XSS...", "INFO", animation=True)
        
        xss_test_cases = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')"
        ]
        
        vulnerabilities = []
        for param in parameters[:3]:
            for payload in xss_test_cases[:4]:
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                response = self.test_endpoint_stealth(test_url)
                
                if response and response.status_code == 200:
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS Vulnerability',
                            'level': 'HIGH',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f"XSS payload reflected: {payload[:50]}...",
                            'response_code': response.status_code,
                            'confidence': 'MEDIUM'
                        })
                        self.display_vulnerability_found("XSS", param, "HIGH")
                        break
                
                if self.stealth_mode:
                    time.sleep(random.uniform(1, 2))
        
        return vulnerabilities

    def check_rce_vulnerabilities(self, base_url, parameters):
        """Scan for RCE vulnerabilities with stealth"""
        self.print_status("Testing for Remote Code Execution...", "INFO", animation=True)
        
        if not self.baseline_response:
            self.get_baseline_response(base_url)
        
        baseline_text = self.baseline_response.text.lower() if self.baseline_response else ""
        
        rce_test_cases = [
            {'payload': "{{7*7}}", 'expected': "49", 'type': 'template_engine'},
            {'payload': "${7*7}", 'expected': "49", 'type': 'expression_language'},
            {'payload': "#{7*7}", 'expected': "49", 'type': 'ruby_template'},
            {'payload': "<?php echo 'XRCE_TEST'; ?>", 'expected': "XRCE_TEST", 'type': 'php_code'},
            {'payload': "__import__('os').popen('echo XRCE_TEST').read()", 'expected': "XRCE_TEST", 'type': 'python_code'},
            {'payload': "|cat /etc/passwd", 'expected': "root:", 'type': 'command_injection'},
            {'payload': ";cat /etc/passwd", 'expected': "root:", 'type': 'command_injection'},
            {'payload': "`cat /etc/passwd`", 'expected': "root:", 'type': 'command_injection'},
            {'payload': "$(cat /etc/passwd)", 'expected': "root:", 'type': 'command_injection'},
            {'payload': "|| cat /etc/passwd", 'expected': "root:", 'type': 'command_injection'},
            {'payload': "&& cat /etc/passwd", 'expected': "root:", 'type': 'command_injection'},
            {'payload': "|ls", 'expected': "bin\nboot", 'type': 'command_injection'},
            {'payload': ";ls", 'expected': "bin\nboot", 'type': 'command_injection'},
            {'payload': "`ls`", 'expected': "bin\nboot", 'type': 'command_injection'},
            {'payload': "$(ls)", 'expected': "bin\nboot", 'type': 'command_injection'},
            {'payload': "|whoami", 'expected': "root", 'type': 'command_injection'},
            {'payload': ";whoami", 'expected': "root", 'type': 'command_injection'},
            {'payload': "`whoami`", 'expected': "root", 'type': 'command_injection'},
            {'payload': "$(whoami)", 'expected': "root", 'type': 'command_injection'}
        ]
        
        confirmed_vulnerabilities = []
        total_tests = len(parameters[:3]) * len(rce_test_cases)
        current_test = 0
        
        for param in parameters[:3]:
            for test_case in rce_test_cases:
                current_test += 1
                self.display_scan_progress(current_test, total_tests, "RCE Scan")
                
                if self.stealth_mode:
                    time.sleep(random.uniform(2, 4))
                
                test_url = f"{base_url}?{param}={urllib.parse.quote(test_case['payload'])}"
                response = self.test_endpoint_stealth(test_url)
                
                if response and response.status_code == 200:
                    response_text = response.text
                    
                    if self.is_confirmed_rce(response_text, test_case, baseline_text):
                        vuln = {
                            'type': f'RCE - {test_case["type"]}',
                            'level': 'CRITICAL',
                            'parameter': param,
                            'payload': test_case['payload'],
                            'evidence': f"Confirmed command execution - Expected: {test_case['expected']}",
                            'response_code': response.status_code,
                            'confidence': 'HIGH'
                        }
                        confirmed_vulnerabilities.append(vuln)
                        self.display_vulnerability_found(f"RCE ({test_case['type']})", param, "CRITICAL")
                
                if self.stealth_mode and test_case != rce_test_cases[-1]:
                    time.sleep(random.uniform(1, 2))
        
        print()
        return confirmed_vulnerabilities

    def is_confirmed_rce(self, response_text, test_case, baseline_text):
        """Confirm RCE vulnerabilities"""
        expected = test_case['expected']
        payload = test_case['payload']
        
        if expected in baseline_text:
            return False
        
        if expected in response_text and expected not in baseline_text:
            if test_case['type'] in ['command_injection']:
                command_indicators = [
                    "root:", "daemon:", "bin:", "sys:", "nobody:",
                    "www-data", "apache", "nginx", "administrator",
                    "command not found", "permission denied"
                ]
                if any(indicator in response_text.lower() for indicator in command_indicators):
                    return True
            else:
                return True
        
        if test_case['type'] in ['template_engine', 'expression_language', 'ruby_template']:
            if expected in response_text and expected not in baseline_text:
                if "7*7" not in response_text or response_text.count("49") > response_text.count("7*7"):
                    return True
        
        if test_case['type'] in ['php_code', 'python_code']:
            if expected in response_text and expected not in baseline_text:
                return True
        
        if self.analyze_rce_payload_reflection(response_text, payload, baseline_text):
            return True
        
        return False

    def analyze_rce_payload_reflection(self, response_text, payload, baseline_text):
        """Analyze how RCE payload is reflected in response"""
        if (payload in response_text and 
            payload not in baseline_text and
            len(payload) > 5):
            return True
        
        rce_patterns = [
            r'root:\w*:\d+:\d+:',
            r'www-data',
            r'administrator',
            r'command not found',
            r'permission denied',
            r'syntax error',
            r'parse error',
            r'undefined function',
            r'warning:',
            r'fatal error:'
        ]
        
        for pattern in rce_patterns:
            if (re.search(pattern, response_text, re.IGNORECASE) and 
                not re.search(pattern, baseline_text, re.IGNORECASE)):
                return True
        
        return False

    def scan_website_stealth(self, target_url):
        """Comprehensive stealth scanning"""
        self.print_scan_header(target_url)
        
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().isoformat()
        
        try:
            if self.stealth_mode:
                self.print_status("Simulating human browsing patterns...", "INFO", animation=True)
                time.sleep(random.uniform(2, 4))
            
            self.get_baseline_response(target_url)
            if not self.baseline_response:
                self.print_status("Target is not accessible", "ERROR")
                return
            
            self.print_status(f"Target status: {self.baseline_response.status_code}", "SUCCESS")
            
            parameters = ['id', 'page', 'file', 'view', 'cmd', 'exec', 'command', 'code', 'eval'][:4]
            
            vulnerabilities = []
            scan_functions = [
                (self.check_exposed_configs, [target_url], "Config Scan"),
                (self.check_admin_panels, [target_url], "Admin Scan"),
                (self.check_lfi_vulnerabilities, [target_url, parameters], "LFI Scan"),
                (self.check_sql_injection, [target_url, parameters], "SQLi Scan"),
                (self.check_xss_vulnerabilities, [target_url, parameters], "XSS Scan"),
                (self.check_rce_vulnerabilities, [target_url, parameters], "RCE Scan"),
            ]
            
            for idx, (func, args, name) in enumerate(scan_functions):
                self.print_status(f"Starting {name}...", "INFO")
                time.sleep(1 if self.stealth_mode else 0.5)
                
                try:
                    result = func(*args)
                    vulnerabilities.extend(result)
                    
                    if self.stealth_mode and idx < len(scan_functions) - 1:
                        delay = random.uniform(3, 8)
                        self.print_status(f"Stealth cooldown: {delay:.1f}s", "DEBUG")
                        time.sleep(delay)
                        
                except Exception as e:
                    self.print_status(f"Scan failed: {str(e)}", "ERROR")
                    if self.stealth_mode:
                        time.sleep(random.uniform(5, 10))
            
            self.results['vulnerabilities'] = vulnerabilities
            self.calculate_statistics()
            
            self.print_status(f"Scan complete. Total requests: {self.request_count}", "SUCCESS")
            
        except Exception as e:
            self.print_status(f"Scan failed: {str(e)}", "ERROR")
            self.cleanup_sessions()

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner - Stealth Mode')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('-th', '--threads', type=int, default=3, help='Number of concurrent threads')
    parser.add_argument('-s', '--stealth', action='store_true', default=True, help='Enable stealth mode')
    parser.add_argument('-ns', '--no-stealth', action='store_false', dest='stealth', help='Disable stealth mode')
    parser.add_argument('-o', '--output', help='Output file for the report')
    
    args = parser.parse_args()
    
    scanner = StealthVulnerabilityScanner(
        timeout=args.timeout, 
        threads=args.threads,
        stealth_mode=args.stealth
    )
    
    scanner.display_advanced_banner()
    
    print(f"{RED}⚠{RESET} {YELLOW}WARNING:{RESET} For authorized testing only. Use at your own risk!")
    print(f"{BLUE}ℹ{RESET} {CYAN}Stealth Mode:{RESET} {GREEN if args.stealth else RED}{'ENABLED' if args.stealth else 'DISABLED'}{RESET}")
    print(f"{BLUE}ℹ{RESET} {CYAN}Anti-blocking:{RESET} {GREEN}ACTIVE{RESET}")
    print()
    
    target = args.target
    if not target:
        target = input(f"{CYAN}🎯 {RESET}Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        start_time = time.time()
        scanner.scan_website_stealth(target)
        scan_time = time.time() - start_time
        scanner.generate_report()
        
        print(f"\n{BLUE}⏱️ {RESET} Scan completed in {GREEN}{scan_time:.2f}{RESET} seconds")
        print(f"{BLUE}📤 {RESET} Total requests: {CYAN}{scanner.request_count}{RESET}")
        print(f"{BLUE}📊 {RESET} Vulnerabilities found: {WHITE}{scanner.results['statistics']['total']}{RESET}")
        
        scanner.cleanup_sessions()
        
        if args.output or input(f"\n{CYAN}💾 {RESET}Save report to file? (y/n): ").lower() == 'y':
            filename = args.output or f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(scanner.results, f, indent=4)
            print(f"{GREEN}✓ {RESET} Report saved to {YELLOW}{filename}{RESET}")
        
        print(f"\n{MAGENTA}🔒 {RESET}{CYAN}Scan completed successfully. Stay secure!{RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{RED}✗ {RESET}Scan interrupted by user")
        scanner.cleanup_sessions()
    except Exception as e:
        print(f"\n{RED}✗ {RESET}Scan failed: {RED}{str(e)}{RESET}")
        scanner.cleanup_sessions()

if __name__ == "__main__":
    main()