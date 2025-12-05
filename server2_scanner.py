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

# تعريف الألوان كمتغيرات عالمية في بداية الكلاس
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
        
        # Create different sessions for different request types
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
        
        # Initialize diverse User-Agent pool
        self._init_user_agents()
        
        # Set base headers with randomization
        self._set_stealth_headers()
        
        # Backup proxy list
        self.proxy_list = [None]
        
        # Random timing between requests
        self.min_delay = 1.5 if stealth_mode else 0.5
        self.max_delay = 4.0 if stealth_mode else 2.0
        
        # Track used IPs
        self.used_ips = set()
        self.current_ip = self._get_public_ip()

    def display_advanced_banner(self):
        """Display professional hacker-style banner with colors"""
        # استخدم المتغيرات العالمية للألوان
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
        
        # Display scanning animation
        self.display_scanning_animation()

    def display_scanning_animation(self):
        """Display scanning animation"""
        animation_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        print(f"\n{BLUE}[{RESET}{CYAN}▶{RESET}{BLUE}]{RESET} {GREEN}Initializing scanning module...{RESET}")
        time.sleep(0.5)
        print(f"{BLUE}[{RESET}{CYAN}▶{RESET}{BLUE}]{RESET} {GREEN}Loading stealth protocols...{RESET}")
        time.sleep(0.5)
        print(f"{BLUE}[{RESET}{CYAN}▶{RESET}{BLUE}]{RESET} {GREEN}Establishing secure connection...{RESET}\n")

    def print_scan_header(self, target_url):
        """Print scan header with style"""
        width = 80
        target_display = target_url[:60] + "..." if len(target_url) > 60 else target_url
        
        print(f"\n{BLUE}╔{'═' * (width-2)}╗{RESET}")
        print(f"{BLUE}║{RESET}{CYAN}                    SCAN INITIATION                    {BLUE}║{RESET}")
        print(f"{BLUE}╠{'═' * (width-2)}╣{RESET}")
        print(f"{BLUE}║{RESET} {GREEN}•{RESET} Target: {YELLOW}{target_display:<55}{RESET} {BLUE}║{RESET}")
        print(f"{BLUE}║{RESET} {GREEN}•{RESET} Mode:   {GREEN if self.stealth_mode else RED}{'Stealth':<12}{RESET} {BLUE}║{RESET}")
        print(f"{BLUE}║{RESET} {GREEN}•{RESET} Time:   {CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<25}{RESET} {BLUE}║{RESET}")
        print(f"{BLUE}║{RESET} {GREEN}•{RESET} IP:     {WHITE}{self.current_ip:<40}{RESET} {BLUE}║{RESET}")
        print(f"{BLUE}╚{'═' * (width-2)}╝{RESET}")

    def print_status(self, message, level="INFO", animation=False):
        """Print status with hacker-style formatting"""
        colors = {
            "INFO": CYAN,
            "SUCCESS": GREEN,
            "WARNING": YELLOW,
            "ERROR": RED,
            "CRITICAL": MAGENTA,
            "DEBUG": GRAY
        }
        
        icons = {
            "INFO": "ℹ",
            "SUCCESS": "✓",
            "WARNING": "⚠",
            "ERROR": "✗",
            "CRITICAL": "⚡",
            "DEBUG": "🔍"
        }
        
        brackets = {
            "INFO": f"{BLUE}[{RESET}{CYAN}{{}}{RESET}{BLUE}]{RESET}",
            "SUCCESS": f"{BLUE}[{RESET}{GREEN}{{}}{RESET}{BLUE}]{RESET}",
            "WARNING": f"{BLUE}[{RESET}{YELLOW}{{}}{RESET}{BLUE}]{RESET}",
            "ERROR": f"{BLUE}[{RESET}{RED}{{}}{RESET}{BLUE}]{RESET}",
            "CRITICAL": f"{BLUE}[{RESET}{MAGENTA}{{}}{RESET}{BLUE}]{RESET}",
            "DEBUG": f"{BLUE}[{RESET}{GRAY}{{}}{RESET}{BLUE}]{RESET}"
        }
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Animation characters for scanning
        if animation and level in ["INFO", "DEBUG"]:
            anim_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            icon = anim_chars[int(time.time() * 4) % len(anim_chars)]
        else:
            icon = icons.get(level, "●")
        
        # Create the formatted message
        bracket_fmt = brackets.get(level, f"{BLUE}[{{}}{BLUE}]{RESET}")
        colored_icon = colors.get(level, CYAN) + icon + RESET
        
        print(f"{bracket_fmt.format(timestamp)} {colors.get(level, CYAN)}{message}{RESET}")

    def display_vulnerability_found(self, vuln_type, param=None, level="MEDIUM"):
        """Display vulnerability found in hacker style"""
        level_colors = {
            'CRITICAL': RED,
            'HIGH': ORANGE,
            'MEDIUM': YELLOW,
            'LOW': GREEN
        }
        
        level_color = level_colors.get(level.upper(), YELLOW)
        
        # Create hacker-style box
        print(f"\n{level_color}╔{'═' * 78}╗{RESET}")
        print(f"{level_color}║{RESET} {WHITE}⚡ VULNERABILITY DETECTED ⚡{' ' * 45}{RESET} {level_color}║{RESET}")
        print(f"{level_color}╠{'═' * 78}╣{RESET}")
        print(f"{level_color}║{RESET} {CYAN}Type:{RESET}     {WHITE}{vuln_type:<60}{RESET} {level_color}║{RESET}")
        if param:
            print(f"{level_color}║{RESET} {CYAN}Parameter:{RESET} {YELLOW}{param:<60}{RESET} {level_color}║{RESET}")
        print(f"{level_color}║{RESET} {CYAN}Severity:{RESET}  {level_color}{level.upper():<60}{RESET} {level_color}║{RESET}")
        print(f"{level_color}║{RESET} {CYAN}Time:{RESET}      {GRAY}{datetime.now().strftime('%H:%M:%S'):<60}{RESET} {level_color}║{RESET}")
        print(f"{level_color}╚{'═' * 78}╝{RESET}")

    def display_scan_progress(self, current, total, scan_type):
        """Display progress bar with hacker style"""
        width = 50
        percent = (current / total) * 100
        filled = int(width * current // total)
        bar = f"{BLUE}▐{RESET}{GREEN}{'█' * filled}{RESET}{CYAN}{'░' * (width - filled)}{RESET}{BLUE}▌{RESET}"
        
        print(f"\r{CYAN}▶{RESET} {YELLOW}{scan_type:<20}{RESET} {bar} {BLUE}{percent:6.1f}%{RESET}", end='', flush=True)
        
        if current >= total:
            print()

    def display_summary_box(self, stats):
        """Display summary in a stylish box"""
        width = 80
        
        print(f"\n{MAGENTA}╔{'═' * (width-2)}╗{RESET}")
        print(f"{MAGENTA}║{RESET}{CYAN}                     SCAN SUMMARY                      {MAGENTA}║{RESET}")
        print(f"{MAGENTA}╠{'═' * (width-2)}╣{RESET}")
        
        # Critical
        crit_bar = f"{RED}{'█' * min(stats['critical'] * 5, 40)}{'░' * (40 - min(stats['critical'] * 5, 40))}{RESET}"
        print(f"{MAGENTA}║{RESET} {RED}⚡ CRITICAL:{RESET} {stats['critical']:>3} {crit_bar} {MAGENTA}║{RESET}")
        
        # High
        high_bar = f"{YELLOW}{'█' * min(stats['high'] * 5, 40)}{'░' * (40 - min(stats['high'] * 5, 40))}{RESET}"
        print(f"{MAGENTA}║{RESET} {YELLOW}⚠ HIGH:{RESET}     {stats['high']:>3} {high_bar} {MAGENTA}║{RESET}")
        
        # Medium
        med_bar = f"{CYAN}{'█' * min(stats['medium'] * 5, 40)}{'░' * (40 - min(stats['medium'] * 5, 40))}{RESET}"
        print(f"{MAGENTA}║{RESET} {CYAN}ℹ MEDIUM:{RESET}   {stats['medium']:>3} {med_bar} {MAGENTA}║{RESET}")
        
        # Low
        low_bar = f"{GREEN}{'█' * min(stats['low'] * 5, 40)}{'░' * (40 - min(stats['low'] * 5, 40))}{RESET}"
        print(f"{MAGENTA}║{RESET} {GREEN}✓ LOW:{RESET}      {stats['low']:>3} {low_bar} {MAGENTA}║{RESET}")
        
        print(f"{MAGENTA}╠{'═' * (width-2)}╣{RESET}")
        print(f"{MAGENTA}║{RESET} {BLUE}📊 TOTAL:{RESET}    {WHITE}{stats['total']:>3}{RESET} {' ' * 40} {MAGENTA}║{RESET}")
        print(f"{MAGENTA}╚{'═' * (width-2)}╝{RESET}")

    def _init_user_agents(self):
        """Initialize diverse User-Agent pool"""
        self.user_agent_pool = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]

    def _set_stealth_headers(self):
        """Set randomized and diverse headers"""
        common_headers = {
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            ]),
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-US,en;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        for session in [self.stealth_session, self.scan_session, self.baseline_session]:
            session.headers.clear()
            session.headers.update(common_headers.copy())
            session.headers['User-Agent'] = random.choice(self.user_agent_pool)

    def _get_public_ip(self):
        """Get current public IP"""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            return response.json()['ip']
        except:
            return "Unknown"

    def _rotate_user_agent(self, session):
        """Randomly change User-Agent"""
        session.headers['User-Agent'] = random.choice(self.user_agent_pool)

    def _respectful_delay(self):
        """Random respectful delay between requests"""
        if self.stealth_mode:
            delay = random.uniform(self.min_delay, self.max_delay)
            if self.request_count % 5 == 0:
                delay += random.uniform(2, 5)
            time.sleep(delay)
            if self.request_count % 3 == 0:
                self._rotate_user_agent(self.scan_session)

    def test_endpoint_stealth(self, url, method="GET", data=None, headers=None, use_baseline=False):
        """Send stealth request avoiding detection"""
        try:
            if use_baseline:
                session = self.baseline_session
            elif self.stealth_mode:
                session = self.stealth_session
            else:
                session = self.scan_session
            
            current_time = time.time()
            if self.last_request_time > 0:
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.min_delay:
                    time.sleep(self.min_delay - time_since_last)
            
            self._respectful_delay()
            
            request_headers = session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            if random.random() > 0.5:
                request_headers['DNT'] = '1'
            
            self.request_count += 1
            self.last_request_time = time.time()
            
            if method.upper() == "GET":
                response = session.get(
                    url, 
                    timeout=self.timeout, 
                    allow_redirects=True, 
                    headers=request_headers,
                    verify=False
                )
            else:
                response = session.post(
                    url, 
                    data=data, 
                    timeout=self.timeout, 
                    allow_redirects=True, 
                    headers=request_headers,
                    verify=False
                )
            
            if self._is_blocked(response):
                self.print_status("Possible blocking detected. Increasing delays...", "WARNING")
                self.min_delay += 1
                self.max_delay += 2
                time.sleep(random.uniform(5, 10))
                self._rotate_user_agent(session)
                return None
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.print_status(f"Request failed: {str(e)}", "DEBUG")
            self.min_delay = min(self.min_delay + 0.5, 10)
            time.sleep(random.uniform(3, 7))
            return None

    def _is_blocked(self, response):
        """Detect blocking signs"""
        if not response:
            return False
            
        blocked_indicators = [
            (response.status_code in [403, 429, 503]),
            ('cloudflare' in response.headers.get('Server', '').lower()),
            ('access denied' in response.text.lower()),
            ('blocked' in response.text.lower()),
        ]
        
        return any(blocked_indicators)

    def get_baseline_response(self, url):
        """Get baseline response in stealth mode"""
        self.print_status("Establishing baseline connection...", "INFO", animation=True)
        
        for i in range(2):
            test_response = self.test_endpoint_stealth(url, use_baseline=True)
            if test_response:
                time.sleep(random.uniform(2, 4))
        
        self.baseline_response = self.test_endpoint_stealth(url, use_baseline=True)
        
        if self.baseline_response:
            self.cookies_pool = list(self.baseline_session.cookies)
            time.sleep(random.uniform(1, 3))
            self.test_endpoint_stealth(url + '?t=' + str(random.random()), use_baseline=True)
        
        return self.baseline_response

    def check_lfi_vulnerabilities(self, base_url, parameters):
        """Scan for LFI vulnerabilities with stealth"""
        self.print_status("Scanning for LFI/Path Traversal...", "INFO", animation=True)
        
        lfi_payloads = [
            "....//....//....//....//etc/passwd",
            "..%252F..%252F..%252F..%252Fetc%252Fpasswd"
        ]
        
        vulnerabilities = []
        
        total_tests = len(parameters[:3]) * len(lfi_payloads)
        current_test = 0
        
        for param in parameters[:3]:
            for payload in lfi_payloads:
                current_test += 1
                self.display_scan_progress(current_test, total_tests, "LFI Scan")
                
                if self.stealth_mode:
                    time.sleep(random.uniform(0.5, 1.5))
                
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                response = self.test_endpoint_stealth(test_url)
                
                if response and response.status_code == 200:
                    content = response.text
                    if "root:" in content or "[boot loader]" in content:
                        vuln = {
                            'type': 'LFI/Path Traversal',
                            'level': 'HIGH',
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'File inclusion successful',
                            'response_code': response.status_code
                        }
                        vulnerabilities.append(vuln)
                        self.display_vulnerability_found("LFI/Path Traversal", param, "HIGH")
                
                if self.stealth_mode and payload != lfi_payloads[-1]:
                    time.sleep(random.uniform(1, 2))
        
        print()
        return vulnerabilities

    def check_exposed_configs(self, base_url):
        """Scan for exposed config files with stealth"""
        self.print_status("Scanning for exposed configurations...", "INFO", animation=True)
        
        config_files = [
            "/.env", "/config.php", "/.git/config",
            "/.htaccess", "/robots.txt", "/sitemap.xml"
        ]
        
        exposed_files = []
        total_files = len(config_files)
        
        for idx, file_path in enumerate(config_files):
            self.display_scan_progress(idx + 1, total_files, "Config Scan")
            
            if self.stealth_mode:
                time.sleep(random.uniform(0.3, 1.2))
            
            test_url = base_url.rstrip('/') + file_path
            response = self.test_endpoint_stealth(test_url)
            
            if response and response.status_code == 200:
                content = response.text
                if (len(content) > 10 and 
                    not any(error in content.lower() for error in ['error', 'not found', '404'])):
                    
                    exposed_files.append({
                        'type': 'Exposed Configuration File',
                        'level': 'HIGH',
                        'url': test_url,
                        'filename': file_path,
                        'response_code': response.status_code,
                        'evidence': f'Configuration file accessible at {test_url}'
                    })
                    self.display_vulnerability_found(f"Exposed Config: {file_path}", None, "HIGH")
        
        print()
        return exposed_files

    def check_admin_panels(self, base_url):
        """Scan for admin panels with stealth"""
        self.print_status("Discovering admin interfaces...", "INFO", animation=True)
        
        admin_paths = [
            "/admin", "/administrator", "/wp-admin",
            "/dashboard", "/login", "/cpanel"
        ]
        
        admin_panels = []
        total_paths = len(admin_paths)
        
        for idx, path in enumerate(admin_paths):
            self.display_scan_progress(idx + 1, total_paths, "Admin Panel Scan")
            
            if self.stealth_mode:
                time.sleep(random.uniform(0.5, 1.5))
            
            test_url = base_url.rstrip('/') + path
            response = self.test_endpoint_stealth(test_url)
            
            if response and response.status_code in [200, 301, 302, 401, 403]:
                title = self.extract_title(response.text)
                content_lower = response.text.lower()
                
                strong_indicators = ['admin', 'login', 'dashboard', 'username', 'password']
                indicator_count = sum(1 for indicator in strong_indicators if indicator in content_lower)
                
                if (indicator_count >= 2 or 
                    response.status_code in [401, 403] or
                    any(word in title.lower() for word in ['admin', 'login', 'dashboard'])):
                    
                    admin_panels.append({
                        'type': 'Admin Panel Discovered',
                        'level': 'MEDIUM',
                        'url': test_url,
                        'path': path,
                        'status_code': response.status_code,
                        'title': title,
                        'evidence': f'Admin interface accessible at {test_url}'
                    })
                    self.display_vulnerability_found(f"Admin Panel: {path}", None, "MEDIUM")
        
        print()
        return admin_panels

    def check_sql_injection(self, base_url, parameters):
        """Scan for SQL Injection with stealth"""
        self.print_status("Testing for SQL Injection...", "INFO", animation=True)
        
        sql_payloads = ["' OR '1'='1", "' UNION SELECT 1,2,3--"]
        sql_vulns = []
        total_tests = len(parameters[:3]) * len(sql_payloads)
        current_test = 0
        
        for param in parameters[:3]:
            for payload in sql_payloads:
                current_test += 1
                self.display_scan_progress(current_test, total_tests, "SQLi Scan")
                
                if self.stealth_mode:
                    time.sleep(random.uniform(1, 3))
                
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                start_time = time.time()
                response = self.test_endpoint_stealth(test_url)
                response_time = time.time() - start_time
                
                if response and response.status_code == 200:
                    content_lower = response.text.lower()
                    sql_errors = ["sql syntax", "mysql_fetch", "ora-", "unclosed quotation"]
                    
                    if any(error in content_lower for error in sql_errors):
                        vuln = {
                            'type': 'SQL Injection',
                            'level': 'CRITICAL',
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'SQL error messages found',
                            'detection_method': 'Error-based',
                            'response_code': response.status_code
                        }
                        sql_vulns.append(vuln)
                        self.display_vulnerability_found("SQL Injection", param, "CRITICAL")
                    
                    elif response_time > 5:
                        vuln = {
                            'type': 'SQL Injection',
                            'level': 'HIGH',
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Delayed response: {response_time:.2f}s',
                            'detection_method': 'Time-based',
                            'response_time': response_time,
                        }
                        sql_vulns.append(vuln)
                        self.display_vulnerability_found("SQL Injection (Time-based)", param, "HIGH")
        
        print()
        return sql_vulns

    def check_xss_vulnerabilities(self, base_url, parameters):
        """Scan for XSS vulnerabilities with stealth"""
        self.print_status("Checking for XSS vulnerabilities...", "INFO", animation=True)
        
        xss_payloads = ["<script>console.log('test')</script>", "\"><img src=x>"]
        xss_vulns = []
        total_tests = len(parameters[:3]) * len(xss_payloads)
        current_test = 0
        
        for param in parameters[:3]:
            for payload in xss_payloads:
                current_test += 1
                self.display_scan_progress(current_test, total_tests, "XSS Scan")
                
                if self.stealth_mode:
                    time.sleep(random.uniform(0.5, 1.5))
                
                test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                response = self.test_endpoint_stealth(test_url)
                
                if response and response.status_code == 200:
                    if payload in response.text:
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'level': 'MEDIUM',
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'XSS payload reflected without encoding',
                            'response_code': response.status_code
                        }
                        xss_vulns.append(vuln)
                        self.display_vulnerability_found("XSS Vulnerability", param, "MEDIUM")
        
        print()
        return xss_vulns

    def extract_title(self, html):
        """Extract page title"""
        try:
            start = html.find('<title>') + 7
            end = html.find('</title>')
            if start > 6 and end > start:
                return html[start:end].strip()[:100]
        except:
            pass
        return "No Title"

    def scan_website_stealth(self, target_url):
        """Comprehensive stealth scanning"""
        self.print_scan_header(target_url)
        
        self.results['target'] = target_url
        self.results['scan_time'] = datetime.now().isoformat()
        
        try:
            # Simulate human behavior first
            if self.stealth_mode:
                self.print_status("Simulating human browsing patterns...", "INFO", animation=True)
                time.sleep(random.uniform(2, 4))
            
            # Get baseline
            self.get_baseline_response(target_url)
            if not self.baseline_response:
                self.print_status("Target is not accessible", "ERROR")
                return
            
            self.print_status(f"Target status: {self.baseline_response.status_code}", "SUCCESS")
            
            # Limited parameters
            parameters = ['id', 'page', 'file', 'view'][:3]
            
            # Sequential scanning
            vulnerabilities = []
            scan_functions = [
                (self.check_exposed_configs, [target_url], "Config Scan"),
                (self.check_admin_panels, [target_url], "Admin Scan"),
                (self.check_lfi_vulnerabilities, [target_url, parameters], "LFI Scan"),
                (self.check_sql_injection, [target_url, parameters], "SQLi Scan"),
                (self.check_xss_vulnerabilities, [target_url, parameters], "XSS Scan"),
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

    def calculate_statistics(self):
        """Calculate statistics"""
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
        """Generate stylish report"""
        width = 80
        
        print(f"\n{MAGENTA}╔{'═' * (width-2)}╗{RESET}")
        print(f"{MAGENTA}║{RESET}{CYAN}               VULNERABILITY SCAN REPORT               {MAGENTA}║{RESET}")
        print(f"{MAGENTA}╠{'═' * (width-2)}╣{RESET}")
        
        # Display statistics in a box
        self.display_summary_box(self.results['statistics'])
        
        if not self.results['vulnerabilities']:
            print(f"\n{BLUE}╔{'═' * (width-2)}╗{RESET}")
            print(f"{BLUE}║{RESET} {GREEN}✓ No vulnerabilities found! Target appears secure. {' ' * 20}{BLUE}║{RESET}")
            print(f"{BLUE}╚{'═' * (width-2)}╝{RESET}")
            return
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in self.results['vulnerabilities']:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Display each vulnerability type
        for vuln_type, vulnerabilities in vuln_by_type.items():
            level_colors = {
                'CRITICAL': RED,
                'HIGH': YELLOW,
                'MEDIUM': CYAN,
                'LOW': GREEN
            }
            
            avg_level = max(set([v['level'] for v in vulnerabilities]), 
                          key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
            color = level_colors.get(avg_level, CYAN)
            
            print(f"\n{color}╔{'═' * (width-2)}╗{RESET}")
            print(f"{color}║{RESET} {BLUE}▶{RESET} {vuln_type.upper()} ({len(vulnerabilities)} found) {' ' * (width - len(vuln_type) - 20)}{color}║{RESET}")
            print(f"{color}╠{'═' * (width-2)}╣{RESET}")
            
            for i, vuln in enumerate(vulnerabilities[:5], 1):  # Show first 5
                level_color = level_colors.get(vuln['level'], CYAN)
                print(f"{color}║{RESET} {level_color}•{RESET} {vuln.get('parameter', 'N/A'):<15} {vuln['evidence'][:50]:<50} {color}║{RESET}")
            
            if len(vulnerabilities) > 5:
                print(f"{color}║{RESET} {BLUE}... and {len(vulnerabilities) - 5} more vulnerabilities{' ' * 30}{color}║{RESET}")
            
            print(f"{color}╚{'═' * (width-2)}╝{RESET}")

    def cleanup_sessions(self):
        """Clean up sessions"""
        for session in [self.stealth_session, self.scan_session, self.baseline_session]:
            session.cookies.clear()
            session.headers.clear()
        
        if self.stealth_mode:
            time.sleep(random.uniform(2, 5))

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
    
    # Display professional banner
    scanner.display_advanced_banner()
    
    # Display warning
    print(f"{RED}⚠{RESET} {YELLOW}WARNING:{RESET} For authorized testing only. Use at your own risk!")
    print(f"{BLUE}ℹ{RESET} {CYAN}Stealth Mode:{RESET} {'GREEN}ENABLED{RESET' if args.stealth else f'{RED}DISABLED{RESET}'}")
    print(f"{BLUE}ℹ{RESET} {CYAN}Anti-blocking:{RESET} {GREEN}ACTIVE{RESET}")
    print()
    
    target = args.target
    if not target:
        target = input(f"{CYAN}🎯 {RESET}Enter target URL: ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    try:
        start_time = time.time()
        
        # Run scan
        scanner.scan_website_stealth(target)
        
        scan_time = time.time() - start_time
        
        # Generate report
        scanner.generate_report()
        
        # Display final stats
        print(f"\n{BLUE}⏱️ {RESET} Scan completed in {GREEN}{scan_time:.2f}{RESET} seconds")
        print(f"{BLUE}📤 {RESET} Total requests: {CYAN}{scanner.request_count}{RESET}")
        print(f"{BLUE}📊 {RESET} Vulnerabilities found: {WHITE}{scanner.results['statistics']['total']}{RESET}")
        
        # Cleanup
        scanner.cleanup_sessions()
        
        # Save report
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