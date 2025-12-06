#!/usr/bin/env python3
"""
[🔥] PRO HUNTER - Advanced Vulnerability Scanner
[⚡] Professional Security Assessment Suite v7.0
[🔒] Developed for Ethical Security Testing
"""

import requests
import urllib.parse
import concurrent.futures
import time
from datetime import datetime
import sys
import json
import argparse
import re
import random
import socket
import ssl
import hashlib
import ipaddress
import dns.resolver
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import csv
import yaml
import base64
from cryptography.fernet import Fernet
import warnings
warnings.filterwarnings('ignore')

# Color Definitions
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ORANGE = '\033[38;5;208m'
    PURPLE = '\033[38;5;129m'
    PINK = '\033[38;5;213m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    # Background Colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_PURPLE = '\033[45m'

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class ProHunterScanner:
    def __init__(self, target, timeout=20, threads=10, stealth=True, depth=2, output=None):
        self.target = self.normalize_url(target)
        self.domain = self.extract_domain(target)
        self.timeout = timeout
        self.max_threads = threads if not stealth else min(threads, 5)
        self.stealth_mode = stealth
        self.scan_depth = depth
        self.output_file = output
        
        # Results storage
        self.results = {
            'target': self.target,
            'domain': self.domain,
            'scan_id': hashlib.md5(f"{target}{datetime.now()}".encode()).hexdigest()[:16],
            'start_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'discoveries': [],
            'configuration': [],
            'technology_stack': [],
            'endpoints': [],
            'statistics': {
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                'total_requests': 0, 'total_vulnerabilities': 0,
                'scan_duration': 0
            }
        }
        
        # Sessions
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self._get_stealth_headers())
        
        # Technology fingerprints
        self.tech_signatures = self._load_tech_signatures()
        self.vuln_signatures = self._load_vuln_signatures()
        
        # Wordlists
        self.wordlists = self._load_wordlists()
        
        # State
        self.crawl_queue = []
        self.crawled_urls = set()
        self.discovered_endpoints = []
        self.technologies = set()
        
        print(self.display_pro_banner())

    def _get_stealth_headers(self):
        """Return stealth headers with rotation"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 Chrome/112.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"
        ]
        
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'ar-SA,ar;q=0.8']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
            'DNT': '1'
        }

    def _load_tech_signatures(self):
        """Load technology detection signatures"""
        return {
            'CMS': {
                'WordPress': ['wp-content', 'wp-includes', 'wp-admin', '/wp-json/'],
                'Joomla': ['/media/jui/', '/components/com_', 'Joomla!'],
                'Drupal': ['/sites/all/', '/modules/', 'Drupal.settings'],
                'Magento': ['/skin/frontend/', '/media/', 'Magento_'],
                'Shopify': ['cdn.shopify.com', 'Shopify.theme']
            },
            'Frameworks': {
                'Laravel': ['_token', 'csrf-token', 'laravel_session'],
                'Django': ['csrfmiddlewaretoken', 'django_language'],
                'Flask': ['session', 'flask'],
                'Express': ['express', 'connect.sid'],
                'Spring': ['jsessionid', 'spring']
            },
            'Servers': {
                'Apache': ['Apache/', 'Server: Apache'],
                'Nginx': ['Server: nginx', 'nginx/'],
                'IIS': ['Server: Microsoft-IIS', 'X-Powered-By: ASP.NET'],
                'CloudFlare': ['Server: cloudflare', 'cf-ray']
            },
            'Languages': {
                'PHP': ['.php', 'PHP/', 'X-Powered-By: PHP'],
                'Python': ['.py', 'Python/', 'WSGI'],
                'Java': ['.jsp', '.do', 'Java/', 'Servlet'],
                'Ruby': ['.rb', 'Rails', 'ruby'],
                '.NET': ['.aspx', '.ashx', 'ASP.NET']
            }
        }

    def _load_vuln_signatures(self):
        """Load vulnerability detection signatures"""
        return {
            'sqli_patterns': [
                r"You have an error in your SQL syntax",
                r"Warning: mysql",
                r"SQL syntax.*MySQL",
                r"Warning: pg_",
                r"Warning: oci_",
                r"Microsoft OLE DB Provider",
                r"Microsoft ODBC",
                r"Unclosed quotation mark",
                r"PostgreSQL.*ERROR",
                r"Driver.*SQL",
                r"SQLite.*Exception"
            ],
            'xss_patterns': [
                r"<script>.*</script>",
                r"javascript:",
                r"onerror=",
                r"onload=",
                r"onmouseover=",
                r"alert\(",
                r"document\.cookie",
                r"window\.location"
            ],
            'lfi_patterns': [
                r"root:.*:0:0:",
                r"\[boot loader\]",
                r"\[fonts\]",
                r"\[extensions\]",
                r"\[mail\]",
                r"\[MCX\]",
                r"\[orphans\]"
            ],
            'rce_patterns': [
                r"(?:root|daemon|bin|sys):[^:]*:[0-9]+:[0-9]+:",
                r"uid=[0-9]+\([^)]+\)",
                r"gid=[0-9]+\([^)]+\)",
                r"groups=[0-9]+\([^)]+\)",
                r"\\$\\{[^}]+\\}",
                r"\\$\\{[^}]+\\}",
                r"\\{\\{[^}]+\\}\\}"
            ],
            'info_leak_patterns': [
                r"(?i)(api[_-]?key|secret|password|token|auth)",
                r"[A-Za-z0-9+/=]{40,}",  # Base64 patterns
                r"eyJ[A-Za-z0-9+/=]*\.[A-Za-z0-9+/=]*\.[A-Za-z0-9+/=]*",  # JWT
                r"[0-9a-f]{32}",  # MD5
                r"[0-9a-f]{40}",  # SHA1
                r"[0-9a-f]{64}",  # SHA256
            ]
        }

    def _load_wordlists(self):
        """Load comprehensive wordlists for scanning"""
        return {
            'common_files': [
                'robots.txt', 'sitemap.xml', 'crossdomain.xml', 
                'clientaccesspolicy.xml', '.well-known/security.txt',
                '.git/HEAD', '.env', '.DS_Store', 'web.config',
                'phpinfo.php', 'test.php', 'info.php', 'admin.php'
            ],
            'admin_paths': [
                'admin', 'administrator', 'wp-admin', 'dashboard',
                'login', 'panel', 'cp', 'controlpanel', 'backend',
                'manager', 'system', 'root', 'config', 'setup',
                'install', 'update', 'upgrade', 'maintenance'
            ],
            'api_endpoints': [
                'api', 'api/v1', 'api/v2', 'graphql', 'rest',
                'soap', 'json', 'xmlrpc', 'webhook', 'webhooks',
                'oauth', 'auth', 'token', 'user', 'users'
            ],
            'backup_files': [
                '.bak', '.backup', '.old', '.orig', '.save',
                '.tmp', '.temp', '.swp', '.swo', '.copy'
            ]
        }

    def normalize_url(self, url):
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def extract_domain(self, url):
        """Extract domain from URL"""
        from urllib.parse import urlparse
        parsed = urlparse(url if '://' in url else 'https://' + url)
        return parsed.netloc

    def display_pro_banner(self):
        """Display professional banner"""
        banner = f"""
{Colors.BG_BLUE}{Colors.BOLD}{'═' * 80}{Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ╔═══════════════════════════════════════════════════════════════════════╗  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║                                                                       ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.PURPLE}██████╗ ██████╗  ██████╗ {Colors.CYAN}██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ {Colors.BOLD}  ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.PURPLE}██╔══██╗██╔══██╗██╔═══██╗{Colors.CYAN}██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗{Colors.BOLD}  ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.PURPLE}██████╔╝██████╔╝██║   ██║{Colors.CYAN}███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝{Colors.BOLD}  ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.PURPLE}██╔═══╝ ██╔══██╗██║   ██║{Colors.CYAN}██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗{Colors.BOLD}  ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.PURPLE}██║     ██║  ██║╚██████╔╝{Colors.CYAN}██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║{Colors.BOLD}  ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.PURPLE}╚═╝     ╚═╝  ╚═╝ ╚═════╝ {Colors.CYAN}╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.BOLD}  ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║                                                                       ║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ╠═══════════════════════════════════════════════════════════════════════╣  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.GREEN}⚡ PRO HUNTER v7.0 - Advanced Vulnerability Scanner              {Colors.BOLD}║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.YELLOW}🔍 Comprehensive Security Assessment Suite                         {Colors.BOLD}║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ║  {Colors.RED}⚔️  Ethical Hacking Tool - For Authorized Testing Only             {Colors.BOLD}║  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}  ╚═══════════════════════════════════════════════════════════════════════╝  {Colors.RESET}
{Colors.BG_BLUE}{Colors.BOLD}{'═' * 80}{Colors.RESET}

{Colors.CYAN}{'─' * 80}{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}🎯 TARGET:{Colors.RESET} {Colors.WHITE}{self.target}{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}🌐 DOMAIN:{Colors.RESET} {Colors.WHITE}{self.domain}{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}⚡ MODE:{Colors.RESET} {Colors.GREEN if self.stealth_mode else Colors.RED}{'STEALTH' if self.stealth_mode else 'AGGRESSIVE'}{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}🚀 THREADS:{Colors.RESET} {Colors.PURPLE}{self.max_threads}{Colors.RESET}
{Colors.BOLD}{Colors.YELLOW}📊 DEPTH:{Colors.RESET} {Colors.ORANGE}{self.scan_depth}{Colors.RESET}
{Colors.CYAN}{'─' * 80}{Colors.RESET}
        """
        return banner

    def log(self, message, level="INFO", color=None):
        """Log messages with colors and timestamps"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        level_colors = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.BG_RED + Colors.WHITE,
            "DEBUG": Colors.GRAY
        }
        
        level_icons = {
            "INFO": "ℹ",
            "SUCCESS": "✓",
            "WARNING": "⚠",
            "ERROR": "✗",
            "CRITICAL": "💀",
            "DEBUG": "🔧"
        }
        
        color = color or level_colors.get(level, Colors.WHITE)
        icon = level_icons.get(level, "•")
        
        print(f"{Colors.GRAY}[{timestamp}]{Colors.RESET} {color}[{icon}]{Colors.RESET} {message}")
        
        # Also add to discoveries for report
        if level in ["CRITICAL", "HIGH", "SUCCESS"]:
            self.results['discoveries'].append({
                'timestamp': timestamp,
                'level': level,
                'message': message
            })

    def make_request(self, url, method='GET', data=None, headers=None, allow_redirects=True):
        """Make HTTP request with stealth features"""
        if self.stealth_mode:
            time.sleep(random.uniform(0.5, 2.0))
        
        try:
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            # Rotate User-Agent
            if random.random() > 0.7:
                req_headers['User-Agent'] = random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                    "Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36"
                ])
            
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                headers=req_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False
            )
            
            self.results['statistics']['total_requests'] += 1
            
            return response
            
        except Exception as e:
            if not self.stealth_mode:
                self.log(f"Request failed: {str(e)[:50]}", "ERROR")
            return None

    # ============== CRAWLING & DISCOVERY ==============
    
    def crawl_website(self):
        """Crawl website to discover endpoints and content"""
        self.log("Starting website crawling...", "INFO")
        
        self.crawl_queue.append(self.target)
        
        depth = 0
        while self.crawl_queue and depth < self.scan_depth:
            current_url = self.crawl_queue.pop(0)
            
            if current_url in self.crawled_urls:
                continue
                
            self.crawled_urls.add(current_url)
            
            response = self.make_request(current_url)
            if not response:
                continue
                
            # Extract links
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urllib.parse.urljoin(current_url, href)
                
                if self.domain in full_url and full_url not in self.crawled_urls:
                    self.crawl_queue.append(full_url)
                    self.discovered_endpoints.append(full_url)
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                form_data = {
                    'action': form.get('action'),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for inp in form.find_all(['input', 'textarea', 'select']):
                    form_data['inputs'].append({
                        'name': inp.get('name'),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', '')
                    })
                
                if form_data['action']:
                    self.discovered_endpoints.append(urllib.parse.urljoin(current_url, form_data['action']))
            
            depth += 1
        
        self.log(f"Crawling completed. Found {len(self.discovered_endpoints)} endpoints", "SUCCESS")

    def fingerprint_technology(self):
        """Fingerprint technologies used by target"""
        self.log("Fingerprinting technologies...", "INFO")
        
        response = self.make_request(self.target)
        if not response:
            return
            
        headers = response.headers
        body = response.text
        
        detected_tech = []
        
        for category, techs in self.tech_signatures.items():
            for tech, signatures in techs.items():
                for sig in signatures:
                    if sig in str(headers) or sig in body:
                        if tech not in self.technologies:
                            self.technologies.add(tech)
                            detected_tech.append(f"{category}: {tech}")
                            break
        
        if detected_tech:
            self.log(f"Detected technologies: {', '.join(detected_tech)}", "SUCCESS")
            self.results['technology_stack'] = list(self.technologies)

    def discover_subdomains(self):
        """Discover subdomains using wordlist"""
        self.log("Discovering subdomains...", "INFO")
        
        subdomains = []
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'test',
            'dev', 'staging', 'api', 'mobile', 'webmail',
            'cpanel', 'whm', 'webdisk', 'ns1', 'ns2'
        ]
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomains.append(result)
                    self.log(f"Found subdomain: {result}", "SUCCESS")
        
        return subdomains

    # ============== VULNERABILITY SCANNING ==============
    
    def scan_sql_injection(self):
        """Advanced SQL injection scanning"""
        self.log("Scanning for SQL Injection vulnerabilities...", "INFO")
        
        test_payloads = [
            "'", "''", "`", "\"", "' OR '1'='1", "' OR '1'='1' --",
            "' OR 1=1--", "' OR 1=1#", "admin'--", "1' ORDER BY 1--",
            "1' AND SLEEP(5)--", "1' UNION SELECT NULL--",
            "1' UNION SELECT 1,2,3--", "1' AND 1=CAST(1 AS INT)--"
        ]
        
        vulnerable_endpoints = []
        
        for endpoint in self.discovered_endpoints[:20]:  # Limit to first 20
            if '?' in endpoint:
                for payload in test_payloads[:5]:  # Limit payloads
                    test_url = endpoint + payload
                    response = self.make_request(test_url)
                    
                    if response and response.status_code == 200:
                        # Check for SQL errors
                        for pattern in self.vuln_signatures['sqli_patterns']:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vulnerable_endpoints.append({
                                    'url': endpoint,
                                    'payload': payload,
                                    'evidence': re.search(pattern, response.text, re.IGNORECASE).group()[:100],
                                    'confidence': 'HIGH'
                                })
                                self.log(f"SQLi found at: {endpoint}", "CRITICAL")
                                break
        
        return vulnerable_endpoints

    def scan_xss(self):
        """Advanced XSS scanning"""
        self.log("Scanning for XSS vulnerabilities...", "INFO")
        
        test_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "onmouseover=alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        vulnerable_endpoints = []
        
        for endpoint in self.discovered_endpoints[:20]:
            if '?' in endpoint:
                for payload in test_payloads[:5]:
                    test_url = endpoint + payload
                    response = self.make_request(test_url)
                    
                    if response and payload in response.text:
                        vulnerable_endpoints.append({
                            'url': endpoint,
                            'payload': payload,
                            'evidence': f"Payload reflected in response",
                            'confidence': 'MEDIUM'
                        })
                        self.log(f"XSS found at: {endpoint}", "HIGH")
                        break
        
        return vulnerable_endpoints

    def scan_lfi(self):
        """Advanced Local File Inclusion scanning"""
        self.log("Scanning for LFI vulnerabilities...", "INFO")
        
        test_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../../etc/hosts",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            "file:///etc/passwd",
            "C:\\boot.ini",
            "/etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        vulnerable_endpoints = []
        
        for endpoint in self.discovered_endpoints[:15]:
            if '?' in endpoint:
                for payload in test_payloads[:4]:
                    test_url = endpoint + payload
                    response = self.make_request(test_url)
                    
                    if response and response.status_code == 200:
                        # Check for file contents
                        for pattern in self.vuln_signatures['lfi_patterns']:
                            if re.search(pattern, response.text):
                                vulnerable_endpoints.append({
                                    'url': endpoint,
                                    'payload': payload,
                                    'evidence': re.search(pattern, response.text).group()[:100],
                                    'confidence': 'HIGH'
                                })
                                self.log(f"LFI found at: {endpoint}", "CRITICAL")
                                break
        
        return vulnerable_endpoints

    def scan_rce(self):
        """Advanced Remote Code Execution scanning"""
        self.log("Scanning for RCE vulnerabilities...", "INFO")
        
        test_payloads = [
            {'payload': "{{7*7}}", 'expected': "49", 'type': 'template'},
            {'payload': "${7*7}", 'expected': "49", 'type': 'expression'},
            {'payload': "<?php echo 'RCE'; ?>", 'expected': "RCE", 'type': 'php'},
            {'payload': ";id", 'expected': "uid=", 'type': 'command'},
            {'payload': "|whoami", 'expected': "root", 'type': 'command'},
            {'payload': "`hostname`", 'expected': "localhost", 'type': 'command'}
        ]
        
        vulnerable_endpoints = []
        
        response = self.make_request(self.target)
        if not response:
            return vulnerable_endpoints
            
        baseline = response.text
        
        for endpoint in self.discovered_endpoints[:10]:
            if '?' in endpoint:
                for test in test_payloads[:3]:
                    test_url = endpoint + test['payload']
                    response = self.make_request(test_url)
                    
                    if response and response.status_code == 200:
                        if test['expected'] in response.text and test['expected'] not in baseline:
                            vulnerable_endpoints.append({
                                'url': endpoint,
                                'payload': test['payload'],
                                'type': test['type'],
                                'evidence': f"Expected output '{test['expected']}' found",
                                'confidence': 'HIGH'
                            })
                            self.log(f"RCE ({test['type']}) found at: {endpoint}", "CRITICAL")
                            break
        
        return vulnerable_endpoints

    def scan_sensitive_files(self):
        """Scan for sensitive files and directories"""
        self.log("Scanning for sensitive files...", "INFO")
        
        discovered_files = []
        
        def check_file(file_path):
            url = f"{self.target}/{file_path}"
            response = self.make_request(url)
            
            if response and response.status_code == 200:
                if response.status_code != 404:
                    discovered_files.append({
                        'url': url,
                        'status': response.status_code,
                        'size': len(response.text)
                    })
                    self.log(f"Found: {file_path} ({response.status_code})", "WARNING")
        
        # Check common files
        all_files = []
        all_files.extend(self.wordlists['common_files'])
        all_files.extend(self.wordlists['admin_paths'])
        all_files.extend(self.wordlists['api_endpoints'])
        
        # Check with backup extensions
        backup_files = []
        for file in all_files[:10]:  # Limit to first 10
            for ext in self.wordlists['backup_files']:
                backup_files.append(file + ext)
        
        all_files.extend(backup_files[:20])
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(check_file, all_files)
        
        return discovered_files

    def scan_info_leakage(self):
        """Scan for information leakage"""
        self.log("Scanning for information leakage...", "INFO")
        
        leaks = []
        response = self.make_request(self.target)
        
        if not response:
            return leaks
        
        # Check headers
        sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-backend-server']
        for header in sensitive_headers:
            if header in response.headers:
                leaks.append({
                    'type': 'HEADER_LEAK',
                    'header': header,
                    'value': response.headers[header],
                    'severity': 'LOW'
                })
        
        # Check response body
        for pattern_name, patterns in self.vuln_signatures.items():
            if 'leak' in pattern_name.lower():
                for pattern in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for match in matches[:5]:  # Limit matches
                        leaks.append({
                            'type': 'BODY_LEAK',
                            'pattern': pattern_name,
                            'match': match[:50] + '...' if len(match) > 50 else match,
                            'severity': 'MEDIUM'
                        })
        
        return leaks

    def scan_csrf(self):
        """Scan for CSRF vulnerabilities"""
        self.log("Scanning for CSRF vulnerabilities...", "INFO")
        
        csrf_issues = []
        response = self.make_request(self.target)
        
        if not response:
            return csrf_issues
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            has_csrf = False
            csrf_tokens = form.find_all('input', {'name': lambda x: x and any(token in x.lower() for token in ['csrf', 'token', '_token'])})
            
            if not csrf_tokens:
                csrf_issues.append({
                    'form_action': form.get('action', 'N/A'),
                    'form_method': form.get('method', 'GET'),
                    'issue': 'Missing CSRF token',
                    'severity': 'MEDIUM'
                })
        
        return csrf_issues

    # ============== MAIN SCAN FUNCTION ==============
    
    def comprehensive_scan(self):
        """Execute comprehensive security scan"""
        self.log(f"Starting comprehensive scan on {self.target}", "INFO")
        start_time = time.time()
        
        try:
            # Phase 1: Discovery
            self.log("Phase 1: Discovery & Reconnaissance", "INFO")
            self.crawl_website()
            self.fingerprint_technology()
            subdomains = self.discover_subdomains()
            
            # Phase 2: Vulnerability Scanning
            self.log("Phase 2: Vulnerability Assessment", "INFO")
            
            scan_results = {
                'sql_injection': self.scan_sql_injection(),
                'xss': self.scan_xss(),
                'lfi': self.scan_lfi(),
                'rce': self.scan_rce(),
                'sensitive_files': self.scan_sensitive_files(),
                'info_leakage': self.scan_info_leakage(),
                'csrf': self.scan_csrf()
            }
            
            # Phase 3: Analysis & Reporting
            self.log("Phase 3: Analysis & Reporting", "INFO")
            
            # Compile results
            for vuln_type, findings in scan_results.items():
                for finding in findings:
                    severity = self._determine_severity(vuln_type, finding)
                    
                    self.results['vulnerabilities'].append({
                        'type': vuln_type.upper().replace('_', ' '),
                        'severity': severity,
                        'details': finding,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Update statistics
                    if severity == 'CRITICAL':
                        self.results['statistics']['critical'] += 1
                    elif severity == 'HIGH':
                        self.results['statistics']['high'] += 1
                    elif severity == 'MEDIUM':
                        self.results['statistics']['medium'] += 1
                    elif severity == 'LOW':
                        self.results['statistics']['low'] += 1
                    else:
                        self.results['statistics']['info'] += 1
            
            # Update total
            self.results['statistics']['total_vulnerabilities'] = len(self.results['vulnerabilities'])
            self.results['statistics']['scan_duration'] = time.time() - start_time
            self.results['end_time'] = datetime.now().isoformat()
            
            # Generate report
            self.generate_report()
            
            return self.results
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
            return None

    def _determine_severity(self, vuln_type, finding):
        """Determine vulnerability severity"""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'rce': 'CRITICAL',
            'lfi': 'HIGH',
            'xss': 'MEDIUM',
            'csrf': 'MEDIUM',
            'info_leakage': 'LOW',
            'sensitive_files': 'LOW'
        }
        
        return severity_map.get(vuln_type, 'INFO')

    def generate_report(self):
        """Generate comprehensive scan report"""
        self.log("Generating scan report...", "INFO")
        
        # Console output
        print(f"\n{Colors.BG_BLUE}{'═' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}📊 SCAN REPORT SUMMARY{Colors.RESET}")
        print(f"{Colors.BG_BLUE}{'═' * 80}{Colors.RESET}\n")
        
        stats = self.results['statistics']
        
        # Statistics
        print(f"{Colors.CYAN}📈 Statistics:{Colors.RESET}")
        print(f"  {Colors.GREEN}✓ Total Requests:{Colors.RESET} {stats['total_requests']}")
        print(f"  {Colors.GREEN}✓ Scan Duration:{Colors.RESET} {stats['scan_duration']:.2f} seconds")
        print(f"  {Colors.GREEN}✓ Technologies Found:{Colors.RESET} {len(self.results['technology_stack'])}")
        print(f"  {Colors.GREEN}✓ Endpoints Discovered:{Colors.RESET} {len(self.discovered_endpoints)}")
        
        # Vulnerabilities by severity
        print(f"\n{Colors.RED}⚠ Vulnerabilities Found:{Colors.RESET}")
        print(f"  {Colors.RED}💀 Critical:{Colors.RESET} {stats['critical']}")
        print(f"  {Colors.ORANGE}🔥 High:{Colors.RESET} {stats['high']}")
        print(f"  {Colors.YELLOW}⚠ Medium:{Colors.RESET} {stats['medium']}")
        print(f"  {Colors.BLUE}ℹ Low:{Colors.RESET} {stats['low']}")
        print(f"  {Colors.GRAY}🔍 Info:{Colors.RESET} {stats['info']}")
        print(f"  {Colors.BOLD}📊 Total:{Colors.RESET} {stats['total_vulnerabilities']}")
        
        # Detailed findings
        if self.results['vulnerabilities']:
            print(f"\n{Colors.PURPLE}🔍 Detailed Findings:{Colors.RESET}")
            for i, vuln in enumerate(self.results['vulnerabilities'][:10], 1):  # Show first 10
                color = Colors.RED if vuln['severity'] == 'CRITICAL' else \
                       Colors.ORANGE if vuln['severity'] == 'HIGH' else \
                       Colors.YELLOW if vuln['severity'] == 'MEDIUM' else \
                       Colors.BLUE
                
                print(f"  {color}[{i}] {vuln['type']} ({vuln['severity']}){Colors.RESET}")
                if 'details' in vuln and 'url' in vuln['details']:
                    print(f"     {Colors.GRAY}URL: {vuln['details']['url'][:70]}...{Colors.RESET}")
        
        # Technology stack
        if self.results['technology_stack']:
            print(f"\n{Colors.CYAN}🛠️  Technology Stack:{Colors.RESET}")
            for tech in self.results['technology_stack'][:10]:
                print(f"  {Colors.GREEN}• {tech}{Colors.RESET}")
        
        # Save to file if requested
        if self.output_file:
            self.save_report_to_file()
        
        print(f"\n{Colors.BG_GREEN}{Colors.BLACK}✅ Scan completed successfully!{Colors.RESET}")
        print(f"{Colors.GRAY}{'─' * 80}{Colors.RESET}")

    def save_report_to_file(self):
        """Save report to file in multiple formats"""
        try:
            # JSON report
            json_filename = self.output_file if self.output_file.endswith('.json') else f"{self.output_file}.json"
            with open(json_filename, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            self.log(f"JSON report saved to: {json_filename}", "SUCCESS")
            
            # HTML report (simple)
            html_filename = self.output_file.replace('.json', '.html') if '.json' in self.output_file else f"{self.output_file}.html"
            self.generate_html_report(html_filename)
            self.log(f"HTML report saved to: {html_filename}", "SUCCESS")
            
            # CSV report
            csv_filename = self.output_file.replace('.json', '.csv') if '.json' in self.output_file else f"{self.output_file}.csv"
            self.generate_csv_report(csv_filename)
            self.log(f"CSV report saved to: {csv_filename}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Failed to save report: {str(e)}", "ERROR")

    def generate_html_report(self, filename):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pro Hunter Scan Report - {self.domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #0f0f23; color: #ccc; }}
                h1 {{ color: #ff6b6b; }}
                h2 {{ color: #4ecdc4; }}
                .critical {{ color: #ff4757; font-weight: bold; }}
                .high {{ color: #ffa502; }}
                .medium {{ color: #ffd32a; }}
                .low {{ color: #1e90ff; }}
                .info {{ color: #a4b0be; }}
                .card {{ background: #1a1a2e; padding: 20px; margin: 15px 0; border-radius: 10px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #2d3436; }}
            </style>
        </head>
        <body>
            <h1>🔥 Pro Hunter Security Scan Report</h1>
            <div class="card">
                <h2>📊 Scan Summary</h2>
                <p><strong>Target:</strong> {self.target}</p>
                <p><strong>Domain:</strong> {self.domain}</p>
                <p><strong>Scan ID:</strong> {self.results['scan_id']}</p>
                <p><strong>Start Time:</strong> {self.results['start_time']}</p>
                <p><strong>Duration:</strong> {self.results['statistics']['scan_duration']:.2f} seconds</p>
            </div>
            
            <div class="card">
                <h2>⚠ Vulnerability Statistics</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th></tr>
                    <tr><td class="critical">Critical</td><td>{self.results['statistics']['critical']}</td></tr>
                    <tr><td class="high">High</td><td>{self.results['statistics']['high']}</td></tr>
                    <tr><td class="medium">Medium</td><td>{self.results['statistics']['medium']}</td></tr>
                    <tr><td class="low">Low</td><td>{self.results['statistics']['low']}</td></tr>
                    <tr><td class="info">Info</td><td>{self.results['statistics']['info']}</td></tr>
                </table>
            </div>
            
            <div class="card">
                <h2>🔍 Discovered Vulnerabilities</h2>
                <table>
                    <tr><th>Type</th><th>Severity</th><th>Details</th></tr>
        """
        
        for vuln in self.results['vulnerabilities']:
            html += f"""
                    <tr>
                        <td>{vuln['type']}</td>
                        <td class="{vuln['severity'].lower()}">{vuln['severity']}</td>
                        <td>{str(vuln.get('details', {}))[:100]}...</td>
                    </tr>
            """
        
        html += """
                </table>
            </div>
            
            <div class="card">
                <h2>🛠️ Technology Stack</h2>
                <ul>
        """
        
        for tech in self.results['technology_stack']:
            html += f"<li>{tech}</li>"
        
        html += """
                </ul>
            </div>
            
            <footer>
                <p><strong>Generated by Pro Hunter v7.0</strong> | For authorized testing only</p>
            </footer>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

    def generate_csv_report(self, filename):
        """Generate CSV report"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Type', 'Severity', 'URL', 'Evidence', 'Timestamp'])
            
            # Write vulnerabilities
            for vuln in self.results['vulnerabilities']:
                details = vuln.get('details', {})
                url = details.get('url', 'N/A') if isinstance(details, dict) else 'N/A'
                evidence = details.get('evidence', 'N/A') if isinstance(details, dict) else str(details)[:100]
                
                writer.writerow([
                    vuln['type'],
                    vuln['severity'],
                    url,
                    evidence,
                    vuln['timestamp']
                ])

def main():
    parser = argparse.ArgumentParser(description='🔥 Pro Hunter - Advanced Vulnerability Scanner')
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('-t', '--timeout', type=int, default=20, help='Request timeout (default: 20)')
    parser.add_argument('-th', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-s', '--stealth', action='store_true', default=True, help='Enable stealth mode')
    parser.add_argument('-ns', '--no-stealth', action='store_false', dest='stealth', help='Disable stealth mode')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-o', '--output', help='Output report file (JSON/HTML/CSV)')
    
    args = parser.parse_args()
    
    try:
        # Initialize scanner
        scanner = ProHunterScanner(
            target=args.target,
            timeout=args.timeout,
            threads=args.threads,
            stealth=args.stealth,
            depth=args.depth,
            output=args.output
        )
        
        # Start comprehensive scan
        results = scanner.comprehensive_scan()
        
        if results:
            print(f"\n{Colors.GREEN}✅ Scan completed successfully!{Colors.RESET}")
            print(f"{Colors.GRAY}Report generated with {results['statistics']['total_vulnerabilities']} findings.{Colors.RESET}")
            
            if args.output:
                print(f"{Colors.CYAN}📁 Reports saved to:{Colors.RESET}")
                print(f"  • {args.output}.json (JSON)")
                print(f"  • {args.output}.html (HTML)")
                print(f"  • {args.output}.csv (CSV)")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠ Scan interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}💀 Scan failed: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()