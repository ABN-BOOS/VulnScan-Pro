#!/usr/bin/env python3
"""
Unified Advanced Server Vulnerability Scanner
Combines server_scanner.py, server2_scanner.py, and advanced_server_scanner.py
"""

import socket
import ssl
import requests
import concurrent.futures
import ipaddress
import re
import json
import time
import argparse
import sys
import os
from datetime import datetime
from urllib.parse import urlparse

# ==================== PROFESSIONAL BANNER ====================
def display_banner():
    """Display professional colorful banner for VulnScan Pro"""
    
    # For systems that support colors
    if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        try:
            # Modern ASCII Art with colors
            banner = """
            \033[1;36m╔══════════════════════════════════════════════════════════════╗\033[0m
            \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;35m╦  ╦╔═╗╔╗╔╔═╗╔╦╗  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╦╗╦ ╦╔═╗╦═╗\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;35m║  ║╠═╣║║║╠═╣║║║  ╠═╝╠═╣ ║║  ╚═╗║ ║ ║ ╠═╣║╣ ╠╦╝\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;35m╩═╝╩╩ ╩╝╚╝╩ ╩╩ ╩  ╩  ╩ ╩═╩╝  ╚═╝╚═╝ ╩ ╩ ╩╚═╝╩╚═\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;33m┌──────────────────────────────────────────────┐\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;33m│\033[0m \033[1;32m🔍  ADVANCED VULNERABILITY SCANNING SUITE  🔍\033[0m \033[1;33m│\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;33m│\033[0m \033[1;34m🚀  Unified • Intelligent • Professional  🚀\033[0m \033[1;33m│\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;33m└──────────────────────────────────────────────┘\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m                                                              \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;95m[➕] Port Scanning    [🔓] Vulnerability Detection\033[0m  \033[1;36m║\033[0m
            \033[1;36m║\033[0m  \033[1;95m[👁️] Stealth Mode     [📊] Advanced Reporting   \033[0m  \033[1;36m║\033[0m
            \033[1;36m╚══════════════════════════════════════════════════════════════╝\033[0m
            """
            print(banner)
            
            # Version info
            version_line = f"\033[1;33m{'═' * 60}\033[0m"
            print(f"{version_line}")
            print(f"\033[1;32mVersion 2.0 | Professional Edition | Python {sys.version_info.major}.{sys.version_info.minor}\033[0m")
            print(f"\033[1;36mDeveloped for Security Professionals | Use Responsibly\033[0m")
            print(f"{version_line}\n")
            
        except:
            # Fallback to simple banner if colors fail
            display_simple_banner()
    else:
        # For non-TTY environments (pipes, redirects)
        display_simple_banner()

def display_simple_banner():
    """Display simple banner for non-color environments"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║  ╦  ╦╔═╗╔╗╔╔═╗╔╦╗  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╦╗╦ ╦╔═╗╦═╗           ║
    ║  ║  ║╠═╣║║║╠═╣║║║  ╠═╝╠═╣ ║║  ╚═╗║ ║ ║ ╠═╣║╣ ╠╦╝           ║
    ║  ╩═╝╩╩ ╩╝╚╝╩ ╩╩ ╩  ╩  ╩ ╩═╩╝  ╚═╝╚═╝ ╩ ╩ ╩╚═╝╩╚═           ║
    ║                                                              ║
    ║  ┌──────────────────────────────────────────────┐           ║
    ║  │  🔍  ADVANCED VULNERABILITY SCANNING SUITE  │           ║
    ║  │  🚀  Unified • Intelligent • Professional    │           ║
    ║  └──────────────────────────────────────────────┘           ║
    ║                                                              ║
    ║  [➕] Port Scanning    [🔓] Vulnerability Detection          ║
    ║  [👁️] Stealth Mode     [📊] Advanced Reporting             ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)
    print("═" * 60)
    print("Version 2.0 | Professional Edition | Unified Server Scanner")
    print("Developed for Security Professionals | Use Responsibly")
    print("═" * 60 + "\n")

def display_scan_start(target, ports, mode):
    """Display scan initiation message"""
    print(f"\033[1;34m[+] Initializing Scan Session\033[0m")
    print(f"\033[1;36m    Target:\033[0m \033[1;33m{target}\033[0m")
    print(f"\033[1;36m    Ports: \033[0m \033[1;33m{ports}\033[0m")
    print(f"\033[1;36m    Mode:  \033[0m \033[1;33m{mode}\033[0m")
    print(f"\033[1;36m    Time:  \033[0m \033[1;33m{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
    print(f"\033[1;34m[+] Starting scan...\033[0m\n")

# ==================== VULNERABILITY INTELLIGENCE ====================
class VulnerabilityIntelligence:
    """Advanced vulnerability detection engine"""
    
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
    
    VULNERABLE_SERVICE_PATTERNS = {
        'ProFTPD 1.3.5': 'CVE-2015-3306 - Mod_copy vulnerability',
        'OpenSSH 7.4': 'CVE-2018-15473 - User enumeration',
        'Apache 2.4.17': 'CVE-2016-5387 - HTTPoxy',
        'nginx 1.13.0': 'CVE-2017-7529 - Integer overflow',
        'MySQL 5.7.0': 'CVE-2016-6662 - Privilege escalation',
        'vsftpd 2.3.4': 'CVE-2011-2523 - Backdoor command execution',
        'Samba 3.5.0': 'CVE-2017-7494 - Remote code execution',
        'Redis 4.0.0': 'Unauthenticated access - Data exposure'
    }
    
    SECURITY_HEADERS = {
        'X-Frame-Options': 'Missing - Clickjacking risk',
        'Content-Security-Policy': 'Missing - XSS protection weak',
        'X-Content-Type-Options': 'Missing - MIME sniffing possible',
        'Strict-Transport-Security': 'Missing - SSL stripping risk',
        'X-XSS-Protection': 'Missing - Browser XSS filter disabled'
    }
    
    @staticmethod
    def analyze_banner(banner, port, service_name=''):
        """Analyze service banner for known vulnerabilities"""
        findings = []
        banner_lower = banner.lower()
        
        # Check for vulnerable versions
        for pattern, description in VulnerabilityIntelligence.VULNERABLE_SERVICE_PATTERNS.items():
            if pattern.lower() in banner_lower:
                findings.append({
                    'type': 'VULNERABLE_VERSION',
                    'port': port,
                    'service': service_name,
                    'risk': 'HIGH',
                    'description': description,
                    'evidence': f"Banner contains: {pattern}"
                })
        
        # Check for anonymous access indicators
        anonymous_keywords = ['anonymous', 'guest', 'login ok', 'access granted']
        if any(keyword in banner_lower for keyword in anonymous_keywords):
            findings.append({
                'type': 'ANONYMOUS_ACCESS',
                'port': port,
                'service': service_name,
                'risk': 'MEDIUM',
                'description': 'Anonymous access allowed - Security misconfiguration',
                'evidence': 'Banner suggests anonymous login'
            })
        
        return findings
    
    @staticmethod
    def check_ssl_tls(host, port):
        """Check for weak SSL/TLS configurations"""
        findings = []
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    if protocol in VulnerabilityIntelligence.WEAK_PROTOCOLS:
                        findings.append({
                            'type': 'WEAK_SSL_PROTOCOL',
                            'port': port,
                            'service': 'SSL/TLS',
                            'risk': 'HIGH',
                            'description': f'Weak protocol detected: {protocol}',
                            'evidence': f'Protocol: {protocol}, Cipher: {cipher[0]}'
                        })
                    
                    # Check certificate
                    cert = ssock.getpeercert()
                    if cert:
                        not_after = cert.get('notAfter', '')
                        if not_after:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry_date - datetime.now()).days
                            if days_left < 30:
                                findings.append({
                                    'type': 'SSL_CERT_EXPIRING',
                                    'port': port,
                                    'service': 'SSL/TLS',
                                    'risk': 'MEDIUM',
                                    'description': f'SSL certificate expires in {days_left} days',
                                    'evidence': f'Expiry: {not_after}'
                                })
        except Exception as e:
            pass
        
        return findings
    
    @staticmethod
    def analyze_http_headers(headers, port):
        """Analyze HTTP headers for security issues"""
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, description in VulnerabilityIntelligence.SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower not in headers_lower:
                findings.append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'port': port,
                    'service': 'HTTP',
                    'risk': 'LOW',
                    'description': description,
                    'evidence': f'Missing header: {header}'
                })
        
        # Check for information disclosure
        info_headers = ['server', 'x-powered-by', 'x-aspnet-version']
        for header in info_headers:
            if header in headers_lower:
                findings.append({
                    'type': 'INFO_DISCLOSURE',
                    'port': port,
                    'service': 'HTTP',
                    'risk': 'LOW',
                    'description': f'Information disclosure in {header} header',
                    'evidence': f'{header}: {headers_lower[header]}'
                })
        
        return findings

# ==================== STEALTH ENGINE ====================
class StealthEngine:
    """Stealth scanning techniques"""
    
    @staticmethod
    def get_random_user_agent():
        """Rotate user agents to avoid fingerprinting"""
        import random
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'curl/7.68.0',
            'python-requests/2.25.1',
            'Wget/1.20.3',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ]
        return random.choice(agents)
    
    @staticmethod
    def calculate_delay(mode='normal'):
        """Calculate random delays between requests"""
        import random
        
        delays = {
            'aggressive': (0.1, 0.3),
            'normal': (0.5, 2.0),
            'stealthy': (3.0, 10.0),
            'paranoid': (15.0, 30.0)
        }
        
        min_delay, max_delay = delays.get(mode, (0.5, 2.0))
        return random.uniform(min_delay, max_delay)
    
    @staticmethod
    def fragment_scan(target_ports, fragments=3):
        """Split port scan into fragments to avoid detection"""
        fragment_size = len(target_ports) // fragments
        fragments_list = []
        
        for i in range(fragments):
            start = i * fragment_size
            end = (i + 1) * fragment_size if i < fragments - 1 else len(target_ports)
            fragments_list.append(target_ports[start:end])
        
        return fragments_list

# ==================== MAIN SCANNER CLASS ====================
class UnifiedServerScanner:
    """Main scanner class combining all features"""
    
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }
    
    def __init__(self, stealth_mode='normal', max_threads=50, timeout=3):
        self.stealth_mode = stealth_mode
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = []
        self.vulnerabilities = []
        self.scan_start_time = None
        self.scan_end_time = None
        
    def scan_port(self, target, port):
        """Scan a single port with advanced detection"""
        try:
            # Apply stealth delay
            delay = StealthEngine.calculate_delay(self.stealth_mode)
            time.sleep(delay)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                service_name = self.COMMON_PORTS.get(port, 'Unknown')
                
                # Try to get banner
                banner = self.get_banner(sock, port)
                
                # Basic service detection
                service_info = {
                    'port': port,
                    'state': 'OPEN',
                    'service': service_name,
                    'banner': banner[:500] if banner else 'No banner'
                }
                
                # Advanced vulnerability analysis
                if banner:
                    vuln_findings = VulnerabilityIntelligence.analyze_banner(banner, port, service_name)
                    self.vulnerabilities.extend(vuln_findings)
                
                # SSL/TLS check for HTTPS and secure ports
                if port in [443, 8443, 993, 995, 465, 587]:
                    ssl_findings = VulnerabilityIntelligence.check_ssl_tls(target, port)
                    self.vulnerabilities.extend(ssl_findings)
                
                # HTTP analysis for web ports
                if port in [80, 443, 8080, 8443, 8888]:
                    http_findings = self.analyze_http_service(target, port)
                    self.vulnerabilities.extend(http_findings)
                
                self.results.append(service_info)
                sock.close()
                
                # Display colorful result
                self.display_port_result(port, service_name, banner)
                return service_info
            else:
                sock.close()
                return None
                
        except Exception as e:
            return None
    
    def display_port_result(self, port, service, banner):
        """Display port scan result with colors"""
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            service_color = "\033[1;32m"  # Green for service
            port_color = "\033[1;36m"     # Cyan for port
            reset = "\033[0m"
            
            if 'HTTP' in service or 'HTTPS' in service:
                service_color = "\033[1;33m"  # Yellow for web services
            
            print(f"{port_color}[+] {reset}Port {port_color}{port:<5}{reset} - {service_color}{service:<15}{reset}", end="")
            
            if banner and banner != 'No banner':
                banner_preview = banner[:50].replace('\n', ' ').replace('\r', '')
                print(f" | {banner_preview}...")
            else:
                print()
        else:
            print(f"[+] Port {port:<5} - {service:<15}")
    
    def get_banner(self, sock, port):
        """Attempt to retrieve service banner"""
        try:
            # Send probe based on common service
            if port == 22:  # SSH
                sock.send(b'SSH-2.0-Client\r\n')
            elif port == 80 or port == 443 or port == 8080 or port == 8443:  # HTTP/S
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:  # FTP
                sock.send(b'\r\n')
            elif port == 25:  # SMTP
                sock.send(b'EHLO example.com\r\n')
            else:
                sock.send(b'\r\n')
            
            # Receive response
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner.strip()
        except:
            return None
    
    def analyze_http_service(self, target, port):
        """Analyze HTTP/HTTPS service for vulnerabilities"""
        findings = []
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}"
            
            headers = {'User-Agent': StealthEngine.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            
            # Analyze headers
            header_findings = VulnerabilityIntelligence.analyze_http_headers(response.headers, port)
            findings.extend(header_findings)
            
            # Check for common paths
            common_paths = ['/phpinfo.php', '/admin/', '/test/', '/backup/', '/wp-admin/']
            for path in common_paths:
                try:
                    test_url = url + path
                    resp = requests.head(test_url, headers=headers, timeout=3, verify=False)
                    if resp.status_code == 200:
                        findings.append({
                            'type': 'EXPOSED_PATH',
                            'port': port,
                            'service': 'HTTP',
                            'risk': 'MEDIUM',
                            'description': f'Exposed sensitive path: {path}',
                            'evidence': f'URL: {test_url}'
                        })
                except:
                    pass
                    
        except Exception as e:
            pass
        
        return findings
    
    def generate_port_list(self, port_spec):
        """Generate list of ports from specification"""
        ports = []
        
        if port_spec == 'common':
            ports = list(self.COMMON_PORTS.keys())
        elif port_spec == 'top100':
            ports = list(self.COMMON_PORTS.keys())[:100]
        elif port_spec == 'top1000':
            ports = list(range(1, 1001))
        elif port_spec == 'all':
            ports = list(range(1, 65536))
        elif '-' in port_spec:
            # Range like 1-1000
            start, end = map(int, port_spec.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_spec:
            # Comma separated list
            ports = [int(p.strip()) for p in port_spec.split(',')]
        else:
            # Single port
            ports = [int(port_spec)]
        
        return ports
    
    def scan(self, target, ports='common'):
        """Main scanning function"""
        self.scan_start_time = datetime.now()
        
        # Display scan start info
        display_scan_start(target, ports, self.stealth_mode)
        
        # Generate port list
        target_ports = self.generate_port_list(ports)
        
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            print(f"\033[1;34m[+] Scanning {len(target_ports)} ports with {self.max_threads} threads\033[0m")
        else:
            print(f"[+] Scanning {len(target_ports)} ports with {self.max_threads} threads")
        
        # Stealth: fragment scan if in stealthy mode
        if self.stealth_mode in ['stealthy', 'paranoid']:
            fragments = StealthEngine.fragment_scan(target_ports, fragments=5)
            print(f"\033[1;33m[+] Fragmenting scan into {len(fragments)} parts for stealth\033[0m")
            
            for i, fragment in enumerate(fragments):
                if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
                    print(f"\033[1;36m[+] Fragment {i+1}/{len(fragments)}: {len(fragment)} ports\033[0m")
                else:
                    print(f"[+] Fragment {i+1}/{len(fragments)}: {len(fragment)} ports")
                
                self.scan_fragment(target, fragment)
                if i < len(fragments) - 1:
                    fragment_delay = StealthEngine.calculate_delay('stealthy') * 10
                    time.sleep(fragment_delay)
        else:
            self.scan_fragment(target, target_ports)
        
        self.scan_end_time = datetime.now()
        scan_duration = self.scan_end_time - self.scan_start_time
        
        # Display summary
        self.display_scan_summary(scan_duration)
        
        return self.results, self.vulnerabilities
    
    def display_scan_summary(self, duration):
        """Display scan summary with colors"""
        print()
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            summary_line = "\033[1;35m" + "═" * 50 + "\033[0m"
            print(summary_line)
            print("\033[1;32m[+] SCAN COMPLETED SUCCESSFULLY\033[0m")
            print(f"\033[1;36m    Duration:      \033[1;33m{duration}\033[0m")
            print(f"\033[1;36m    Open Ports:    \033[1;33m{len(self.results)}\033[0m")
            print(f"\033[1;36m    Vulnerabilities Found: \033[1;31m{len(self.vulnerabilities)}\033[0m")
            print(summary_line)
        else:
            print("=" * 50)
            print("[+] SCAN COMPLETED SUCCESSFULLY")
            print(f"    Duration:      {duration}")
            print(f"    Open Ports:    {len(self.results)}")
            print(f"    Vulnerabilities Found: {len(self.vulnerabilities)}")
            print("=" * 50)
    
    def scan_fragment(self, target, ports):
        """Scan a fragment of ports"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    future.result()
                except Exception as e:
                    pass
    
    def generate_report(self, output_format='text'):
        """Generate scan report"""
        report = {
            'scan_info': {
                'start_time': self.scan_start_time.isoformat() if self.scan_start_time else None,
                'end_time': self.scan_end_time.isoformat() if self.scan_end_time else None,
                'duration': str(self.scan_end_time - self.scan_start_time) if self.scan_start_time and self.scan_end_time else None,
                'scanner': 'VulnScan Pro Unified Scanner v2.0'
            },
            'open_ports': self.results,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_ports_scanned': len(self.results) + sum(1 for r in self.results if r.get('state') == 'closed'),
                'open_ports_count': len(self.results),
                'vulnerabilities_count': len(self.vulnerabilities)
            }
        }
        
        if output_format == 'json':
            return json.dumps(report, indent=2, default=str)
        else:
            # Text format with some styling
            text_report = "\n" + "=" * 60 + "\n"
            text_report += "VULNSCAN PRO - SCAN REPORT\n"
            text_report += "=" * 60 + "\n\n"
            
            text_report += f"Scan Duration: {report['scan_info']['duration']}\n"
            text_report += f"Scanner: {report['scan_info']['scanner']}\n"
            text_report += f"Open Ports: {report['summary']['open_ports_count']}\n"
            text_report += f"Vulnerabilities Found: {report['summary']['vulnerabilities_count']}\n\n"
            
            text_report += "OPEN PORTS:\n" + "-" * 40 + "\n"
            for port_info in self.results:
                text_report += f"Port {port_info['port']}: {port_info['service']}\n"
                if port_info['banner'] and port_info['banner'] != 'No banner':
                    text_report += f"  Banner: {port_info['banner'][:100]}...\n"
            
            if self.vulnerabilities:
                text_report += "\nVULNERABILITIES:\n" + "-" * 40 + "\n"
                for vuln in self.vulnerabilities:
                    risk_color = {
                        'HIGH': '[!]',
                        'MEDIUM': '[-]',
                        'LOW': '[.]'
                    }.get(vuln['risk'], '[?]')
                    
                    text_report += f"{risk_color} {vuln['type']} on port {vuln['port']} ({vuln['risk']})\n"
                    text_report += f"     Description: {vuln['description']}\n"
                    if 'evidence' in vuln:
                        text_report += f"     Evidence: {vuln['evidence'][:80]}...\n"
                    text_report += "\n"
            
            text_report += "=" * 60 + "\n"
            text_report += "Report generated by VulnScan Pro v2.0\n"
            text_report += "=" * 60
            
            return text_report

# ==================== MAIN FUNCTION ====================
def main():
    # Display banner first
    display_banner()
    
    parser = argparse.ArgumentParser(
        description='VulnScan Pro - Unified Advanced Server Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s 192.168.1.1 -p 1-1000 -s stealthy -t 20
  %(prog)s target.com -p "80,443,8080" -o report.json --format json
  %(prog)s 10.0.0.1 -p all -s paranoid -t 10
        
Scan Modes:
  aggressive  - Fast scanning, high detection risk
  normal      - Balanced speed and stealth
  stealthy    - Slow scanning, low detection risk  
  paranoid    - Very slow, minimal detection risk
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Ports to scan: common, top100, top1000, all, or range (1-1000), or list (80,443,8080)')
    parser.add_argument('-s', '--stealth', default='normal', 
                       choices=['aggressive', 'normal', 'stealthy', 'paranoid'],
                       help='Stealth mode')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Maximum threads (default: 50)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--format', default='text', choices=['text', 'json'],
                       help='Output format')
    
    args = parser.parse_args()
    
    try:
        scanner = UnifiedServerScanner(
            stealth_mode=args.stealth,
            max_threads=args.threads,
            timeout=3
        )
        
        results, vulnerabilities = scanner.scan(args.target, args.ports)
        
        report = scanner.generate_report(args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\033[1;32m[+] Report saved to {args.output}\033[0m")
        else:
            print(report)
            
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan interrupted by user\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[1;31m[!] Error: {e}\033[0m")
        sys.exit(1)

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] VulnScan Pro terminated by user\033[0m")
        sys.exit(0)