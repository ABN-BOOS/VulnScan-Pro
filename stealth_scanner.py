#!/usr/bin/env python3
"""
Website Management Interface Discovery Tool
For authorized security testing and educational purposes only
"""

import requests
import time
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import sys
import os
import socket
import ssl
import json
from datetime import datetime
import hashlib

class StealthScanner:
    def __init__(self, target_url):
        """
        Initialize stealth scanner
        """
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.found_interfaces = []
        self.session = requests.Session()
        self.request_count = 0
        self.start_time = time.time()
        
        # Random user agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]
        
        # Common management interface paths
        self.management_paths = [
            # WordPress
            'wp-admin/', 'wp-login.php', 'wp-admin/admin-ajax.php',
            
            # Common paths
            'admin/', 'administrator/', 'admin.php', 'admin/login',
            'admin_area/', 'adminarea/', 'admincontrol/', 'adminpanel/',
            'backend/', 'backoffice/', 'cp/', 'controlpanel/',
            'dashboard/', 'management/', 'member/', 'moderator/',
            'panel/', 'private/', 'secret/', 'secure/',
            'sysadmin/', 'system/', 'webadmin/',
            
            # Authentication files
            'login.php', 'login.asp', 'signin.php', 'auth.php',
            'account/login', 'user/login', 'signin',
            
            # Control panels
            'cpanel/', 'whm/', 'webmail/', 'plesk/', 'directadmin/',
            'webmin/', 'hestiacp/', 'vestacp/',
            
            # Development
            'phpmyadmin/', 'pma/', 'mysql/', 'dbadmin/',
            'test/', 'debug/', 'console/', 'api/',
            
            # Backup and config
            'backup/', 'config/', 'configuration/', 'setup/',
            'install/', 'update/', 'upgrade/',
            
            # API endpoints
            'api/v1/', 'api/v2/', 'rest-api/', 'graphql',
            
            # Less common
            'moderator.php', 'operator/', 'staff/', 'support/',
            'manager/', 'webmaster/', 'root/', 'superuser/',
            
            # File extensions variations
            'admin.html', 'admin.htm', 'admin.cgi', 'admin.pl',
            'admin.aspx', 'admin.jsp', 'admin.cfm',
            
            # Subdirectory variations
            'app/admin/', 'system/admin/', 'cms/admin/',
            'myadmin/', 'siteadmin/', 'serveradmin/',
            'clientarea/', 'memberarea/', 'userarea/',
        ]
        
        # Random referers
        self.referers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://search.yahoo.com/',
            'https://duckduckgo.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
            'https://www.linkedin.com/',
            f'https://{self.domain}/',
            f'http://{self.domain}/'
        ]
        
        # Headers template
        self.headers_template = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
        }
        
        # Content indicators for management interfaces
        self.content_indicators = {
            'login': ['login', 'sign in', 'username', 'password', 'log in'],
            'dashboard': ['dashboard', 'control panel', 'overview', 'statistics'],
            'admin': ['admin', 'administrator', 'manage', 'settings'],
            'wordpress': ['wordpress', 'wp-admin', 'wp-login'],
            'joomla': ['joomla', 'com_', 'mod_login'],
            'drupal': ['drupal', 'drupal.settings'],
            'cpanel': ['cpanel', 'whm', 'webhost'],
            'plesk': ['plesk', 'parallels'],
            'webmin': ['webmin', 'usermin'],
            'phpmyadmin': ['phpmyadmin', 'pma_']
        }
        
        # Request delay configuration
        self.min_delay = 0.5
        self.max_delay = 2.0
        self.batch_size = 5
        
        # Results storage
        self.scan_log = []
        
    def print_logo(self):
        """
        Display tool logo
        """
        logo = """
        ╔═══════════════════════════════════════════════════╗
        ║     ███████╗████████╗███████╗ █████╗ ██╗  ██╗    ║
        ║     ██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║ ██╔╝    ║
        ║     ███████╗   ██║   █████╗  ███████║█████╔╝     ║
        ║     ╚════██║   ██║   ██╔══╝  ██╔══██║██╔═██╗     ║
        ║     ███████║   ██║   ███████╗██║  ██║██║  ██╗    ║
        ║     ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝    ║
        ║                                                   ║
        ║       Stealth Interface Discovery Scanner         ║
        ╚═══════════════════════════════════════════════════╝
        
        [!] For authorized security assessment only
        [!] Use only on systems you own or have permission to test
        """
        print(logo)
    
    def random_delay(self):
        """
        Add random delay between requests
        """
        delay = random.uniform(self.min_delay, self.max_delay)
        time.sleep(delay)
        
    def rotate_headers(self):
        """
        Rotate request headers for stealth
        """
        headers = self.headers_template.copy()
        headers['User-Agent'] = random.choice(self.user_agents)
        headers['Referer'] = random.choice(self.referers)
        
        # Add random headers
        if random.random() > 0.5:
            headers['X-Forwarded-For'] = f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        
        if random.random() > 0.7:
            headers['X-Requested-With'] = 'XMLHttpRequest'
            
        return headers
    
    def make_request(self, url_path, method='GET'):
        """
        Make stealthy HTTP request
        """
        full_url = urljoin(self.target_url + '/', url_path)
        
        try:
            # Rotate headers
            headers = self.rotate_headers()
            
            # Add random delay
            self.random_delay()
            
            # Make request
            if method == 'HEAD':
                response = self.session.head(
                    full_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
            else:
                response = self.session.get(
                    full_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                    verify=False
                )
            
            self.request_count += 1
            
            # Log request (stealth mode - minimal logging)
            if response.status_code < 400:
                self.scan_log.append({
                    'url': full_url,
                    'status': response.status_code,
                    'time': datetime.now().isoformat(),
                    'size': len(response.content) if hasattr(response, 'content') else 0
                })
            
            return response
            
        except requests.RequestException as e:
            # Simulate normal browser behavior on error
            time.sleep(random.uniform(1, 3))
            return None
            
    def check_interface(self, url_path):
        """
        Check if path leads to management interface
        """
        # First, use HEAD request to check existence
        response = self.make_request(url_path, 'HEAD')
        
        if not response or response.status_code >= 400:
            return False
        
        # If HEAD looks promising, do GET for content analysis
        if response.status_code == 200 or response.status_code == 403:
            response = self.make_request(url_path, 'GET')
            
            if not response:
                return False
                
            return self.analyze_response(response, url_path)
        
        return False
    
    def analyze_response(self, response, url_path):
        """
        Analyze response for management interface indicators
        """
        if response.status_code not in [200, 403, 301, 302]:
            return False
        
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Check if it's HTML content
        if 'text/html' not in content_type and 'application/xhtml+xml' not in content_type:
            return False
        
        content = response.text.lower()
        
        # Check for common interface indicators
        interface_score = 0
        detected_types = []
        
        for interface_type, keywords in self.content_indicators.items():
            for keyword in keywords:
                if keyword in content:
                    interface_score += 1
                    if interface_type not in detected_types:
                        detected_types.append(interface_type)
        
        # Check for form elements
        if '<form' in content and ('password' in content or 'passwd' in content):
            interface_score += 3
            
        # Check for specific titles
        page_title = self.extract_title(response.text)
        title_indicators = ['admin', 'login', 'dashboard', 'control', 'panel', 'manage']
        if any(indicator in page_title.lower() for indicator in title_indicators):
            interface_score += 2
        
        # Minimum score threshold
        if interface_score >= 2:
            result = {
                'url': urljoin(self.target_url + '/', url_path),
                'status': response.status_code,
                'title': page_title,
                'score': interface_score,
                'types': detected_types,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': content_type,
                'size': len(response.content),
                'redirect': response.history[0].url if response.history else None
            }
            
            # Fingerprint specific CMS/panels
            result['fingerprint'] = self.fingerprint_interface(content, response.headers)
            
            self.found_interfaces.append(result)
            return True
            
        return False
    
    def extract_title(self, html_content):
        """
        Extract page title from HTML
        """
        try:
            import re
            match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                title = re.sub(r'\s+', ' ', title)
                return title[:100]
        except:
            pass
        return "No title found"
    
    def fingerprint_interface(self, content, headers):
        """
        Fingerprint specific management interface
        """
        content_lower = content.lower()
        fingerprints = []
        
        # WordPress
        if 'wp-admin' in content_lower or 'wordpress' in content_lower:
            fingerprints.append('WordPress')
            
        # Joomla
        if 'joomla' in content_lower or 'com_content' in content_lower:
            fingerprints.append('Joomla')
            
        # Drupal
        if 'drupal' in content_lower:
            fingerprints.append('Drupal')
            
        # cPanel
        if 'cpanel' in content_lower:
            fingerprints.append('cPanel')
            
        # Plesk
        if 'plesk' in content_lower:
            fingerprints.append('Plesk')
            
        # phpMyAdmin
        if 'phpmyadmin' in content_lower or 'pma_' in content_lower:
            fingerprints.append('phpMyAdmin')
            
        # Custom check from headers
        server_header = headers.get('Server', '').lower()
        if 'cpanel' in server_header:
            fingerprints.append('cPanel (Server Header)')
        if 'plesk' in server_header:
            fingerprints.append('Plesk (Server Header)')
        
        return fingerprints if fingerprints else ['Unknown']
    
    def check_robots_txt(self):
        """
        Check robots.txt for disallowed paths
        """
        print("\n[+] Checking robots.txt...")
        response = self.make_request('robots.txt')
        
        if response and response.status_code == 200:
            lines = response.text.split('\n')
            admin_paths = []
            
            for line in lines:
                if 'disallow:' in line.lower():
                    path = line.split(':')[1].strip()
                    if path and '/' in path:
                        admin_paths.append(path.lstrip('/'))
            
            return admin_paths
        
        return []
    
    def check_sitemap(self):
        """
        Check sitemap.xml for paths
        """
        print("[+] Checking sitemap.xml...")
        response = self.make_request('sitemap.xml')
        
        if response and response.status_code == 200:
            import re
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
            return [urlparse(url).path.lstrip('/') for url in urls if self.domain in url]
        
        return []
    
    def port_scan(self):
        """
        Stealth port scanning for common admin ports
        """
        common_ports = {
            2082: 'cPanel',
            2083: 'cPanel SSL',
            2086: 'WHM',
            2087: 'WHM SSL',
            2095: 'Webmail',
            2096: 'Webmail SSL',
            8080: 'HTTP Alt',
            8443: 'HTTPS Alt',
            10000: 'Webmin',
            8888: 'HTTP Alt 2',
            2222: 'DirectAdmin',
            4643: 'Plesk',
        }
        
        print("\n[+] Scanning common management ports...")
        
        open_ports = []
        target_ip = socket.gethostbyname(self.domain.split(':')[0])
        
        for port, service in common_ports.items():
            try:
                # Stealth TCP SYN scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Send SYN
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    open_ports.append((port, service))
                    print(f"    [+] Port {port} open ({service})")
                    
                    # Check if it's a web interface
                    try:
                        url = f"http://{self.domain}:{port}"
                        if port in [2083, 2087, 2096, 8443, 4643]:
                            url = f"https://{self.domain}:{port}"
                        
                        self.make_request(url.replace(self.target_url, ''))
                    except:
                        pass
                
                sock.close()
                time.sleep(0.2)  # Delay between port checks
                
            except:
                pass
        
        return open_ports
    
    def dns_enumeration(self):
        """
        DNS enumeration for subdomains
        """
        print("[+] Performing DNS lookups...")
        subdomains = [
            'admin', 'administrator', 'cpanel', 'whm',
            'webmail', 'mail', 'secure', 'login',
            'dashboard', 'control', 'panel', 'manage',
            'server', 'host', 'cp', 'direct'
        ]
        
        found_subdomains = []
        
        for sub in subdomains:
            hostname = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(hostname)
                found_subdomains.append(hostname)
                print(f"    [+] Found: {hostname}")
                
                # Check the subdomain
                self.make_request(f"http://{hostname}".replace(self.target_url, ''))
            except:
                pass
            time.sleep(0.3)
        
        return found_subdomains
    
    def smart_scan(self):
        """
        Intelligent scanning with adaptive techniques
        """
        print("\n[+] Starting intelligent scan...")
        
        # Get additional paths from robots.txt and sitemap
        robot_paths = self.check_robots_txt()
        sitemap_paths = self.check_sitemap()
        
        all_paths = set(self.management_paths + robot_paths + sitemap_paths)
        
        print(f"[*] Total paths to scan: {len(all_paths)}")
        print("[*] Using stealth mode with randomized delays...")
        
        # Scan in small batches with delays
        paths_list = list(all_paths)
        total_paths = len(paths_list)
        
        for i in range(0, total_paths, self.batch_size):
            batch = paths_list[i:i + self.batch_size]
            
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(self.check_interface, path) for path in batch]
                
                for future in as_completed(futures):
                    try:
                        future.result(timeout=15)
                    except:
                        pass
            
            # Progress indicator
            progress = min(i + self.batch_size, total_paths)
            sys.stdout.write(f"\r[*] Progress: {progress}/{total_paths} paths scanned")
            sys.stdout.flush()
            
            # Random delay between batches
            if i + self.batch_size < total_paths:
                time.sleep(random.uniform(2, 5))
        
        print()
    
    def save_results(self, filename):
        """
        Save scan results to file
        """
        if not self.found_interfaces:
            return
        
        results = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'duration': time.time() - self.start_time,
            'requests_made': self.request_count,
            'interfaces_found': self.found_interfaces,
            'scan_log': self.scan_log[-100:]  # Last 100 requests
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            # Also save simple text report
            txt_filename = filename.replace('.json', '.txt')
            with open(txt_filename, 'w') as f:
                f.write(f"Scan Report for {self.target_url}\n")
                f.write(f"Time: {datetime.now()}\n")
                f.write(f"Duration: {time.time() - self.start_time:.2f} seconds\n")
                f.write(f"Requests made: {self.request_count}\n")
                f.write(f"Interfaces found: {len(self.found_interfaces)}\n\n")
                
                for interface in self.found_interfaces:
                    f.write(f"URL: {interface['url']}\n")
                    f.write(f"Status: {interface['status']}\n")
                    f.write(f"Title: {interface['title']}\n")
                    f.write(f"Score: {interface['score']}\n")
                    f.write(f"Types: {', '.join(interface['types'])}\n")
                    f.write(f"Fingerprint: {', '.join(interface['fingerprint'])}\n")
                    f.write("-" * 50 + "\n")
            
            print(f"\n[+] Results saved to: {filename}")
            print(f"[+] Text report saved to: {txt_filename}")
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def run_scan(self):
        """
        Execute complete stealth scan
        """
        self.print_logo()
        
        print(f"\n[+] Target: {self.target_url}")
        print(f"[+] Domain: {self.domain}")
        print(f"[+] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Stealth mode: Enabled")
        print(f"[+] Random delays: {self.min_delay}-{self.max_delay}s")
        print(f"[+] Batch size: {self.batch_size}")
        
        # Initial connection test
        print("\n[+] Testing initial connection...")
        try:
            response = self.make_request('')
            if response:
                print(f"[+] Server: {response.headers.get('Server', 'Unknown')}")
                print(f"[+] Response: {response.status_code}")
                print(f"[+] Technology: {response.headers.get('X-Powered-By', 'Unknown')}")
            else:
                print("[-] Connection failed")
                return
        except:
            print("[-] Connection test failed")
            return
        
        # Start scanning
        start_time = time.time()
        
        # Smart scanning
        self.smart_scan()
        
        # Additional reconnaissance
        if len(self.found_interfaces) < 5:  # Only if we haven't found much
            print("\n[+] Performing additional reconnaissance...")
            self.port_scan()
            self.dns_enumeration()
        
        # Display results
        self.display_results(start_time)
    
    def display_results(self, start_time):
        """
        Display scan results
        """
        duration = time.time() - start_time
        
        print(f"\n{'='*70}")
        print("SCAN RESULTS:")
        print('='*70)
        
        print(f"\n[*] Scan completed in {duration:.2f} seconds")
        print(f"[*] Total requests made: {self.request_count}")
        print(f"[*] Average requests/second: {self.request_count/duration:.2f}")
        
        if not self.found_interfaces:
            print("\n[-] No management interfaces detected")
            print("\n[+] Suggestions for manual inspection:")
            print("    1. Review JavaScript files for admin paths")
            print("    2. Check common backup file locations")
            print("    3. Examine HTTP headers for clues")
            print("    4. Look for commented paths in HTML source")
            print("    5. Try common default credentials if testing authorized")
        else:
            print(f"\n[+] Potential management interfaces found: {len(self.found_interfaces)}\n")
            
            # Sort by score
            self.found_interfaces.sort(key=lambda x: x['score'], reverse=True)
            
            for i, interface in enumerate(self.found_interfaces, 1):
                print(f"{i}. {interface['url']}")
                print(f"   ├─ Status: {interface['status']}")
                print(f"   ├─ Title: {interface['title'][:50]}")
                print(f"   ├─ Confidence: {'★' * min(5, interface['score'])} ({interface['score']}/10)")
                print(f"   ├─ Type: {', '.join(interface['types'])}")
                print(f"   ├─ Fingerprint: {', '.join(interface['fingerprint'])}")
                if interface['redirect']:
                    print(f"   └─ Redirects from: {interface['redirect']}")
                else:
                    print(f"   └─ Server: {interface['server']}")
                print()
        
        print('='*70)

def main():
    parser = argparse.ArgumentParser(
        description='Stealth Management Interface Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s http://192.168.1.1 -o scan_results.json
  %(prog)s https://target.site -t 5 -d 1.0
        """
    )
    
    parser.add_argument(
        'url',
        help='Target URL (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Save results to JSON file',
        default=None
    )
    
    parser.add_argument(
        '-t', '--threads',
        help='Maximum concurrent threads (default: 3)',
        type=int,
        default=3
    )
    
    parser.add_argument(
        '-d', '--delay',
        help='Maximum delay between requests in seconds (default: 2.0)',
        type=float,
        default=2.0
    )
    
    parser.add_argument(
        '-q', '--quiet',
        help='Quiet mode (minimal output)',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    # Warning and consent
    if not args.quiet:
        warning = """
        ⚠️  WARNING: This tool is for authorized security testing only!
        
        You must:
        1. Have explicit permission to test the target
        2. Own the target system OR have written authorization
        3. Comply with all applicable laws and regulations
        4. Use responsibly and ethically
        
        Unauthorized testing is illegal and unethical.
        """
        print(warning)
        
        consent = input("Do you agree to use this tool ethically and legally? (yes/NO): ")
        if consent.lower() != 'yes':
            print("\n[!] Scan cancelled. Always obtain proper authorization.")
            sys.exit(0)
    
    # Configure scanner
    scanner = StealthScanner(args.url)
    scanner.max_delay = args.delay
    scanner.batch_size = args.threads
    
    # Suppress warnings for cleaner output
    requests.packages.urllib3.disable_warnings()
    
    # Run scan
    scanner.run_scan()
    
    # Save results if requested
    if args.output:
        scanner.save_results(args.output)
    
    # Final warning
    print("\n" + "="*70)
    print("REMINDER: Use findings responsibly and only on authorized targets")
    print("="*70)

if __name__ == "__main__":
    main()