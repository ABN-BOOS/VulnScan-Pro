#!/usr/bin/env python3
import requests
import sys
import urllib.parse
import time
from colorama import Fore, Style, init
import urllib3

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class RealVulnerabilityScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.vulnerabilities = []
        self.start_time = time.time()
        
    def print_banner(self):
        """طباعة بانر السكربت"""
        banner = f"""
{Fore.CYAN + Style.BRIGHT}
╔═══════════════════════════════════════════════╗
║           REAL VULNERABILITY SCANNER          ║
║           {Fore.RED}FOCUSED ON CRITICAL FLAWS{Fore.CYAN}           ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {Fore.GREEN}{self.target}{Style.RESET_ALL}
Start Time: {time.ctime()}
{Fore.WHITE}{'='*60}{Style.RESET_ALL}
        """
        print(banner)
    
    def print_vulnerability(self, title, url, risk, evidence):
        """طباعة الثغرة المكتشفة"""
        risk_colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW, 
            'LOW': Fore.BLUE
        }
        
        color = risk_colors.get(risk, Fore.WHITE)
        
        print(f"\n{color}╔═══════════════════════════════════════════════╗")
        print(f"║ {risk:^45} ║")
        print(f"╚═══════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}🔍 Vulnerability:{Style.RESET_ALL} {Fore.WHITE}{title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🌐 URL:{Style.RESET_ALL} {Fore.GREEN}{url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📋 Evidence:{Style.RESET_ALL} {Fore.MAGENTA}{evidence}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}{'─'*60}{Style.RESET_ALL}")

        # حفظ الثغرة
        self.vulnerabilities.append({
            'title': title,
            'url': url,
            'risk': risk,
            'evidence': evidence,
            'timestamp': time.ctime()
        })
    
    def test_sql_injection_advanced(self):
        """فحص متقدم لثغرات SQL Injection"""
        print(f"\n{Fore.CYAN}[+] Testing Advanced SQL Injection...{Style.RESET_ALL}")
        
        # باراميترات شائعة
        params = ['id', 'user', 'product', 'category', 'page', 'search', 'username']
        
        for param in params:
            # payloads متقدمة
            payloads = [
                {"payload": "'", "type": "Syntax Error"},
                {"payload": "1' AND '1'='1", "type": "Boolean-Based"},
                {"payload": "1' AND SLEEP(5)--", "type": "Time-Based"},
                {"payload": "1' UNION SELECT 1,2,3--", "type": "Union-Based"},
                {"payload": "1' OR 1=1--", "type": "Always True"}
            ]
            
            for p in payloads:
                test_url = f"{self.target}/?{param}={p['payload']}"
                try:
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10, verify=False)
                    response_time = time.time() - start_time
                    
                    # كشف الأخطاء
                    sql_errors = [
                        "mysql_fetch", "sql syntax", "ora-", "postgresql", 
                        "microsoft odbc", "warning:", "mysql_num_rows",
                        "you have an error in your sql syntax"
                    ]
                    
                    error_found = any(error in response.text.lower() for error in sql_errors)
                    
                    # Time-Based Detection
                    time_based = response_time > 4
                    
                    # Content-Based Detection
                    content_based = "admin" in response.text.lower() or "password" in response.text.lower()
                    
                    if error_found:
                        self.print_vulnerability(
                            f"SQL Injection - {p['type']}",
                            test_url,
                            "CRITICAL",
                            f"Error detected with payload: {p['payload']}"
                        )
                        return True
                    
                    if time_based:
                        self.print_vulnerability(
                            f"SQL Injection - Time-Based",
                            test_url,
                            "HIGH",
                            f"Response delay: {response_time:.2f}s with payload: {p['payload']}"
                        )
                        return True
                        
                except Exception as e:
                    continue
        
        print(f"{Fore.GREEN}[+] No SQL Injection vulnerabilities found{Style.RESET_ALL}")
        return False
    
    def test_file_upload_vulnerability(self):
        """فحص ثغرات رفع الملفات"""
        print(f"\n{Fore.CYAN}[+] Testing File Upload Vulnerabilities...{Style.RESET_ALL}")
        
        # البحث عن صفحات رفع ملفات
        upload_paths = [
            '/upload', '/admin/upload', '/file/upload', 
            '/image/upload', '/attachment/upload'
        ]
        
        for path in upload_paths:
            test_url = f"{self.target}{path}"
            response = requests.get(test_url, timeout=8, verify=False)
            
            if response.status_code == 200:
                # تحقق من وجود حقول رفع ملفات
                if 'type="file"' in response.text or 'enctype="multipart/form-data"' in response.text:
                    self.print_vulnerability(
                        "File Upload Page Discovered",
                        test_url,
                        "MEDIUM",
                        "File upload form found - Manual testing required"
                    )
                    return True
        
        print(f"{Fore.GREEN}[+] No file upload pages found{Style.RESET_ALL}")
        return False
    
    def test_admin_panels(self):
        """فحص لوحات التحكم المخفية"""
        print(f"\n{Fore.CYAN}[+] Scanning for Admin Panels...{Style.RESET_ALL}")
        
        admin_paths = [
            '/admin', '/administrator', '/wp-admin', '/admin.php',
            '/dashboard', '/controlpanel', '/manager', '/backend',
            '/cpanel', '/webadmin', '/admin/login', '/admin/admin'
        ]
        
        found_panels = []
        for path in admin_paths:
            test_url = f"{self.target}{path}"
            response = requests.get(test_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                # تحقق من أن الصفحة هي فعلاً لوحة تحكم
                if any(keyword in response.text.lower() for keyword in ['login', 'password', 'username', 'admin', 'dashboard']):
                    found_panels.append(test_url)
                    self.print_vulnerability(
                        "Admin Panel Discovered",
                        test_url,
                        "HIGH",
                        f"Admin interface accessible - Status: {response.status_code}"
                    )
        
        if not found_panels:
            print(f"{Fore.GREEN}[+] No admin panels found{Style.RESET_ALL}")
        
        return len(found_panels) > 0
    
    def test_xss_vulnerability(self):
        """فحص ثغرات XSS"""
        print(f"\n{Fore.CYAN}[+] Testing for XSS Vulnerabilities...{Style.RESET_ALL}")
        
        params = ['q', 'search', 'query', 'name', 'message', 'comment']
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for param in params:
            for payload in xss_payloads:
                test_url = f"{self.target}/?{param}={urllib.parse.quote(payload)}"
                response = requests.get(test_url, timeout=8, verify=False)
                
                # تحقق إذا الpayload رجع في الresponse
                if payload in response.text:
                    self.print_vulnerability(
                        "Cross-Site Scripting (XSS)",
                        test_url,
                        "HIGH",
                        f"XSS payload reflected: {payload}"
                    )
                    return True
        
        print(f"{Fore.GREEN}[+] No XSS vulnerabilities found{Style.RESET_ALL}")
        return False
    
    def test_command_injection(self):
        """فحص ثغرات تنفيذ الأوامر"""
        print(f"\n{Fore.CYAN}[+] Testing for Command Injection...{Style.RESET_ALL}")
        
        params = ['cmd', 'command', 'exec', 'ping', 'host']
        cmd_payloads = [
            "; whoami", "| id", "&& cat /etc/passwd", 
            "'; uname -a;'", '| dir'
        ]
        
        for param in params:
            for payload in cmd_payloads:
                test_url = f"{self.target}/?{param}={urllib.parse.quote(payload)}"
                response = requests.get(test_url, timeout=8, verify=False)
                
                # تحقق من وجود مخرجات الأوامر
                if any(output in response.text for output in ['root', 'uid=', 'etc/passwd', 'Linux', 'Windows']):
                    self.print_vulnerability(
                        "Command Injection",
                        test_url,
                        "CRITICAL",
                        f"Command output detected with payload: {payload}"
                    )
                    return True
        
        print(f"{Fore.GREEN}[+] No command injection vulnerabilities found{Style.RESET_ALL}")
        return False
    
    def generate_report(self):
        """توليد تقرير نهائي"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"                 REAL VULNERABILITY SCAN REPORT")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        total_vulns = len(self.vulnerabilities)
        critical_vulns = len([v for v in self.vulnerabilities if v['risk'] == 'CRITICAL'])
        high_vulns = len([v for v in self.vulnerabilities if v['risk'] == 'HIGH'])
        
        print(f"{Fore.CYAN}[>] Target:{Style.RESET_ALL} {self.target}")
        print(f"{Fore.CYAN}[>] Scan Duration:{Style.RESET_ALL} {time.time() - self.start_time:.2f}s")
        print(f"{Fore.CYAN}[>] Total Vulnerabilities:{Style.RESET_ALL} {total_vulns}")
        print(f"{Fore.CYAN}[>] Critical:{Style.RESET_ALL} {critical_vulns}")
        print(f"{Fore.CYAN}[>] High:{Style.RESET_ALL} {high_vulns}")
        
        if total_vulns > 0:
            print(f"\n{Fore.YELLOW}🔍 CRITICAL FINDINGS:{Style.RESET_ALL}")
            for vuln in self.vulnerabilities:
                if vuln['risk'] in ['CRITICAL', 'HIGH']:
                    print(f"\n{Fore.RED}⚠️  {vuln['title']}{Style.RESET_ALL}")
                    print(f"   URL: {vuln['url']}")
                    print(f"   Evidence: {vuln['evidence']}")
        else:
            print(f"\n{Fore.GREEN}🎉 No critical vulnerabilities found!{Style.RESET_ALL}")
    
    def full_scan(self):
        """مسح كامل للموقع"""
        self.print_banner()
        
        # تشغيل الفحوصات الأساسية
        tests = [
            self.test_sql_injection_advanced,
            self.test_xss_vulnerability,
            self.test_command_injection,
            self.test_admin_panels,
            self.test_file_upload_vulnerability
        ]
        
        for test in tests:
            test()
            time.sleep(1)  # فواصل بين الاختبارات
        
        # التقرير النهائي
        self.generate_report()

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python3 real_scanner.py TARGET_URL{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python3 real_scanner.py https://example.com{Style.RESET_ALL}")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = RealVulnerabilityScanner(target)
    scanner.full_scan()

if __name__ == "__main__":
    main()