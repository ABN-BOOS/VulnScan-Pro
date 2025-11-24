
                    #!/usr/bin/env python3
import requests
import sys
import urllib.parse
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import json
from colorama import Fore, Style, Back, init

# تهيئة الألوان
init(autoreset=True)

class AdvancedServerScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.vulnerabilities = []
        self.start_time = time.time()
        
    def print_banner(self):
        """طباعة بانر ملون"""
        banner = f"""
{Fore.CYAN + Style.BRIGHT}
╔═══════════════════════════════════════════════╗
║           ADVANCED SERVER SCANNER             ║
║           {Fore.YELLOW}VULNERABILITY ASSESSMENT TOOL{Fore.CYAN}        ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {Fore.GREEN}{self.target}{Style.RESET_ALL}
Start Time: {time.ctime()}
{Fore.WHITE}{'='*60}{Style.RESET_ALL}
        """
        print(banner)
    
    def print_status(self, message, status="INFO"):
        """طباعة حالة الفحص"""
        status_colors = {
            "INFO": Fore.BLUE,
            "SCANNING": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED
        }
        
        color = status_colors.get(status, Fore.WHITE)
        print(f"{color}[{status}] {message}{Style.RESET_ALL}")
    
    def print_vulnerability(self, vuln_type, url, risk, payload=None):
        """طباعة الثغرة بشكل منظم مثل VulnScan Pro"""
        
        risk_colors = {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW, 
            'LOW': Fore.BLUE,
            'INFO': Fore.CYAN
        }
        
        color = risk_colors.get(risk, Fore.WHITE)
        
        # الرأس حسب مستوى الخطورة
        print(f"\n{color}╔═══════════════════════════════════════════════╗")
        print(f"║ {risk:^45} ║")
        print(f"╚═══════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # تفاصيل الثغرة
        print(f"{Fore.CYAN}🔍 Type:{Style.RESET_ALL} {Fore.WHITE}{vuln_type}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🌐 URL:{Style.RESET_ALL} {Fore.GREEN}{url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚠️  Risk:{Style.RESET_ALL} {color}{risk}{Style.RESET_ALL}")
        if payload:
            print(f"{Fore.CYAN}🎯 Payload:{Style.RESET_ALL} {Fore.MAGENTA}{payload}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🕒 Time:{Style.RESET_ALL} {time.ctime()}")
        print(f"{Fore.WHITE}{'─'*60}{Style.RESET_ALL}")

        # حفظ الثغرة
        self.vulnerabilities.append({
            'type': vuln_type,
            'url': url,
            'risk': risk,
            'payload': payload,
            'timestamp': time.ctime()
        })
    
    def test_sql_injection(self):
        """فحص ثغرات SQL Injection بنظام الإخراج الجديد"""
        self.print_status(f"Testing SQL Injection on {self.target}", "SCANNING")
        
        test_params = ['id', 'user', 'product', 'category', 'page', 'article']
        payloads = [
            {"payload": "'", "description": "Basic SQL Syntax"},
            {"payload": "1' OR '1'='1'--", "description": "Authentication Bypass"},
            {"payload": "1' UNION SELECT 1,2,3--", "description": "Data Extraction"},
            {"payload": "1' AND SLEEP(5)--", "description": "Time-Based Detection"}
        ]
        
        for param in test_params:
            for p in payloads:
                test_urls = [
                    f"{self.target}/?{param}={p['payload']}",
                    f"{self.target}/product?{param}={p['payload']}",
                    f"{self.target}/article?{param}={p['payload']}"
                ]
                
                for test_url in test_urls:
                    try:
                        start_time = time.time()
                        response = requests.get(test_url, timeout=10, verify=False)
                        response_time = time.time() - start_time
                        
                        # كشف الأخطاء
                        sql_errors = {
                            "mysql": ["mysql_fetch", "mysql_num_rows", "mysqli_"],
                            "mssql": ["microsoft odbc", "sql server", "odbc driver"],
                            "oracle": ["ora-", "oracle error"],
                            "postgresql": ["postgresql", "pg_"],
                            "generic": ["sql syntax", "warning:", "syntax error"]
                        }
                        
                        for db_type, errors in sql_errors.items():
                            if any(error in response.text.lower() for error in errors):
                                self.print_vulnerability(
                                    f"SQL Injection ({db_type.upper()})",
                                    test_url,
                                    "CRITICAL",
                                    f"{p['payload']} - {p['description']}"
                                )
                                return True
                        
                        # Time-Based Detection
                        if response_time > 5:
                            self.print_vulnerability(
                                "SQL Injection (Time-Based)",
                                test_url,
                                "HIGH", 
                                f"{p['payload']} - Delayed response: {response_time:.2f}s"
                            )
                            return True
                            
                    except Exception as e:
                        continue
        
        self.print_status("No SQL Injection vulnerabilities found", "SUCCESS")
        return False
    
    def test_file_inclusion(self):
        """فحص ثغرات File Inclusion"""
        self.print_status(f"Testing File Inclusion on {self.target}", "SCANNING")
        
        lfi_payloads = [
            {"payload": "../../../../etc/passwd", "description": "Linux Password File"},
            {"payload": "../../../../windows/win.ini", "description": "Windows Config"},
            {"payload": "../../../../etc/hosts", "description": "Hosts File"},
            {"payload": "....//....//....//etc/passwd", "description": "Double Encoding"}
        ]
        
        params = ['file', 'page', 'load', 'path', 'doc', 'template']
        
        for param in params:
            for p in lfi_payloads:
                test_url = f"{self.target}/?{param}={p['payload']}"
                try:
                    response = requests.get(test_url, timeout=8, verify=False)
                    
                    # كشف الملفات
                    if "root:" in response.text:
                        self.print_vulnerability(
                            "Local File Inclusion",
                            test_url,
                            "HIGH",
                            f"{p['payload']} - {p['description']}"
                        )
                        return True
                    elif "[extensions]" in response.text:
                        self.print_vulnerability(
                            "Local File Inclusion", 
                            test_url,
                            "HIGH",
                            f"{p['payload']} - Windows file detected"
                        )
                        return True
                        
                except:
                    pass
        
        self.print_status("No File Inclusion vulnerabilities found", "SUCCESS")
        return False
    
    def test_sensitive_files(self):
        """فحص الملفات الحساسة"""
        self.print_status(f"Scanning for sensitive files on {self.target}", "SCANNING")
        
        sensitive_files = [
            {"path": "/.env", "risk": "HIGH", "description": "Environment Variables"},
            {"path": "/config.php", "risk": "CRITICAL", "description": "PHP Configuration"},
            {"path": "/config.json", "risk": "HIGH", "description": "Application Config"},
            {"path": "/.git/config", "risk": "MEDIUM", "description": "Git Configuration"},
            {"path": "/backup.sql", "risk": "CRITICAL", "description": "Database Backup"},
            {"path": "/admin.php", "risk": "MEDIUM", "description": "Admin Panel"},
            {"path": "/phpinfo.php", "risk": "HIGH", "description": "PHP Info Disclosure"},
            {"path": "/.htaccess", "risk": "LOW", "description": "Server Configuration"},
            {"path": "/web.config", "risk": "MEDIUM", "description": "IIS Configuration"},
            {"path": "/robots.txt", "risk": "LOW", "description": "Search Engine Rules"}
        ]
        
        found_files = []
        for file_info in sensitive_files:
            test_url = f"{self.target}{file_info['path']}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200:
                    self.print_vulnerability(
                        f"Sensitive File Exposure - {file_info['description']}",
                        test_url,
                        file_info['risk'],
                        f"File: {file_info['path']} | Size: {len(response.content)} bytes"
                    )
                    found_files.append(test_url)
                    
                    # حفظ المحتوى الحساس
                    if file_info['risk'] in ['CRITICAL', 'HIGH']:
                        filename = f"found_{file_info['path'].replace('/', '')}.txt"
                        with open(filename, "w", encoding='utf-8') as f:
                            f.write(response.text)
                        self.print_status(f"File content saved: {filename}", "INFO")
            except:
                pass
        
        if not found_files:
            self.print_status("No sensitive files found", "SUCCESS")
        
        return len(found_files) > 0
    
    def generate_detailed_report(self):
        """توليد تقرير تفصيلي مثل VulnScan Pro"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"                 ADVANCED SERVER SCANNER - DETAILED REPORT")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        total_vulns = len(self.vulnerabilities)
        high_vulns = len([v for v in self.vulnerabilities if v['risk'] in ['CRITICAL', 'HIGH']])
        medium_vulns = len([v for v in self.vulnerabilities if v['risk'] == 'MEDIUM'])
        low_vulns = len([v for v in self.vulnerabilities if v['risk'] == 'LOW'])
        
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Target:{Style.RESET_ALL} {Fore.GREEN}{self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Scan Date:{Style.RESET_ALL} {time.ctime()}")
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Scan Duration:{Style.RESET_ALL} {time.time() - self.start_time:.2f}s")
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Total Vulnerabilities:{Style.RESET_ALL} {total_vulns}")
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}High/Critical:{Style.RESET_ALL} {high_vulns}")
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Medium:{Style.RESET_ALL} {medium_vulns}")
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Low:{Style.RESET_ALL} {low_vulns}")
        
        # حساب مستوى الخطورة
        risk_score = (high_vulns * 3) + (medium_vulns * 2) + (low_vulns * 1)
        if risk_score >= 10:
            risk_level = "CRITICAL"
        elif risk_score >= 5:
            risk_level = "HIGH" 
        elif risk_score >= 2:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        print(f"{Fore.CYAN}[>]{Style.RESET_ALL} {Fore.WHITE}Overall Risk Score:{Style.RESET_ALL} {risk_score} ({risk_level})")
        
        if total_vulns > 0:
            print(f"\n{Fore.YELLOW}🔍 DETAILED VULNERABILITY FINDINGS:{Style.RESET_ALL}")
            print(f"{Fore.WHITE}{'='*80}{Style.RESET_ALL}")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                color = Fore.RED if vuln['risk'] in ['CRITICAL', 'HIGH'] else Fore.YELLOW if vuln['risk'] == 'MEDIUM' else Fore.BLUE
                
                print(f"\n{color}📌 VULNERABILITY #{i}: {vuln['type']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}   🔸 Risk Level: {vuln['risk']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}   🔸 URL: {vuln['url']}{Style.RESET_ALL}")
                if vuln.get('payload'):
                    print(f"{Fore.WHITE}   🔸 Payload: {vuln['payload']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}   🔸 Timestamp: {vuln['timestamp']}{Style.RESET_ALL}")
                print(f"{Fore.WHITE}   {'─'*60}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}🎉 No vulnerabilities found! The target appears to be secure.{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    
    def generate_html_report(self):
        """توليد تقرير HTML ملون"""
        html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: white; }}
        .banner {{ background: linear-gradient(45deg, #ff6b6b, #4ecdc4); padding: 20px; border-radius: 10px; text-align: center; }}
        .vulnerability {{ background: #2d2d2d; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 5px solid; }}
        .critical {{ border-color: #ff4757; }}
        .high {{ border-color: #ffa502; }}
        .medium {{ border-color: #ffdd59; }}
        .low {{ border-color: #2ed573; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ background: #34495e; padding: 15px; border-radius: 5px; text-align: center; }}
    </style>
</head>
<body>
    <div class="banner">
        <h1>🛡️ Security Scan Report</h1>
        <h2>Target: {self.target}</h2>
        <p>Scan Date: {time.ctime()} | Duration: {time.time() - self.start_time:.2f}s</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Total Vulnerabilities</h3>
            <h2>{len(self.vulnerabilities)}</h2>
        </div>
        <div class="stat-box">
            <h3>Critical</h3>
            <h2>{len([v for v in self.vulnerabilities if v['risk'] == 'CRITICAL'])}</h2>
        </div>
        <div class="stat-box">
            <h3>High</h3>
            <h2>{len([v for v in self.vulnerabilities if v['risk'] == 'HIGH'])}</h2>
        </div>
    </div>
    
    <h2>📋 Vulnerability Details</h2>
        """
        
        for vuln in self.vulnerabilities:
            risk_class = vuln['risk'].lower()
            html_report += f"""
    <div class="vulnerability {risk_class}">
        <h3>🔍 {vuln['type']}</h3>
        <p><strong>Risk:</strong> <span style="color: {'#ff4757' if vuln['risk'] == 'CRITICAL' else '#ffa502' if vuln['risk'] == 'HIGH' else '#ffdd59' if vuln['risk'] == 'MEDIUM' else '#2ed573'}">{vuln['risk']}</span></p>
        <p><strong>URL:</strong> <a href="{vuln['url']}" style="color: #4ecdc4;">{vuln['url']}</a></p>
        <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
        <p><strong>Time:</strong> {vuln['timestamp']}</p>
    </div>
            """
        
        html_report += """
</body>
</html>
        """
        
        with open("security_report.html", "w", encoding='utf-8') as f:
            f.write(html_report)
        
        self.print_status(f"HTML report generated: security_report.html", "SUCCESS")
    
    def full_scan(self):
        """مسح كامل مع المخرجات المنظمة"""
        self.print_banner()
        
        # تشغيل جميع الفحوصات
        scan_methods = [
            ("SQL Injection", self.test_sql_injection),
            ("File Inclusion", self.test_file_inclusion),
            ("Sensitive Files", self.test_sensitive_files)
        ]
        
        for scan_name, scan_method in scan_methods:
            self.print_status(f"Starting {scan_name} scan...", "SCANNING")
            scan_method()
            time.sleep(1)  # فواصل بين الفحوصات
        
        # التقرير التفصيلي النهائي
        self.generate_detailed_report()
        self.generate_html_report()
        
        # طباعة الملخص النهائي
        print(f"""
{Fore.CYAN + Style.BRIGHT}
╔═══════════════════════════════════════════════╗
║                 SCAN COMPLETED                ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.GREEN}✓ Target:{Style.RESET_ALL} {self.target}
{Fore.GREEN}✓ Duration:{Style.RESET_ALL} {time.time() - self.start_time:.2f}s
{Fore.GREEN}✓ Vulnerabilities Found:{Style.RESET_ALL} {len(self.vulnerabilities)}

{Fore.YELLOW}📁 Reports Generated:{Style.RESET_ALL}
  • {Fore.CYAN}security_report.html{Style.RESET_ALL} - Interactive HTML report
  • {Fore.CYAN}found_*.txt files{Style.RESET_ALL} - Sensitive file contents

{Fore.MAGENTA}🔧 Next Steps:{Style.RESET_ALL}
  1. Review the detailed report above
  2. Analyze each vulnerability
  3. Implement security patches
  4. Rescan after fixes
        """)

def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python3 advanced_server_scanner.py TARGET_URL{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python3 advanced_server_scanner.py https://example.com{Style.RESET_ALL}")
        sys.exit(1)
    
    # تثبيت colorama إذا غير مثبت
    try:
        import colorama
    except ImportError:
        print("Installing colorama...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
        import colorama
        colorama.init()
    
    target = sys.argv[1]
    scanner = AdvancedServerScanner(target)
    scanner.full_scan()

if __name__ == "__main__":
    main()