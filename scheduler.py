# scheduler.py (للمسح المجدول)
#!/usr/bin/env python3
import schedule
import time
import subprocess
import datetime
import json
import os

class VulnScanScheduler:
    def __init__(self):
        self.scan_configs = self.load_config()
        
    def load_config(self):
        config_path = "/app/config/scan_schedule.json"
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}
    
    def run_scan(self, target, scan_type="full"):
        print(f"[{datetime.datetime.now()}] Running {scan_type} scan for {target}")
        
        cmd = ["python", "vulnscan_pro.py"]
        if scan_type == "quick":
            cmd.extend(["--quick", target])
        else:
            cmd.append(target)
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            self.save_report(target, result.stdout)
        except Exception as e:
            print(f"Scan failed: {e}")
    
    def save_report(self, target, output):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"/app/reports/scan_{target}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(output)
        print(f"Report saved: {filename}")

if __name__ == "__main__":
    scheduler = VulnScanScheduler()
    
    # Example scheduled scans
    schedule.every().day.at("02:00").do(
        scheduler.run_scan, "http://test-site.com", "full"
    )
    
    while True:
        schedule.run_pending()
        time.sleep(60)