from live_scanner import LiveScanner
import json

def verify():
    url = "http://testphp.vulnweb.com/artists.php?artist=1"
    print(f"--- Verifying Robust Scanner on {url} ---")
    
    scanner = LiveScanner(url, depth=0, verbose=True)
    try:
        report = scanner.run()
        print("\n--- Scan Report ---")
        print(json.dumps(report, indent=2))
        
        findings = report['vulnerabilities']
        has_sqli = any(f['type'] == 'SQL Injection' for f in findings)
        has_xss = any(f['type'] == 'Cross-Site Scripting' for f in findings)
        
        print("\n--- Summary ---")
        print(f"SQLi Found: {has_sqli}")
        print(f"XSS Found: {has_xss}")
        
        if not (has_sqli and has_xss):
            print("\nWARNING: Some expected vulnerabilities were NOT found.")
            print("This could be due to network timeouts on testphp.vulnweb.com.")
            
    finally:
        scanner.close()

if __name__ == "__main__":
    verify()
