import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from urllib.robotparser import RobotFileParser
import time
import re
from typing import List, Dict, Set

class LiveScanner:
    ALLOWED_DOMAINS = [
        "testphp.vulnweb.com",
        "dvwa.local",
        "localhost",
        "127.0.0.1",
        "juice-shop.herokuapp.com"
    ]

    def __init__(self, base_url: str, depth: int = 1, verbose: bool = True, timeout: float = 15.0):
        self.base_url = base_url.rstrip('/')
        self.max_depth = min(depth, 1) # Force depth 1 for performance
        self.max_pages = 10 # Reduced to 10
        self.verbose = verbose
        self.visited = set()
        self.findings = []
        
        # Security & Speed settings
        self.delay = 0.5  # Slightly faster delay
        self.timeout = timeout
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OpenMythos/2.0"
        
        self.client = httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": self.user_agent}
        )
        
        self.rp = RobotFileParser()
        self.robots_loaded = False
        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc.lower()

    def log(self, msg):
        if self.verbose:
            print(f"[DAST] {msg}")

    def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        hostname = parsed.hostname.lower() if parsed.hostname else parsed.netloc.lower()
        
        # Strict Domain Check
        domain_ok = any(hostname == allowed or hostname.endswith(f".{allowed}") for allowed in self.ALLOWED_DOMAINS) or hostname.endswith('.test')
        if not domain_ok:
            return False
            
        # Robots.txt check
        if self.robots_loaded:
            if not self.rp.can_fetch(self.user_agent, url):
                self.log(f"Blocked by robots.txt: {url}")
                return False
        
        return True

    def load_robots(self):
        try:
            robots_url = urljoin(self.base_url, "/robots.txt")
            resp = self.fetch_with_retry(robots_url)
            if resp and resp.status_code == 200:
                self.rp.parse(resp.text.splitlines())
                self.robots_loaded = True
        except: pass

    def fetch_with_retry(self, url: str, method: str = "GET", data: Dict = None, params: Dict = None):
        for attempt in range(2):
            try:
                time.sleep(self.delay)
                if method == "GET":
                    return self.client.get(url, params=params)
                else:
                    return self.client.post(url, data=data)
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                self.log(f"Attempt {attempt+1} failed for {url}: {e}")
                if attempt == 1: raise
        return None

    def run(self):
        self.log(f"Starting professional scan on {self.base_url}")
        if not self.is_allowed(self.base_url):
            self.log(f"Domain {self.domain} is NOT authorized for scanning.")
            return {"status": "error", "message": f"Domain {self.domain} is not in whitelist."}
        
        self.load_robots()
        
        # Get baseline for anomaly detection
        try:
            baseline_resp = self.fetch_with_retry(self.base_url)
            self.baseline_len = len(baseline_resp.text) if baseline_resp else 0
        except:
            self.baseline_len = 0

        self.crawl_and_scan(self.base_url, 0)
        
        return self.generate_report()

    def crawl_and_scan(self, url: str, current_depth: int):
        if url in self.visited or current_depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        
        if not self.is_allowed(url):
            return

        self.visited.add(url)
        self.log(f"Crawling {url} (Depth {current_depth})")
        
        try:
            resp = self.fetch_with_retry(url)
            if not resp or resp.status_code != 200:
                return
            
            # Extract parameters from URL if any
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                self.test_all_vulnerabilities(url, "GET", params)

            # Extract and test forms
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                self.handle_form(url, form)

            # Crawl links
            if current_depth < self.max_depth:
                links = soup.find_all('a', href=True)
                for a in links:
                    next_url = urljoin(url, a['href'])
                    # Stay on same domain
                    if urlparse(next_url).netloc.lower() == self.domain:
                        # Strip fragments
                        next_url = next_url.split('#')[0]
                        self.crawl_and_scan(next_url, current_depth + 1)
                        
        except Exception as e:
            self.log(f"Error scanning {url}: {e}")

    def handle_form(self, base_url: str, form):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        target_url = urljoin(base_url, action)
        
        inputs = {}
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inputs[name] = inp.get('value', '1')
        
        if inputs:
            self.log(f"Found form at {base_url} -> {target_url} ({method})")
            self.test_all_vulnerabilities(target_url, method.upper(), {k: [v] for k, v in inputs.items()})

    def test_all_vulnerabilities(self, url: str, method: str, params: Dict[str, List[str]]):
        for param in params:
            # SQL Injection
            sqli_payloads = ["'", "' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL--"]
            for p in sqli_payloads:
                if self.test_sqli(url, method, param, p): break

            # XSS
            xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>"]
            for p in xss_payloads:
                if self.test_xss(url, method, param, p): break
            
            # Command Injection
            cmd_payloads = ["; ls", "| dir", "$(whoami)"]
            for p in cmd_payloads:
                if self.test_cmd_injection(url, method, param, p): break

    def test_sqli(self, url: str, method: str, param: str, payload: str) -> bool:
        self.log(f"Testing SQLi on {param} with {payload}")
        try:
            resp = self.send_payload(url, method, param, payload)
            if not resp: return False
            
            text = resp.text.lower()
            errors = [
                "sql syntax", "mysql_fetch", "you have an error", "unclosed quotation mark",
                "warning: mysql", "sqlite3.error", "postgresql error", "oracle error", "odbc driver"
            ]
            
            # Error based
            if any(err in text for err in errors):
                self.add_finding(url, "SQL Injection", "critical", param, payload, "SQL error message in response")
                return True
                
            # Content-length based anomaly
            if self.baseline_len > 0:
                diff = abs(len(resp.text) - self.baseline_len) / self.baseline_len
                if diff > 0.25:
                    self.add_finding(url, "SQL Injection", "high", param, payload, "Significant response length anomaly")
                    return True
        except: pass
        return False

    def test_xss(self, url: str, method: str, param: str, payload: str) -> bool:
        self.log(f"Testing XSS on {param} with {payload}")
        try:
            resp = self.send_payload(url, method, param, payload)
            if not resp: return False
            
            # Check for unescaped reflection
            if payload in resp.text and "&lt;" not in resp.text and "script" in resp.text.lower():
                self.add_finding(url, "Cross-Site Scripting", "high", param, payload, "Payload reflected unescaped")
                return True
        except: pass
        return False

    def test_cmd_injection(self, url: str, method: str, param: str, payload: str) -> bool:
        self.log(f"Testing Cmd Injection on {param} with {payload}")
        try:
            resp = self.send_payload(url, method, param, payload)
            if not resp: return False
            
            evidence = ["root:x:", "bin/bash", "directory of", "total ", "Volume in drive"]
            if any(ev in resp.text.lower() for ev in evidence):
                self.add_finding(url, "Command Injection", "critical", param, payload, "System command output detected")
                return True
        except: pass
        return False

    def send_payload(self, url: str, method: str, param: str, payload: str):
        try:
            if method == "GET":
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[param] = [payload]
                new_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
                return self.fetch_with_retry(new_url, "GET")
            else:
                data = {param: payload}
                return self.fetch_with_retry(url, "POST", data=data)
        except: return None

    def add_finding(self, url: str, vuln_type: str, severity: str, param: str, payload: str, evidence: str):
        finding = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "description": f"Detected {vuln_type} on {url} via parameter '{param}'.",
            "exploitation": f"Injecting '{payload}' resulted in: {evidence}",
            "fix": "Use parameterized queries, sanitize inputs, and employ context-aware encoding.",
            "source": "live-scan"
        }
        # Avoid duplicates
        if not any(f['url'] == url and f['type'] == vuln_type and f['parameter'] == param for f in self.findings):
            self.findings.append(finding)
            self.log(f"‼️  VULNERABILITY FOUND: {vuln_type} on {param}")

    def close(self):
        try:
            self.client.close()
        except: pass

    def generate_report(self):
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            summary[f['severity']] += 1
        
        risk_score = min(100, summary['critical']*30 + summary['high']*20 + summary['medium']*10)
        
        return {
            "status": "success",
            "vulnerabilities": self.findings,
            "summary": summary,
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score > 70 else "high" if risk_score > 40 else "medium" if risk_score > 15 else "low",
            "metadata": {
                "pages_scanned": len(self.visited),
                "scan_type": "live-v4-robust",
                "base_url": self.base_url
            }
        }