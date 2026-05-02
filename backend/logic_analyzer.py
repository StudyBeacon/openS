import re
from typing import List, Dict

class LogicAnalyzer:
    """
    Advanced Logic Flaw Analyzer (Regex Heuristics V3)
    Deep audit for auth bypass and state machine logic flaws.
    """
    def analyze(self, code: str) -> List[Dict]:
        findings = []
        
        # Pattern 1: Email Verification Bypass (STRICT Audit)
        # Matches /verify routes that select 'verified' but update it without checking the value.
        verify_route_pattern = r'@app\.route\([\'"]/verify[\'"]\).*?def\s+verify\(\):.*?SELECT.*?verified.*?FROM.*?WHERE.*?email.*?token.*?UPDATE.*?verified\s*=\s*1'
        if re.search(verify_route_pattern, code, re.DOTALL | re.IGNORECASE):
            # Check if the UPDATE is conditional on verified being 0 in the WHERE clause
            # AND check if there is an explicit Python 'if verified' guard
            has_where_guard = re.search(r'WHERE\s+verified\s*=\s*0', code, re.IGNORECASE)
            has_python_guard = re.search(r'if\s+verified.*?:.*?return', code, re.IGNORECASE)
            
            if not (has_where_guard or has_python_guard):
                findings.append({
                    "type": "Email Verification Bypass",
                    "severity": "critical",
                    "line": 1,
                    "description": "Verification endpoint does not prevent re-verification of already verified accounts. Stale verification tokens can be reused.",
                    "fix": "Add a condition: if verified: return 'Already verified' or WHERE verified = 0",
                    "corrected_code": "if verified: return 'Account already verified'",
                    "exploitation": "Attacker reuses a valid verification token to verify an account that was already verified, possibly bypassing security monitors.",
                    "source": "logic-engine"
                })

        # Pattern 2: Password reset IDOR (Token Linkage Audit)
        if re.search(r"@app\.route\(['\"]/reset_password['\"].*?methods\s*=\s*\[.*?POST.*?\]", code, re.DOTALL | re.IGNORECASE):
            has_secure_query = re.search(r"WHERE.*?email\s*=\s*\?\s*AND\s+reset_token\s*=\s*\?", code, re.IGNORECASE)
            has_token_check = re.search(r"if\s+.*token.*==.*reset_token", code, re.IGNORECASE)
            
            if not (has_secure_query or has_token_check):
                findings.append({
                    "type": "Password Reset IDOR / Token Bypass",
                    "severity": "critical",
                    "line": 1,
                    "description": "Password reset updates password based only on email, without validating reset_token linkage.",
                    "fix": "Query by both email AND token: WHERE email = ? AND reset_token = ?",
                    "corrected_code": "cur.execute('UPDATE users SET password_hash = ? WHERE email = ? AND reset_token = ?', (new_hash, email, token))",
                    "exploitation": "Attacker can reset any user's password by providing their email and any arbitrary token.",
                    "source": "logic-engine"
                })

        # Pattern 3: Sequential state updates (Race Condition)
        race_pattern = r'cur\.execute\([\'"]UPDATE.*?SET.*?WHERE.*?\)\s*.*?cur\.execute\([\'"]UPDATE.*?SET.*?WHERE'
        if re.search(race_pattern, code, re.DOTALL):
            findings.append({
                "type": "Potential Race Condition",
                "severity": "medium",
                "line": 1,
                "description": "Sequential UPDATE statements lacking transaction isolation.",
                "fix": "Use DB transactions or atomic updates.",
                "exploitation": "Concurrent requests could cause state inconsistency.",
                "source": "logic-engine"
            })
        
        return findings

def scan_logic(code: str) -> List[Dict]:
    return LogicAnalyzer().analyze(code)
