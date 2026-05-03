from scanner import scan_code
import asyncio
import json

test_code = """
import os
import sqlite3
import jwt
from Crypto.Cipher import AES

# 1. COMMAND INJECTION (Critical AST)
def run_cmd(request):
    user_input = request.GET.get("cmd")
    os.system("ping " + user_input)

# 2. SECOND-ORDER SQL INJECTION (Critical AST)
def update_profile(request, db):
    bio = request.POST.get("bio")
    db.execute("UPDATE users SET bio = ?", (bio,))

def view_profile(db):
    row = db.execute("SELECT bio FROM users WHERE id=1").fetchone()
    # Tainted value fetched from DB
    user_bio = row[0]
    # Sink: String concatenation in SQL
    db.execute(f"SELECT * FROM activity WHERE desc = '{user_bio}'")

# 3. JWT ALGORITHM CONFUSION (High Semantic)
def verify_token(token):
    # Missing verification
    payload = jwt.decode(token, verify_signature=False)
    return payload

def bad_header(token):
    # None algorithm Header
    header = {"alg": "none"}
    return jwt.decode(token, algorithms=['none'])

# 4. WEAK CRYPTO ECB (Medium Semantic)
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_ECB) # Insecure mode
    return cipher.encrypt(data)

"""

async def run_test():
    print("--- Scanning All-In-One Test Code ---")
    results = await scan_code(test_code, "python")
    
    findings = results.get("findings", [])
    
    print(f"\nTotal Findings: {len(findings)}")
    
    types = [f.get("type", "Unknown") for f in findings]
    
    has_cmd = any("COMMAND" in t.upper() for t in types)
    has_sqli = any("SECOND_ORDER_SQL" in t.upper() for t in types)
    has_jwt = any("JWT ALGORITHM CONFUSION" in t.upper() for t in types)
    has_crypto = any("CRYPTOGRAPHY MISUSE" in t.upper() for t in types)
    
    print("\nExpected Vulnerabilities:")
    print(f"- Command Injection: {'[FOUND]' if has_cmd else '[MISSING]'}")
    print(f"- Second-Order SQLi: {'[FOUND]' if has_sqli else '[MISSING]'}")
    print(f"- JWT Algo Confusion:{'[FOUND]' if has_jwt else '[MISSING]'}")
    print(f"- Weak Crypto (ECB): {'[FOUND]' if has_crypto else '[MISSING]'}")
    
    print("\nDetails:")
    for f in findings:
        print(f"[{f['severity'].upper()}] {f['type']} at line {f['line']}")

if __name__ == "__main__":
    asyncio.run(run_test())
