import re

ADVANCED_PATTERNS = [
    {
        "id": "BUSINESS_LOGIC_TAMPERING",
        "type": "Logic Flaw",
        "severity": "high",
        "regex": r"(price|amount|quantity)\s*=\s*req(uest)?\.(form|args|GET|POST|json)\.get",
        "description": "Directly assigning price or quantity from user input can lead to logic tampering.",
        "fix": "Always fetch prices and quantities from a verified database, not the client request."
    },
    {
        "id": "WEAK_CRYPTO_ECB",
        "type": "Cryptography Misuse",
        "severity": "medium",
        "regex": r"AES\.MODE_ECB",
        "description": "ECB mode is insecure as it does not provide serious data confidentiality.",
        "fix": "Use GCM or CBC mode with a strong initialization vector (IV)."
    },
    {
        "id": "JWT_NONE_ALGO",
        "type": "Broken Authentication",
        "severity": "critical",
        "regex": r'algorithm\s*[:=]\s*["\']none["\']',
        "description": "JWT 'none' algorithm allowed, which permits signature bypass.",
        "fix": "Explicitly whitelist safe algorithms like HS256 or RS256."
    }
]

def scan_advanced_patterns(code: str) -> list:
    findings = []
    lines = code.split('\n')
    for pattern in ADVANCED_PATTERNS:
        for i, line in enumerate(lines):
            if re.search(pattern["regex"], line, re.IGNORECASE):
                findings.append({
                    "type": pattern["id"],
                    "severity": pattern["severity"],
                    "line": i + 1,
                    "description": pattern["description"],
                    "code_snippet": line.strip(),
                    "fix": pattern["fix"],
                    "source": "semantic"
                })
    return findings
