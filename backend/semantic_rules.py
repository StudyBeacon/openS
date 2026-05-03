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
        "id": "JWT_ALGORITHM_CONFUSION_DECODE",
        "type": "JWT Algorithm Confusion",
        "severity": "high",
        "regex": r"jwt\.decode.*?(verify_signature\s*=\s*False|[\"']verify_signature[\"']\s*:\s*(False|False)|algorithms\s*=\s*\[\s*[\"']none[\"']\s*\])",
        "description": "JWT algorithm confusion: Disabling signature verification or allowing 'none' algorithm permits attackers to forge tokens.",
        "fix": "Always verify signatures and strictly whitelist secure algorithms (e.g., algorithms=['HS256'])."
    },
    {
        "id": "JWT_ALGORITHM_NONE_HEADER",
        "type": "JWT Algorithm Confusion",
        "severity": "high",
        "regex": r"[\"']alg[\"']\s*:\s*[\"']none[\"']",
        "description": "JWT header specifies the 'none' algorithm, which is inherently insecure.",
        "fix": "Reject tokens using the 'none' algorithm."
    }
]

def scan_advanced_patterns(code: str) -> list:
    findings = []
    lines = code.split('\n')
    for pattern in ADVANCED_PATTERNS:
        for i, line in enumerate(lines):
            if re.search(pattern["regex"], line, re.IGNORECASE):
                findings.append({
                    "type": pattern["type"],
                    "severity": pattern["severity"],
                    "line": i + 1,
                    "description": pattern["description"],
                    "code_snippet": line.strip(),
                    "fix": pattern["fix"],
                    "source": "semantic"
                })
    return findings
