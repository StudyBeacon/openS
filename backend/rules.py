import re
from typing import List, Dict


# =========================
# MAIN ENTRY
# =========================

def scan_with_rules(code: str, language: str) -> List[Dict]:
    findings = []
    lines = code.split("\n")

    flagged = set()

    for i, line in enumerate(lines, 1):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue

        if i in flagged:
            continue

        context = "\n".join(lines[max(0, i - 3): i + 3])

        # =========================
        # PATH TRAVERSAL (HIGHEST PRIORITY)
        # =========================
        if _path_traversal(i, lines, raw, context):
            findings.append({
                "type": "Path Traversal",
                "severity": "critical",
                "line": i,
                "code_snippet": raw,
                "description": "User input flows into file system path operations.",
                "fix": "Validate paths and restrict directory access.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # SQL INJECTION
        # =========================
        if _sql_injection(raw, context):
            findings.append({
                "type": "SQL Injection",
                "severity": "critical",
                "line": i,
                "code_snippet": raw,
                "description": "Unsafe string-based SQL query construction.",
                "fix": "Use parameterized queries.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # COMMAND INJECTION
        # =========================
        if _command_injection(raw):
            findings.append({
                "type": "Command Injection",
                "severity": "critical",
                "line": i,
                "code_snippet": raw,
                "description": "User input passed into system execution.",
                "fix": "Use subprocess with list args.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # EVAL ABUSE
        # =========================
        if _eval_abuse(raw):
            findings.append({
                "type": "Eval Abuse",
                "severity": "critical",
                "line": i,
                "code_snippet": raw,
                "description": "Dynamic code execution detected.",
                "fix": "Avoid eval/exec entirely.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # DESERIALIZATION
        # =========================
        if _deserialization(raw):
            findings.append({
                "type": "Insecure Deserialization",
                "severity": "high",
                "line": i,
                "code_snippet": raw,
                "description": "Unsafe object deserialization.",
                "fix": "Use safe parsers like json.loads.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # SECRETS
        # =========================
        if _secrets(raw):
            findings.append({
                "type": "Hardcoded Secret",
                "severity": "high",
                "line": i,
                "code_snippet": raw,
                "description": "Sensitive data hardcoded in code.",
                "fix": "Move to environment variables.",
                "taint_hint": {"source": True}
            })
            flagged.add(i)
            continue

        # =========================
        # IDOR (IMPROVED CONTEXT MODEL)
        # =========================
        if _idor(i, lines):
            findings.append({
                "type": "IDOR",
                "severity": "high",
                "line": i,
                "code_snippet": raw,
                "description": "Direct object reference without authorization.",
                "fix": "Add ownership/permission checks.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # XSS
        # =========================
        if _xss(raw):
            findings.append({
                "type": "XSS",
                "severity": "medium",
                "line": i,
                "code_snippet": raw,
                "description": "Unescaped user input in output context.",
                "fix": "Sanitize output or use safe rendering.",
                "taint_hint": {"source": True, "sink": True}
            })
            flagged.add(i)
            continue

        # =========================
        # WEAK CRYPTO
        # =========================
        if _weak_crypto(raw):
            findings.append({
                "type": "Weak Cryptography",
                "severity": "medium",
                "line": i,
                "code_snippet": raw,
                "description": "Weak hashing algorithm used.",
                "fix": "Use SHA-256 or bcrypt.",
                "taint_hint": {"source": True}
            })
            flagged.add(i)
            continue

    return findings


# =========================
# RULE FUNCTIONS
# =========================

def _path_traversal(i, lines, line, context):
    if not (
        re.search(r"path\.join\s*\([^)]*[a-zA-Z_]", line) or
        re.search(r"readFileSync|fs\.read|open\s*\(", line)
    ):
        return False

    # check real user input in context
    return bool(re.search(r"req\.(query|params|body)", context))


def _sql_injection(line, context):
    if re.search(r"\b(path\.|open|fs\.read)", line):
        return False

    if not re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b", line, re.I):
        return False

    return bool(
        re.search(r"\+\s*[a-zA-Z_]", line) or
        re.search(r"\$\{", line)
    )


def _command_injection(line):
    return bool(
        re.search(r"os\.system\s*\(\s*[a-zA-Z_]", line) or
        re.search(r"subprocess\.(run|call|Popen)\s*\([^)]*[a-zA-Z_]", line) or
        re.search(r"\bexec\s*\(", line)
    )


def _eval_abuse(line):
    return bool(
        re.search(r"\beval\s*\([^'\"]*[a-zA-Z_]", line) and
        not re.search(r"eval\s*\(\s*['\"]", line)
    )


def _deserialization(line):
    return bool(
        re.search(r"pickle\.loads\s*\(", line) or
        re.search(r"yaml\.load\s*\(", line) and "Loader" not in line
    )


def _secrets(line):
    m = re.search(r"(password|secret|token|api[_-]?key)\s*=\s*['\"]([^'\"]+)['\"]", line, re.I)
    if not m:
        return False
    val = m.group(2)
    return val not in ["", "xxx", "test", "example"]


def _idor(i, lines):
    line = lines[i - 1]
    if not re.search(r"req\.(query|params)\.id", line):
        return False

    context = "\n".join(lines[max(0, i - 2): i + 2])

    return bool(re.search(r"(SELECT|find|query|db\.)", context, re.I))


def _xss(line):
    return bool(
        re.search(r"\.innerHTML\s*=", line) or
        re.search(r"document\.write\s*\(", line) or
        re.search(r"res\.(send|write)\s*\(`", line)
    )


def _weak_crypto(line):
    return bool(
        re.search(r"hashlib\.(md5|sha1)\s*\(", line) or
        re.search(r"createHash\s*\(\s*['\"](md5|sha1)['\"]", line)
    )