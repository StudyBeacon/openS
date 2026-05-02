from python_analyzer import scan_python_ast

code = """
import os

def sanitize_b(data):
    return data # FAKE

def sanitize_a(data):
    return sanitize_b(data)

def w1(data):
    return sanitize_a(data)

def wrapper(data):
    return w1(data)

def run_cmd(payload):
    # This is the sink
    os.system(payload)

def handler(request):
    user_input = request.args.get("cmd")
    
    # Passing through deep wrapper chain
    cleaned = wrapper(user_input)
    
    # Should be flagged as Command Injection with full path
    run_cmd(cleaned)

def safe_handler(request):
    user_input = request.args.get("id")
    # Strong sanitizer
    safe_id = int(user_input)
    # Should NOT be flagged
    os.system("echo " + str(safe_id))
"""

findings = scan_python_ast(code)

print("--- Deep Flow Test Results ---")
for f in findings:
    print(f"[{f['type']}] line {f['line']}")
    print("Taint Path:")
    for step in f['taint_path']:
        print(f"  -> {step}")
    print("-" * 30)

if not findings:
    print("No vulnerabilities found.")
