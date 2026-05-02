import ast

def calculate_complexity(code: str) -> float:
    """
    Calculates a normalized complexity score (0.0 - 1.0) 
    based on Cyclomatic Complexity principles.
    """
    try:
        tree = ast.parse(code)
        nodes = 0
        branches = 0
        
        for node in ast.walk(tree):
            nodes += 1
            # Increment core cyclomatic components
            if isinstance(node, (ast.If, ast.While, ast.For, ast.ExceptHandler, ast.With)):
                branches += 1
            elif isinstance(node, ast.BoolOp):
                branches += len(node.values) - 1
        
        if nodes == 0: return 0.0
        
        # CC = E - N + 2P
        # Here we use a simpler heuristic: branches / total nodes
        # normalized to a reasonable ceiling.
        raw_score = (branches + 1) / (nodes / 10 + 1)
        return min(1.0, raw_score / 5.0) 
        
    except:
        return 0.5 

def is_critical_path(code: str) -> bool:
    """
    Detects if the code contains keywords indicating it's a critical system component.
    """
    critical_keywords = [
        "login", "auth", "password", "session", "payment", 
        "encrypt", "decrypt", "admin", "token", "sign_in"
    ]
    code_lower = code.lower()
    return any(kw in code_lower for kw in critical_keywords)
