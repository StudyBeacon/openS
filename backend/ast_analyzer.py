import ast
import re
from typing import List, Dict, Optional, Set, Any


class TaintAnalyzer:
    """
    ULTIMATE AST Taint Analyzer (Phase 5)
    Detects Second-Order SQL Injection with table/column persistence tracking.
    """
    def __init__(self):
        # ───────── SOURCES ─────────
        self.sources = {
            "req.GET.get", "request.GET.get", "request.POST.get", "request.form.get",
            "request.args.get", "request.values.get", "input", "sys.stdin", "os.getenv",
            "request.json", "req.json", "request.get_json"
        }
        
        # ───────── PERSISTENCE (DB) ─────────
        self.persistence_sinks = ["execute", "db.execute", "cursor.execute", "db.save", "models.save"]
        self.persistence_sources = ["fetchone", "fetchall", "db.get", "models.objects.get", "query"]

        # ───────── VULNERABILITY SINKS ─────────
        self.vulnerability_sinks = {
            "SQL_INJECTION": ["execute", "db.execute", "cursor.execute", "raw_query", "query"],
            "COMMAND_INJECTION": ["system", "popen", "run", "call", "Popen", "spawn"],
            "PATH_TRAVERSAL": ["open", "listdir", "remove", "rename", "load_file"],
            "EVAL_ABUSE": ["eval", "exec", "compile", "execfile"],
            "XSS": ["render_template", "render", "HttpResponse", "write", "innerHTML", "document.write"]
        }

        self.strong_sanitizers = {"int", "float", "bool", "shlex.quote", "html.escape"}
        self.fake_sanitizers = {"strip", "trim", "lower", "upper", "replace", "escape"}

        # ───────── STATE ─────────
        self.taint_graph = {}  # var -> {origin, path, sanitized, type}
        self.poisoned_db = set() # Set of "table.column" strings
        self.findings = []
        self.reported_lines = set()

    def _get_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return f"{self._get_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call): return self._get_name(node.func)
        return ""

    def _extract_sql_info(self, sql: str):
        """Extract table and column from common INSERT/UPDATE/SELECT queries."""
        table, column = None, None
        
        # INSERT INTO table (col) ...
        insert_match = re.search(r"INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)", sql, re.IGNORECASE)
        if insert_match:
            table = insert_match.group(1)
            column = insert_match.group(2).split(',')[0].strip() # Take first for simplicity
        
        # UPDATE table SET col = ...
        update_match = re.search(r"UPDATE\s+(\w+)\s+SET\s+(\w+)\s*=", sql, re.IGNORECASE)
        if update_match:
            table = update_match.group(1)
            column = update_match.group(2)

        # SELECT col FROM table ...
        select_match = re.search(r"SELECT\s+([\w,\*]+)\s+FROM\s+(\w+)", sql, re.IGNORECASE)
        if select_match:
            column = select_match.group(1).split(',')[0].strip()
            table = select_match.group(2)

        return table, column

    def analyze(self, code: str) -> List[Dict]:
        try:
            tree = ast.parse(code)
            # Higher pass count for Second-Order flow (Sink -> State -> Source)
            for _ in range(6):
                self._traverse(tree)
            return self.findings
        except Exception as e:
            print(f"AST Analysis Error: {e}")
            return []

    def _traverse(self, node: Any):
        if isinstance(node, ast.Assign): self._handle_assign(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call): self._handle_call(node.value)
        elif isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
            for body_node in node.body: self._traverse(body_node)

    def _handle_assign(self, node: ast.Assign):
        if not isinstance(node.targets[0], ast.Name): return
        var_name = node.targets[0].id
        val = node.value
        line = node.lineno

        # SOURCE: User Input
        if isinstance(val, ast.Call):
            name = self._get_name(val)
            if any(name.startswith(s) or name == s for s in self.sources):
                self.taint_graph[var_name] = {
                    "origin": "USER_INPUT",
                    "path": [f"SOURCE: {name} at line {line}"],
                    "sanitized": False,
                    "type": "FIRST_ORDER"
                }
            
            # SOURCE: DB Persistence (Second-Order)
            elif any(name.endswith(s) or name == s for s in self.persistence_sources):
                # Check if we can identify the table/column
                table, column = None, None
                if val.args and isinstance(val.args[0], ast.Constant) and isinstance(val.args[0].value, str):
                    table, column = self._extract_sql_info(val.args[0].value)
                
                # If we know it's poisoned, or generically a DB read after we saw some poisoning
                if (table and column and f"{table}.{column}" in self.poisoned_db) or self.poisoned_db:
                    self.taint_graph[var_name] = {
                        "origin": "DATABASE_FETCH",
                        "path": [f"PERSISTENCE_SOURCE: DB read ({table or 'unknown'}.{column or 'unknown'}) at line {line}"],
                        "sanitized": False,
                        "type": "SECOND_ORDER"
                    }

        # PROPAGATION
        elif isinstance(val, ast.Name) and val.id in self.taint_graph:
            parent = self.taint_graph[val.id]
            self.taint_graph[var_name] = {
                "origin": parent["origin"],
                "path": parent["path"] + [f"FLOW: {val.id} -> {var_name} at line {line}"],
                "sanitized": parent["sanitized"],
                "type": parent["type"]
            }

    def _handle_call(self, node: ast.Call):
        name = self._get_name(node)
        line = node.lineno

        # SINK: Persistence (DB Write)
        if any(name.endswith(s) or name == s for s in self.persistence_sinks):
            sql = ""
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                sql = node.args[0].value
            
            # Check if any arg (or the SQL string itself if f-string) is tainted
            tainted_var = None
            for arg in node.args:
                if isinstance(arg, (ast.Name, ast.JoinedStr)):
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Name) and sub.id in self.taint_graph:
                            tainted_var = sub.id
                            break
            
            if tainted_var:
                table, column = self._extract_sql_info(sql)
                if table and column:
                    self.poisoned_db.add(f"{table}.{column}")
                else:
                    self.poisoned_db.add("GLOBAL") # Generic poison

        # SINK: Vulnerability
        for v_type, sinks in self.vulnerability_sinks.items():
            if any(name.endswith(s) or name == s for s in sinks):
                for arg in node.args:
                    if self._is_tainted_expr(arg):
                        t_var = self._get_tainted_var(arg)
                        info = self.taint_graph[t_var]
                        final_type = v_type
                        if info["type"] == "SECOND_ORDER":
                            final_type = f"SECOND_ORDER_{v_type}"
                        
                        self._report(final_type, name, line, info)

    def _is_tainted_expr(self, node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.taint_graph: return True
        return False

    def _get_tainted_var(self, node):
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.taint_graph: return sub.id
        return None

    def _get_remediation(self, v_type, sink, var_name):
        """Generate static remediation and exploit examples for AST findings."""
        templates = {
            "SQL_INJECTION": {
                "fix": f"Use parameterized query: cursor.execute('SELECT ... WHERE {var_name}=?', ({var_name},))",
                "exploit": f"'{var_name}' set to: admin' OR '1'='1"
            },
            "COMMAND_INJECTION": {
                "fix": f"Use shlex.quote({var_name}) or pass arguments as a list to subprocess.run()",
                "exploit": f"'{var_name}' set to: ; rm -rf /"
            },
            "XSS": {
                "fix": f"Encode {var_name} using html.escape() or use textContent instead of innerHTML",
                "exploit": f"'{var_name}' set to: <script>alert('XSS')</script>"
            },
            "PATH_TRAVERSAL": {
                "fix": f"Use os.path.basename({var_name}) and validate against an allowlist",
                "exploit": f"'{var_name}' set to: ../../../etc/passwd"
            }
        }
        
        base_type = v_type.replace("SECOND_ORDER_", "")
        return templates.get(base_type, {
            "fix": "Standard security remediation recommended.",
            "exploit": "Varies by context."
        })

    def _report(self, v_type, sink, line, info):
        # ... logic to avoid duplicate reports ...
        key = (v_type, line)
        if key in self.reported_lines: return
        self.reported_lines.add(key)
        
        remediation = self._get_remediation(v_type, sink, info.get("var_name", "input"))
        
        self.findings.append({
            "type": v_type,
            "severity": "critical",
            "line": line,
            "description": f"Deep Taint found reaching {v_type} sink: {sink}",
            "code_snippet": f"{sink}(...)",
            "taint_path": info["path"] + [f"SINK: {sink} at line {line}"],
            "fix": remediation["fix"],
            "corrected_code": remediation["fix"],
            "exploitation": remediation["exploit"]
        })


def scan_python_ast(code: str) -> List[Dict]:
    return TaintAnalyzer().analyze(code)
