import ast
import re
from typing import List, Dict, Optional, Set, Any

class ASTAnalyzer:
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
        self.poisoned_db = {} # table.column -> {"var_name", "line"}
        self.findings = []
        self.reported_lines = set()
        self.debug_log = []

    def _get_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return f"{self._get_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call): return self._get_name(node.func)
        return ""

    def _get_str_value(self, node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.JoinedStr):
            parts = []
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    parts.append(val.value)
                else:
                    parts.append("?")
            return "".join(parts)
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

    def analyze(self, code: str, language: str = "python") -> List[Dict]:
        if language.lower() not in ["python", "py"]:
            return []
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
        elif isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.If, ast.For, ast.While, ast.With, ast.Try)):
            if hasattr(node, 'body'):
                for body_node in node.body: self._traverse(body_node)
            if hasattr(node, 'orelse'):
                for body_node in node.orelse: self._traverse(body_node)
            if hasattr(node, 'handlers'):
                for handler in node.handlers: self._traverse(handler)
            if hasattr(node, 'finalbody'):
                for body_node in node.finalbody: self._traverse(body_node)

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
                table, column = None, None
                if val.args:
                    sql = self._get_str_value(val.args[0])
                    table, column = self._extract_sql_info(sql)
                elif hasattr(val, 'func') and isinstance(val.func, ast.Attribute) and isinstance(val.func.value, ast.Call):
                    # Handle chained calls like .execute(...).fetchone()
                    inner_call = val.func.value
                    if inner_call.args:
                        sql = self._get_str_value(inner_call.args[0])
                        table, column = self._extract_sql_info(sql)
                
                # Check DB mapping
                key = f"{table}.{column}" if (table and column) else "GLOBAL"
                origin_info = self.poisoned_db.get(key) or self.poisoned_db.get("GLOBAL")
                
                if origin_info:
                    source_base = origin_info.get("source_base", "unknown")
                    table_col = f"{table or 'unknown'}.{column or 'unknown'}"
                    chain_str = f"SOURCE ({source_base}) → DB STORE ({table_col}) → DB READ"
                    
                    print(f"[DEBUG AST] DB READ TRACKED: variable={var_name}, from={table_col}")
                    
                    self.taint_graph[var_name] = {
                        "origin": "DATABASE_FETCH",
                        "path": [chain_str],
                        "sanitized": False,
                        "type": "SECOND_ORDER"
                    }

        # PROPAGATION
        else:
            tainted_child = self._get_tainted_var(val)
            if tainted_child:
                parent = self.taint_graph[tainted_child]
                self.taint_graph[var_name] = {
                    "origin": parent["origin"],
                    "path": parent["path"] + [f"FLOW: {tainted_child} -> {var_name} at line {line}"],
                    "sanitized": parent["sanitized"],
                    "type": parent["type"]
                }

    def _handle_call(self, node: ast.Call):
        name = self._get_name(node)
        line = node.lineno

        # SINK: Persistence (DB Write)
        if any(name.endswith(s) or name == s for s in self.persistence_sinks):
            sql = ""
            if node.args:
                sql = self._get_str_value(node.args[0])
            
            # Check if any arg (or the SQL string itself if f-string) is tainted
            tainted_info = None
            for arg in node.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name) and sub.id in self.taint_graph:
                        tainted_info = {"var_name": sub.id, "line": line}
                        break
                if tainted_info: break
            
            if tainted_info:
                table, column = self._extract_sql_info(sql)
                if table and column:
                    t_var = tainted_info["var_name"]
                    t_path = self.taint_graph[t_var]["path"][0] # Get first element e.g. "SOURCE: request.POST.get at line x"
                    # clean up the start string, user wants "request.POST.get"
                    if t_path.startswith("SOURCE: "):
                        t_path = t_path.replace("SOURCE: ", "").split(" at line")[0]
                    tainted_info["source_base"] = t_path
                    self.poisoned_db[f"{table}.{column}"] = tainted_info
                    print(f"[DEBUG AST] DB WRITE TRACKED: table={table}, column={column}, source={t_path}")
                else:
                    self.poisoned_db["GLOBAL"] = tainted_info
                    print(f"[DEBUG AST] DB WRITE TRACKED: GLOBAL. source={tainted_info['var_name']}")

        # SINK: Vulnerability
        for v_type, sinks in self.vulnerability_sinks.items():
            if any(name.endswith(s) or name == s for s in sinks):
                if node.args:
                    arg = node.args[0]
                    # Specific check for string concatenation in SQL sinks
                    is_concatenated = isinstance(arg, (ast.JoinedStr, ast.BinOp)) or \
                                     (isinstance(arg, ast.Call) and self._get_name(arg.func).endswith("format"))
                    
                    if v_type == "SQL_INJECTION":
                        print(f"[DEBUG AST] Checking SINK {name} at line {line}...")
                        print(f"[DEBUG AST] Tainted? {self._is_tainted_expr(arg)}")
                    
                    # If arg itself is tainted, it's an injection since it shouldn't be dynamic!
                    if v_type == "SQL_INJECTION" and self._is_tainted_expr(arg):
                        t_var = self._get_tainted_var(arg)
                        info = self.taint_graph[t_var]
                        final_type = v_type
                        if info["type"] == "SECOND_ORDER":
                            final_type = f"SECOND_ORDER_{v_type}"
                            # Overwrite the path entirely as requested by user
                            base_chain = info["path"][0]
                            info["path"] = [f"{base_chain} → SINK ({name})"]
                        
                        info_with_var = dict(info)
                        info_with_var["var_name"] = t_var
                        print(f"[DEBUG AST] SINK DETECTED: {t_var} is tainted. Final Path: {info['path']}")
                        self._report(final_type, name, line, info_with_var)
                    elif v_type != "SQL_INJECTION" and self._is_tainted_expr(arg):
                        t_var = self._get_tainted_var(arg)
                        info = self.taint_graph[t_var]
                        final_type = v_type
                        if info["type"] == "SECOND_ORDER":
                            final_type = f"SECOND_ORDER_{v_type}"
                        
                        info_with_var = dict(info)
                        info_with_var["var_name"] = t_var
                        self._report(final_type, name, line, info_with_var)

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
        
        desc_prefix = "Second-Order Taint" if "SECOND_ORDER" in v_type else "Deep Taint"
        display_type = "Second-Order SQL Injection" if v_type == "SECOND_ORDER_SQL_INJECTION" else v_type.replace("_", " ").title()
        
        final_path = info["path"]
        if "SECOND_ORDER" not in v_type:
            final_path = final_path + [f"SINK: {sink} at line {line}"]
        
        self.findings.append({
            "type": display_type,
            "severity": "critical",
            "line": line,
            "description": f"{desc_prefix} found reaching {display_type} sink: {sink}",
            "code_snippet": f"{sink}(...)",
            "taint_trail": " → ".join(final_path) if isinstance(final_path, list) else final_path,
            "fix": remediation["fix"],
            "corrected_code": remediation["fix"],
            "exploitation": remediation["exploit"],
            "source": "ast-analyzer"
        })


def scan_python_ast(code: str) -> List[Dict]:
    return ASTAnalyzer().analyze(code)
