import ast
from typing import List, Dict, Optional, Set


class PythonTaintScanner:
    def __init__(self):
        # ───────── SOURCES ─────────
        self.sources = {
            "request.args.get", "req.args.get",
            "request.form.get", "req.form.get",
            "request.values.get", "req.values.get",
            "request.form", "req.form",
            "request.args", "req.args",
            "request.json", "req.json",
            "input", "getUserInput", "get_input", "source", "os.getenv"
        }

        # ───────── SINKS ─────────
        self.sinks = {
            "COMMAND_INJECTION": ["os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "os.popen", "eval", "exec"],
            "SQL_INJECTION": ["cursor.execute", "db.execute", "sqlite3.connect", "execute", "db.engine.execute"],
            "SSRF": ["requests.get", "requests.post", "requests.request", "urllib.request.urlopen", "httpx.get"],
            "PATH_TRAVERSAL": ["open", "os.path.join", "os.listdir", "shutil.copy"],
            "DESERIALIZATION": ["pickle.loads", "yaml.load", "marshal.loads"],
            "UNVALIDATED_REDIRECT": ["flask.redirect", "redirect", "django.shortcuts.redirect"]
        }

        # ───────── SANITIZERS ─────────
        self.strong_sanitizers = {
            "int", "float", "bool", "shlex.quote", "html.escape", "quote"
        }

        # ───────── TAINT STATE ─────────
        self.tainted = {}   # var → node info
        self.func_summaries = {}  # function → summary
        self.findings = []
        self.reported = set()

    def _name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return f"{self._name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call): return self._name(node.func)
        return ""

    def _is_source(self, node: ast.Call) -> bool:
        n = self._name(node.func)
        return any(n.startswith(s) or n == s for s in self.sources)

    def _sink_type(self, node: ast.Call) -> Optional[str]:
        n = self._name(node.func)
        for t, patterns in self.sinks.items():
            if any(n.endswith(p) or n == p for p in patterns):
                return t
        return None

    def _summarize_function(self, fn: ast.FunctionDef):
        """Build a summary of what a function does to its arguments."""
        args = [a.arg for a in fn.args.args]
        summary = {"returns_arg": -1, "sinks": []}

        for n in ast.walk(fn):
            # Propagation via return
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Name):
                if n.value.id in args:
                    summary["returns_arg"] = args.index(n.value.id)

            # Internal sinks
            if isinstance(n, ast.Call):
                st = self._sink_type(n)
                if st:
                    for i, arg in enumerate(n.args):
                        if isinstance(arg, ast.Name) and arg.id in args:
                            summary["sinks"].append({"arg_index": i, "type": st})

        self.func_summaries[fn.name] = summary

    def analyze(self, code: str) -> List[Dict]:
        try:
            tree = ast.parse(code)
            
            # Phase 1: Summary collection
            for n in ast.walk(tree):
                if isinstance(n, ast.FunctionDef):
                    self._summarize_function(n)

            # Phase 2: Multi-pass propagation
            for _ in range(5): 
                self._visit(tree)

            return self.findings
        except Exception as e:
            print(f"Deep AST error: {e}")
            return []

    def _visit(self, node):
        if isinstance(node, ast.Assign): self._handle_assign(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call): self._handle_call(node.value)
        elif isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)):
            # Track file access for TOCTOU heuristic
            access_sequence = []
            for n in node.body:
                if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
                    cname = self._name(n.value.func)
                    if cname in ["os.path.exists", "os.path.isfile", "os.access"]:
                        if n.value.args and isinstance(n.value.args[0], ast.Name):
                            access_sequence.append({"type": "check", "var": n.value.args[0].id, "line": n.lineno})
                    elif cname in ["open", "os.remove", "os.rename"]:
                         if n.value.args and isinstance(n.value.args[0], ast.Name):
                            access_sequence.append({"type": "use", "var": n.value.args[0].id, "line": n.lineno})
                self._visit(n)
            
            # Simple TOCTOU heuristic: check -> [at least one other stmt] -> use
            for i in range(len(access_sequence)-1):
                curr = access_sequence[i]
                nxt = access_sequence[i+1]
                if curr["type"] == "check" and nxt["type"] == "use" and curr["var"] == nxt["var"]:
                    if nxt["line"] - curr["line"] > 1:
                        self._report("TOCTOU_RACE_CONDITION", nxt["var"], "logic_flow", nxt["line"])

    def _handle_assign(self, node):
        line = node.lineno
        val = node.value
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var = target.id
                
                # Source detection
                if isinstance(val, ast.Call) and self._is_source(val):
                    self.tainted[var] = {"path": [f"SOURCE: {self._name(val)} at line {line}"]}
                
                # Direct propagation
                elif isinstance(val, ast.Name) and val.id in self.tainted:
                    self.tainted[var] = {"path": self.tainted[val.id]["path"] + [f"VAR: {var} (line {line})"]}
                
                # Inter-procedural propagation (Function calls)
                elif isinstance(val, ast.Call):
                    cname = self._name(val.func)
                    if cname in self.strong_sanitizers:
                        self.tainted.pop(var, None)
                    elif cname in self.func_summaries:
                        summary = self.func_summaries[cname]
                        if summary["returns_arg"] != -1 and summary["returns_arg"] < len(val.args):
                            arg_node = val.args[summary["returns_arg"]]
                            if isinstance(arg_node, ast.Name) and arg_node.id in self.tainted:
                                self.tainted[var] = {"path": self.tainted[arg_node.id]["path"] + [f"FLOW: {cname}() -> {var}"]}
                    
                    # Sink detection inside assignments (e.g., res = db.execute(tainted))
                    self._handle_call(val)
            
            # Attribute manipulation (Prototype-like)
            elif isinstance(target, ast.Attribute):
                obj = self._name(target.value)
                attr = target.attr
                if attr in ["__dict__", "__class__", "__init__"]:
                    if isinstance(val, ast.Name) and val.id in self.tainted:
                        self._report("PROTOTYPE_POLLUTION", f"{obj}.{attr}", val.id, line)

    def _handle_call(self, node):
        st = self._sink_type(node)
        line = node.lineno
        if not st: return

        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted:
                self._report(st, self._name(node.func), arg.id, line)
            elif isinstance(arg, ast.BinOp) and self._any_tainted_in_expr(arg):
                self._report(st, self._name(node.func), "interpolated_expr", line)

    def _any_tainted_in_expr(self, node) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted: return True
        return False

    def _report(self, stype, sink, var, line):
        key = (stype, line)
        if key in self.reported: return
        self.reported.add(key)

        path = self.tainted.get(var, {}).get("path", ["UNKNOWN SOURCE"])
        
        self.findings.append({
            "type": stype,
            "severity": "critical" if stype in ["COMMAND_INJECTION", "SQL_INJECTION", "PROTOTYPE_POLLUTION"] else "high",
            "line": line,
            "description": f"Deep Taint Analysis found path to {stype}",
            "code_snippet": f"Sink: {sink}",
            "taint_path": path + [f"SINK: {sink} at line {line}"],
            "fix": "Apply strict input validation and use parameterized APIs."
        })


def scan_python_ast(code: str) -> List[Dict]:
    return PythonTaintScanner().analyze(code)