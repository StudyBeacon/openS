from ast_analyzer import scan_python_ast

code = """
def update_profile(request, db):
    bio = request.POST.get("bio")
    db.execute("UPDATE users SET bio = ?", (bio,))

def view_profile(db):
    row = db.execute("SELECT bio FROM users WHERE id=1").fetchone()
    # Tainted value fetched from DB
    user_bio = row[0]
    # Sink: String concatenation in SQL
    db.execute(f"SELECT * FROM activity WHERE desc = '{user_bio}'")
"""

findings = scan_python_ast(code)
for f in findings:
    print(f"[{f['severity'].upper()}] {f['type']} at line {f['line']}")
    print(f"Path: {f['taint_path']}")

import ast
tree = ast.parse(code)
class CallVisitor(ast.NodeVisitor):
    def visit_Call(self, node):
        print(f"Call: {ast.dump(node)}")
        self.generic_visit(node)
CallVisitor().visit(tree)
