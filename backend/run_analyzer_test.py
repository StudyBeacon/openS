import json
from ast_analyzer import ASTAnalyzer

with open("minimal_second_order.py", "r") as f:
    code = f.read()

analyzer = ASTAnalyzer()
import pprint
pprint.pprint(analyzer.analyze(code, "python"))
