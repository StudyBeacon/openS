import ast
import pprint
from ast_analyzer import scan_code
import asyncio
test_code = """
import sqlite3
from flask import request

def store_bio(username):
    bio = request.form.get("bio")
    conn.execute("UPDATE users SET bio = ? WHERE username = ?", (bio, username))

def search_by_bio(username):
    row = conn.execute("SELECT bio FROM users WHERE username = ?", (username,)).fetchone()
    keyword = row[0]
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
                         
    query = f"SELECT * FROM profiles WHERE bio_preview = '{keyword}'"
    conn.execute(query)
"""

scanner = ASTScanner()
findings = scanner.scan(test_code)
pprint.pprint(findings)
