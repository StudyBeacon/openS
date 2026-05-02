import sqlite3
import hashlib
import json
import os
from typing import Optional, Dict

class AICache:
    def __init__(self, db_path: str = "ai_cache.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    hash TEXT PRIMARY KEY,
                    result TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def _generate_hash(self, code: str, language: str, context: list) -> str:
        # Sort context to ensure stable hash
        context_str = json.dumps(context, sort_keys=True)
        raw = f"{language}:{code}:{context_str}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, code: str, language: str, context: list) -> Optional[Dict]:
        h = self._generate_hash(code, language, context)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cur = conn.execute("SELECT result FROM cache WHERE hash = ?", (h,))
                row = cur.fetchone()
                if row:
                    return json.loads(row[0])
        except Exception as e:
            print(f"Cache read error: {e}")
        return None

    def set(self, code: str, language: str, context: list, result: Dict):
        if not result or result.get("verdict") == "unknown":
            return
        
        h = self._generate_hash(code, language, context)
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cache (hash, result) VALUES (?, ?)",
                    (h, json.dumps(result))
                )
        except Exception as e:
            print(f"Cache write error: {e}")

# Global cache instance
cache = AICache()
