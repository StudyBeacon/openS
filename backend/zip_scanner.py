import os
import shutil
import tempfile
import zipfile
import asyncio
from scanner import scan_code
from github_scanner import RepositoryScanner

class ZipScanner(RepositoryScanner):
    async def scan_zip(self, zip_path: str):
        """Extract and scan a zip file."""
        temp_dir = tempfile.mkdtemp()
        try:
            print(f"Extracting zip to {temp_dir}...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Safe extraction (basic check)
                for member in zip_ref.infolist():
                    filename = os.path.normpath(member.filename)
                    if filename.startswith('/') or '..' in filename:
                        continue # Skip suspicious paths
                    zip_ref.extract(member, temp_dir)
            
            all_results = []
            for root, dirs, files in os.walk(temp_dir):
                if any(x in root for x in [".git", "node_modules", "venv", "__pycache__"]):
                    continue
                
                for file in files:
                    _, ext = os.path.splitext(file)
                    if ext.lower() in self.allowed_extensions:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, temp_dir)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                code = f.read()
                            
                            language = "python" if ext == ".py" else "javascript"
                            result = await scan_code(code, language)
                            result["filename"] = rel_path
                            all_results.append(result)
                        except Exception as e:
                            print(f"Error scanning {rel_path}: {e}")

            return self.aggregate_results(all_results)
        finally:
            shutil.rmtree(temp_dir)
