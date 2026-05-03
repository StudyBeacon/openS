import os
import shutil
import tempfile
import asyncio
from git import Repo
from scanner import scan_code

class RepositoryScanner:
    def __init__(self):
        self.allowed_extensions = {".py", ".js", ".ts"}

    async def scan_repo(self, repo_url: str):
        """Clone and scan a GitHub repository."""
        temp_dir = tempfile.mkdtemp()
        try:
            print(f"Cloning {repo_url} to {temp_dir}...")
            # Use subprocess for cloning to avoid GitPython issues in some envs
            # but since GitPython is installed, let's try it
            Repo.clone_from(repo_url, temp_dir, depth=1)
            
            all_results = []
            for root, dirs, files in os.walk(temp_dir):
                # Skip common dirs
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

    def aggregate_results(self, results):
        """Consolidate multiple scan results into one project-level report."""
        vulnerabilities = []
        total_score = 0
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for res in results:
            findings = res.get("findings", [])
            for f in findings:
                f["filename"] = res.get("filename")
                vulnerabilities.append(f)
            
            # Weighted average for risk score might be too complex, 
            # let's use the sum capped at 100 or some project-level logic.
            total_score += res.get("risk_score", 0)
            
            for k in summary:
                summary[k] += res.get("summary", {}).get(k, 0)

        # Better project score: Max of file scores + small boost for many findings
        max_file_score = max([r.get("risk_score", 0) for r in results]) if results else 0
        overall_risk_score = min(100, max_file_score + (len(vulnerabilities) // 10) * 5)
        
        # Sort vulnerabilities by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "low").lower(), 3))

        top_5 = vulnerabilities[:5]
        
        risk_level = "critical" if overall_risk_score > 80 else "high" if overall_risk_score > 60 else "medium" if overall_risk_score > 30 else "low"

        return {
            "status": "success",
            "vulnerabilities": vulnerabilities,
            "top_findings": top_5,
            "risk_score": overall_risk_score,
            "risk_level": risk_level,
            "summary": summary,
            "total_files_scanned": len(results),
            "metadata": {
                "project_mode": True,
                "total_findings": len(vulnerabilities)
            }
        }
