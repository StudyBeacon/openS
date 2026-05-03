from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import httpx
import os
from typing import List
from pydantic import BaseModel, Field
from scanner import scan_code
from github_scanner import RepositoryScanner
from zip_scanner import ZipScanner
from pdf_report import PDFGenerator
from live_scanner import LiveScanner
from fastapi.responses import Response
import shutil
import tempfile

# In-memory history (last 50 scans)
scan_history: List[dict] = []
repo_scanner = RepositoryScanner()
zip_scanner = ZipScanner()
pdf_gen = PDFGenerator()
MAX_HISTORY = 50


class ScanRequest(BaseModel):
    code: str = Field(..., max_length=50000, description="Code to scan (max 50000 chars)")
    language: str = Field(default="python", description="Programming language")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown"""
    # Startup
    print("Vulnerability Scanner API starting...")
    yield
    # Shutdown
    print("Vulnerability Scanner API shutting down...")


app = FastAPI(
    title="Vulnerability Scanner API",
    version="1.0.0",
    description="Scan code for security vulnerabilities using rule-based and AI analysis",
    lifespan=lifespan
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def store_scan_result(result: dict) -> None:
    """Store scan result in history, keeping only last 50"""
    scan_history.insert(0, result)
    if len(scan_history) > MAX_HISTORY:
        scan_history.pop()


@app.post("/api/scan")
async def scan(request: ScanRequest) -> dict:
    """
    Scan code for vulnerabilities.

    Request body:
    - code: Source code to scan (required, max 50000 chars)
    - language: Programming language (optional, default: "python")

    Returns:
    - Scan result with risk_score, risk_level, verdict, findings, etc.
    """
    result = await scan_code(request.code, request.language)
    store_scan_result(result)
    return result


@app.post("/api/scan/files")
async def scan_files(files: List[UploadFile] = File(...)) -> List[dict]:
    """
    Scan multiple files for vulnerabilities.

    Detects language from file extension:
    - .py → python
    - .js → javascript
    - .ts → typescript
    - .go → go
    - .java → java
    - .cpp → cpp
    - other → unknown

    Max file size: 1MB per file (enforced in code; adjust as needed)

    Returns:
    - List of scan results with filename added to each
    """
    # Language detection from file extension
    ext_to_language = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".go": "go",
        ".java": "java",
        ".cpp": "cpp"
    }

    results = []

    for file in files:
        # Get file extension and detect language
        _, ext = os.path.splitext(file.filename or "")
        language = ext_to_language.get(ext.lower(), "unknown")

        try:
            # Read file content (max 1MB per file)
            content = await file.read()
            if len(content) > 1_000_000:
                results.append({
                    "filename": file.filename,
                    "error": "File exceeds 1MB size limit"
                })
                continue

            # Decode and scan
            code = content.decode("utf-8")
            result = await scan_code(code, language)
            result["filename"] = file.filename
            results.append(result)
            store_scan_result(result)

        except UnicodeDecodeError:
            results.append({
                "filename": file.filename,
                "error": "File is not valid UTF-8 text"
            })
        except Exception as e:
            results.append({
                "filename": file.filename,
                "error": f"Scan failed: {str(e)}"
            })

    return results


@app.get("/api/health")
async def health() -> dict:
    """
    Health check endpoint.

    Returns:
    - status: "ok" if API is running
    - ollama: true if Ollama API is reachable, false otherwise
    """
    ast_reachable = False

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check Ollama
            try:
                ollama_resp = await client.get("http://localhost:11434/api/tags")
                ollama_reachable = ollama_resp.status_code == 200
            except: pass

            # Check AST Service
            try:
                ast_resp = await client.get("http://localhost:8001/health")
                ast_reachable = ast_resp.status_code == 200
            except: pass
    except Exception:
        pass

    return {
        "status": "ok",
        "ollama": ollama_reachable,
        "ast": ast_reachable
    }


@app.get("/api/history")
async def history() -> List[dict]:
    """
    Get scan history.

    Returns:
    - Last 50 scans in reverse chronological order (newest first)
    """
    return scan_history


class RepoRequest(BaseModel):
    url: str


@app.post("/api/scan-repo")
async def scan_repo(request: RepoRequest):
    """Scan a public GitHub repository."""
    result = await repo_scanner.scan_repo(request.url)
    store_scan_result(result)
    return result


@app.post("/api/scan-zip")
async def scan_zip(file: UploadFile = File(...)):
    """Upload and scan a zip file."""
    # Save upload to temp file
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        result = await zip_scanner.scan_zip(tmp_path)
        store_scan_result(result)
        return result
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.post("/api/report/pdf")
async def export_pdf(data: dict):
    """Generate and return a PDF report."""
    pdf_bytes = pdf_gen.generate(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=openmythos_report.pdf"}
    )


class LiveScanRequest(BaseModel):
    url: str = Field(..., description="The URL of the website to scan")
    depth: int = Field(default=2, description="Maximum crawling depth")


@app.post("/api/live-scan")
async def live_scan(request: dict):
    url = request.get("url")
    depth = request.get("depth", 1)
    timeout = request.get("timeout", 15) # Default 15s
    
    if not url:
        from fastapi import HTTPException
        raise HTTPException(400, "URL required")
    
    from live_scanner import LiveScanner
    import asyncio
    
    scanner = LiveScanner(url, depth=depth, verbose=True, timeout=timeout)
    try:
        # Run sync scanner in a separate thread with an overall timeout
        results = await asyncio.wait_for(
            asyncio.to_thread(scanner.run),
            timeout=timeout + 5 # Give a small buffer
        )
        store_scan_result(results)
        return results
    except asyncio.TimeoutError:
        return {
            "status": "error",
            "message": f"Scan timed out after {timeout} seconds",
            "vulnerabilities": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
    finally:
        scanner.close()


class ManualTestRequest(BaseModel):
    url: str
    param: str
    payload: str
    type: str # 'sqli' or 'xss'


@app.post("/api/test-target")
async def manual_test(request: ManualTestRequest):
    """Manually test a specific URL and parameter with a custom payload."""
    scanner = LiveScanner(request.url, depth=0, verbose=True)
    try:
        method = "GET" # Default to GET for simplicity in manual test
        resp = scanner.send_payload(request.url, method, request.param, request.payload)
        
        if not resp:
            return {"vulnerable": False, "target": request.url, "snippet": "No response from target."}

        vulnerable = False
        if request.type == "sqli":
            # Repurpose detection logic from scanner
            sql_errors = ["sql syntax", "mysql_fetch", "you have an error", "unclosed quotation mark", "warning: mysql"]
            if any(err in resp.text.lower() for err in sql_errors):
                vulnerable = True
        else: # xss
            if request.payload in resp.text and "&lt;" not in resp.text:
                vulnerable = True
            
        return {
            "vulnerable": vulnerable,
            "target": resp.url if hasattr(resp, 'url') else request.url,
            "snippet": resp.text[:1000] if vulnerable else "No vulnerability detected."
        }
    finally:
        scanner.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
