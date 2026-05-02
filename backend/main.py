from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import httpx
import os
from typing import List
from pydantic import BaseModel, Field
from scanner import scan_code

# In-memory history (last 50 scans)
scan_history: List[dict] = []
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
