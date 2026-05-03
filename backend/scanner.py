import asyncio
import time
import os
import httpx
from typing import Dict, List
from rules import scan_with_rules
from ast_analyzer import scan_python_ast
from logic_analyzer import scan_logic
from semantic_rules import scan_advanced_patterns
from complexity import calculate_complexity, is_critical_path
from ai_engine import scan_with_ollama
from groq_engine import scan_with_groq
from cache_manager import cache

async def scan_code(code: str, language: str) -> Dict:
    """
    ULTIMATE Scanner Orchestrator (Phase 2 & 3 Integrated)
    """
    start_time = time.time()
    
    # ── PHASE 1: COMPLEXITY & ROUTING ──
    complexity = calculate_complexity(code)
    critical = is_critical_path(code)
    use_heavy_ai = complexity > 0.7 or critical

    # ── PHASE 2: AST & SEMANTIC RULES ──
    try:
        if language == "python":
            from ast_analyzer import ASTAnalyzer
            ast_analyzer = ASTAnalyzer()
            ast_findings = ast_analyzer.analyze(code, language)
            
            logic_findings = scan_logic(code)
            semantic_findings = scan_advanced_patterns(code)
        else:
            # Fallback to general rules and Node AST service
            ast_findings = []
            logic_findings = []
            semantic_findings = []
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    res = await client.post("http://localhost:8001/analyze", json={"code": code, "language": language})
                    ast_findings = res.json().get("findings", []) if res.status_code == 200 else []
            except: pass
    except:
        ast_findings = []
        semantic_findings = []

    # Basic rules
    rule_findings = scan_with_rules(code, language)

    # ── PHASE 3: CONSOLIDATION ──
    all_findings = rule_findings + ast_findings + logic_findings + semantic_findings
    
    # ── PHASE 4: AI ENHANCEMENT (SMART ROUTING) ──
    ai_status = "offline"
    ai_result = {"verdict": "unknown", "summary": "AI Enrichment skipped", "confidence": 0}
    
    cached = cache.get(code, language, all_findings)
    if cached:
        ai_result = cached
        ai_status = "cached"
    else:
        try:
            # Route to appropriate engine
            if use_heavy_ai and os.getenv("GROQ_API_KEY"):
                print(f"DEBUG: Complexity {complexity:.2f} - Routing to HIGH TIER AI")
                ai_result = await scan_with_groq(code, language, all_findings)
                ai_status = "online (Strong)"
            else:
                ai_task = scan_with_ollama(code, language, all_findings)
                ai_result = await asyncio.wait_for(ai_task, timeout=25.0)
                if ai_result.get("enabled"):
                    ai_status = "online (Local)"
            
            if ai_status != "offline":
                cache.set(code, language, all_findings, ai_result)
        except Exception: pass

    # Merge AI findings
    final_findings = all_findings.copy()
    for f in ai_result.get("additional_findings", []):
        is_dup = any(d.get("type") == f.get("type") and d.get("line") == f.get("line") for d in all_findings)
        if not is_dup:
            f["source"] = "ai-deep"
            final_findings.append(f)

    # ── PHASE 4: RISK & CONFIDENCE SCORING ──
    # Increase confidence if AST and AI agree
    rule_conf = 0.8 if rule_findings else 0.5
    ast_conf = 0.95 if ast_findings else 0.0
    
    # AI Confidence with boost for consensus
    raw_ai_conf = (ai_result.get("confidence", 0) / 100.0) if ai_status.startswith("online") else 0.0
    
    # Consensus Boost: If both detect same line/type, boost confidence
    consensus_boost = 0
    if ast_findings and ai_status.startswith("online"):
        for af in ast_findings:
            if any(f.get("type") == af.get("type") and f.get("line") == af.get("line") for f in ai_result.get("additional_findings", [])):
                consensus_boost = 0.15
                break
    
    final_confidence = int(min(1.0, max(rule_conf, ast_conf, raw_ai_conf) + consensus_boost) * 100)

    # ── PHASE 5: RISK SCORING ──
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_score = 0
    for f in final_findings:
        sev = f.get("severity", "low").lower()
        if sev in summary:
            summary[sev] += 1
            total_score += weights.get(sev, 3)

    risk_score = min(100, total_score)
    risk_level = "critical" if risk_score > 80 else "high" if risk_score > 60 else "medium" if risk_score > 30 else "low"
    
    scan_time = int((time.time() - start_time) * 1000)

    return {
        "status": "success",
        "vulnerabilities": final_findings,
        "findings": final_findings,
        "summary": summary,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_time_ms": scan_time,
        "verdict": ai_result.get("verdict", "vulnerable" if final_findings else "safe"),
        "confidence": ai_result.get("confidence", 70),
        "reasoning": ai_result.get("reasoning", "Multi-layered analysis complete."),
        "sources": {"rules": True, "ast": True, "llm": ai_status.startswith("online")},
        "metadata": {
            "ai_status": ai_status,
            "complexity_score": round(complexity, 2),
            "critical_path": critical,
            "routing": "High-Tier" if use_heavy_ai else "Standard",
            "total_findings": len(final_findings),
            "raw_ai_response": ai_result.get("raw_response") if not ai_result.get("additional_findings") else None
        }
    }