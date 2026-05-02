import json
import re
import httpx
from typing import Dict, List

async def scan_with_ollama(code: str, language: str, rule_findings: List[dict]) -> Dict:
    """
    AI ENHANCER ENGINE (V2 FINAL)
    Focuses only on deep-flow vulnerabilities and false-positive reduction.
    """
    fallback_response = {
        "verdict": "unknown",
        "confidence": 80,
        "summary": "AI analysis skipped (Offline or Error).",
        "reasoning": "Rule-based analysis complete.",
        "additional_findings": [],
        "enabled": False,
        "status": "offline"
    }

    try:
        # Check if Ollama is reachable first
        try:
            async with httpx.AsyncClient(timeout=5.0) as health_client:
                health_response = await health_client.get("http://localhost:11434/api/tags")
                if health_response.status_code != 200:
                    return fallback_response
        except Exception as e:
            # REGEX FALLBACK: Try to extract findings even if JSON is malformed
            findings_match = re.findall(r'\{"type":\s*"([^"]+)",\s*"severity":\s*"([^"]+)",\s*"line":\s*(\d+)', str(e))
            if findings_match:
                extracted = []
                for t, s, l in findings_match:
                    extracted.append({
                        "type": t,
                        "severity": s.lower(),
                        "line": int(l),
                        "description": "Extracted via regex fallback.",
                        "fix": "Review manually (JSON truncated)."
                    })
                return {
                    "verdict": "vulnerable",
                    "confidence": 60,
                    "summary": "AI response was truncated, but some findings were extracted.",
                    "reasoning": "Malformed JSON from model.",
                    "additional_findings": extracted,
                    "enabled": True,
                    "raw_response": str(e)
                }

            return {**fallback_response, "reasoning": f"Parse error: {str(e)}", "raw_response": str(e)}

        # Build rule context
        rule_context = ""
        if rule_findings:
            rule_context = "PREVIOUS ENGINE FINDINGS (DO NOT DUPLICATE):\n"
            for f in rule_findings:
                rule_context += f"- {f.get('type')} at line {f.get('line')}\n"
            rule_context += "\nFocus ONLY on NEW deep-flow issues.\n"

        # PRE-PROCESSING: Strip non-code content to focus AI
        def pre_process(c):
            c = re.sub(r'<[^>]+>', '', c) # Strip HTML
            c = re.sub(r'\[\d{4}-\d{2}-\d{2}.*?\].*', '', c) # Strip common logs
            return c.strip()

        clean_code = pre_process(code)
        truncated_code = clean_code[:4000] if len(clean_code) > 4000 else clean_code
        
        is_complex = len(truncated_code) > 2000
        complex_instruction = "IMPORTANT: Focus ONLY on security-relevant code patterns. Ignore boilerplate and error logs. Trace variables cross-functionally." if is_complex else ""

        prompt = f"""You are a security expert. Analyze this code for:

1. Taint-based vulnerabilities (SQLi, XSS, command injection)
2. **Business logic flaws**: missing authorization checks, IDOR, race conditions, token reusability, email verification bypass.

Return JSON with fields: verdict, confidence, summary, reasoning, additional_findings (each with type, severity, line, code_snippet, description, fix, exploitation, corrected_code).

DO NOT repeat any findings listed below:
{rule_context}

CODE TO ANALYZE:
```{language}
{truncated_code}
```
"""

        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "deepseek-coder:1.3b",
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 1024,
                        "top_p": 0.9
                    }
                }
            )

            if response.status_code != 200:
                print(f"Ollama returned status {response.status_code}")
                return fallback_response

            data = response.json()
            raw_text = data.get("response", "").strip()

            if not raw_text:
                return fallback_response

            # Multiple JSON extraction strategies
            parsed = None
            
            # Strategy 1: Find JSON between curly braces
            match = re.search(r'(\{.*\})', raw_text, re.DOTALL)
            if match:
                json_str = match.group(1)
                # Cleanup common issues
                json_str = re.sub(r',\s*([}\]])', r'\1', json_str) # Remove trailing commas
                json_str = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', json_str) # Remove control chars
                try:
                    parsed = json.loads(json_str)
                except json.JSONDecodeError:
                    pass

            # Strategy 2: If no match, try parsing the whole thing after cleaning
            if not parsed:
                try:
                    clean_text = re.sub(r'```json\s*', '', raw_text)
                    clean_text = re.sub(r'```\s*', '', clean_text)
                    parsed = json.loads(clean_text)
                except json.JSONDecodeError:
                    pass

            # Strategy 3: Heuristic fallback if parsing failed
            if not parsed:
                has_vulnerability = any(keyword in raw_text.lower() for keyword in
                                     ['sql injection', 'xss', 'command injection', 'vulnerable'])
                parsed = {
                    "verdict": "vulnerable" if has_vulnerability else "safe",
                    "confidence": 70 if has_vulnerability else 30,
                    "summary": "AI analysis completed (heuristic fallback)",
                    "reasoning": raw_text[:500],
                    "additional_findings": []
                }

            # Standardize and normalize
            parsed.setdefault("verdict", "unknown")
            parsed.setdefault("confidence", 70)
            parsed.setdefault("summary", "AI analysis completed")
            parsed.setdefault("reasoning", "Analysis based on code patterns")
            parsed.setdefault("additional_findings", [])
            
            try:
                parsed["confidence"] = int(parsed.get("confidence", 70))
            except (ValueError, TypeError):
                parsed["confidence"] = 70
                
            parsed["enabled"] = True
            parsed["status"] = "online"

            # Clean up additional_findings
            cleaned_findings = []
            for finding in parsed.get("additional_findings", []):
                cleaned_finding = {
                    "type": finding.get("type", "Unknown"),
                    "severity": finding.get("severity", "medium").lower(),
                    "line": finding.get("line", 0),
                    "code_snippet": finding.get("code_snippet", "")[:200],
                    "description": finding.get("description", ""),
                    "fix": finding.get("fix", ""),
                    "corrected_code": finding.get("corrected_code", ""),
                    "exploitation": finding.get("exploitation", "")
                }
                cleaned_findings.append(cleaned_finding)
            parsed["additional_findings"] = cleaned_findings

            print(f"✅ AI analysis successful - Confidence: {parsed['confidence']}%")
            return parsed

    except httpx.TimeoutException:
        print("Ollama timeout")
        return fallback_response
    except httpx.ConnectError:
        print("Ollama connection error")
        return fallback_response
    except Exception as e:
        print(f"Ollama unexpected error: {e}")
        return fallback_response