import json
import re
import httpx
import os
from typing import Dict

async def scan_with_groq(code: str, language: str, rule_findings: list) -> Dict:
    """
    Deep semantic analysis using Groq Cloud.
    High-performance fallback for Architecture V2.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return {"verdict": "unknown", "confidence": 0, "summary": "Groq API key not set."}

    try:
        findings_context = ""
        if rule_findings:
            findings_context = "Scanners already found:\n"
            for f in rule_findings:
                findings_context += f"- {f.get('type')}: line {f.get('line')}\n"
            findings_context += "\nFocus on NEW deep-flow issues.\n"

        # ── Refined PRO-LEVEL Prompt ─────────────────────────────────────
        prompt = f"""You are an expert security auditor performing deep semantic analysis on {language} code.

### ANALYSIS METHODOLOGY:
1. DATA-FLOW ANALYSIS (CRITICAL): 
   - Identify sources (user input), track transformations, and detect if sanitization is effective. 
   - Determine if data reaches a dangerous sink.
2. FALSE POSITIVE REDUCTION:
   - Do NOT flag hardcoded strings or safe parameterized queries.
   - Precision over quantity.

{findings_context}

CODE:
```{language}
{code}
```

Return ONLY valid JSON:
{{
  "verdict": "vulnerable" | "safe",
  "confidence": 0-100,
  "summary": "brief assessment",
  "reasoning": "data-flow analysis explanation",
  "additional_findings": [
    {{
      "type": "Vulnerability Type",
      "severity": "Low | Medium | High | Critical",
      "line": number,
      "code_snippet": "the line",
      "description": "source -> sink path",
      "fix": "fix suggestion"
    }}
  ]
}}"""

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "llama3-70b-8192",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"}
                }
            )
            
            if response.status_code != 200:
                return {"verdict": "unknown", "confidence": 0}

            choice = response.json()["choices"][0]["message"]["content"]
            parsed = json.loads(choice)
            
            parsed["confidence"] = int(parsed.get("confidence", 0))
            parsed.setdefault("additional_findings", [])
            return parsed

    except Exception as e:
        print(f"Groq error: {e}")
        return {"verdict": "unknown", "confidence": 0}
