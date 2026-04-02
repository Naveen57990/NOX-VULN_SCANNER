"""AI-powered analysis module for vulnerability findings."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import os

class AIAnalyzer:
    def __init__(self, api_key: str = "", provider: str = "openai"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        self.provider = provider or os.getenv("AI_PROVIDER", "openai")
        self.model = os.getenv("AI_MODEL", "gpt-4")
    
    def analyze_findings(self, findings, target: str) -> dict:
        if not self.api_key:
            return {"error": "No API key configured", "summary": self._basic_summary(findings)}
        
        prompt = self._build_analysis_prompt(findings, target)
        
        try:
            if self.provider == "anthropic":
                response = self._call_anthropic(prompt)
            else:
                response = self._call_openai(prompt)
            
            return self._parse_ai_response(response, findings)
        except Exception as e:
            return {"error": str(e), "summary": self._basic_summary(findings)}
    
    def _build_analysis_prompt(self, findings, target: str) -> str:
        findings_json = json.dumps([f.to_dict() if hasattr(f, 'to_dict') else f for f in findings], indent=2)
        
        prompt = f"""You are a senior cybersecurity analyst. Analyze the following vulnerability scan results for the target: {target}

FINDINGS:
{findings_json}

TASK:
1. Identify false positives
2. Prioritize findings by risk
3. Provide remediation steps
4. Calculate overall risk assessment (0-10)

Respond in JSON format:
{{
    "false_positives": [],
    "risk_assessment": {{"score": 0-10, "summary": "...", "critical_findings": [], "attack_chains": []}},
    "remediation_priority": [],
    "analyst_notes": "..."
}}
"""
        return prompt
    
    def _call_anthropic(self, prompt: str) -> str:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}]
            )
            return message.content[0].text
        except Exception:
            return self._call_openai(prompt)
    
    def _call_openai(self, prompt: str) -> str:
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception:
            return "{}"
    
    def _parse_ai_response(self, response: str, findings) -> dict:
        try:
            result = json.loads(response)
            return {
                "success": True,
                "analysis": result,
                "suppressed_findings": [fp["finding_id"] for fp in result.get("false_positives", [])]
            }
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": "Failed to parse AI response",
                "summary": self._basic_summary(findings)
            }
    
    def _basic_summary(self, findings) -> dict:
        by_severity = {}
        for f in findings:
            sev = getattr(f, 'severity', 'UNKNOWN')
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "top_findings": [f.name for f in findings if getattr(f, 'severity', '') in ["CRITICAL", "HIGH"]][:5]
        }


class AIGenerator:
    def __init__(self, api_key: str = "", provider: str = "openai"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        self.provider = provider
        self.model = os.getenv("AI_MODEL", "gpt-4")
    
    def generate_executive_summary(self, findings, target: str, risk_score: float) -> str:
        if not self.api_key:
            return self._basic_summary(findings, target, risk_score)
        
        prompt = f"""Generate executive summary for vulnerability assessment. Target: {target}, Risk Score: {risk_score}/10, Findings: {len(findings)}"""
        try:
            if self.provider == "anthropic":
                return self._call_anthropic(prompt)
            return self._call_openai(prompt)
        except:
            return self._basic_summary(findings, target, risk_score)
    
    def _call_anthropic(self, prompt: str) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        message = client.messages.create(model=self.model, max_tokens=2048, messages=[{"role": "user", "content": prompt}])
        return message.content[0].text
    
    def _call_openai(self, prompt: str) -> str:
        import openai
        client = openai.OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(model=self.model, messages=[{"role": "user", "content": prompt}])
        return response.choices[0].message.content
    
    def _basic_summary(self, findings, target: str, risk_score: float) -> str:
        by_severity = {}
        for f in findings:
            sev = getattr(f, 'severity', 'UNKNOWN')
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return f"""Vulnerability Assessment Report
Target: {target}
Risk Score: {risk_score}/10

Summary:
- Total Findings: {len(findings)}
- Critical: {by_severity.get('CRITICAL', 0)}
- High: {by_severity.get('HIGH', 0)}
- Medium: {by_severity.get('MEDIUM', 0)}
- Low: {by_severity.get('LOW', 0)}

{'Immediate action required for critical and high severity findings.' if by_severity.get('CRITICAL', 0) or by_severity.get('HIGH', 0) else 'No critical vulnerabilities detected.'}
"""
