"""AI-powered analysis module for vulnerability findings."""

import json
from typing import Optional
from ..config import config
from ..memory import Finding

class AIAnalyzer:
    def __init__(self, api_key: str = "", provider: str = "anthropic"):
        self.api_key = api_key or config.OPENAI_API_KEY or config.ANTHROPIC_API_KEY
        self.provider = provider or config.AI_PROVIDER
        self.model = config.AI_MODEL
    
    def analyze_findings(self, findings: list[Finding], target: str) -> dict:
        if not self.api_key:
            return {"error": "No API key configured", "summary": self._basic_summary(findings)}
        
        prompt = self._build_analysis_prompt(findings, target)
        
        try:
            if "claude" in self.model.lower() or self.provider == "anthropic":
                response = self._call_anthropic(prompt)
            else:
                response = self._call_openai(prompt)
            
            return self._parse_ai_response(response, findings)
        except Exception as e:
            return {"error": str(e), "summary": self._basic_summary(findings)}
    
    def _build_analysis_prompt(self, findings: list[Finding], target: str) -> str:
        findings_json = json.dumps([f.to_dict() for f in findings], indent=2)
        
        prompt = f"""You are a senior cybersecurity analyst. Analyze the following vulnerability scan results for the target: {target}

FINDINGS:
{findings_json}

TASK:
1. Identify false positives and explain why each is likely a false positive
2. Prioritize findings by actual risk to the organization
3. Provide actionable remediation steps for HIGH and CRITICAL findings
4. Identify attack chains where multiple low-severity issues combine
5. Calculate an overall risk assessment (0-10)

Respond in JSON format:
{{
    "false_positives": [
        {{"finding_id": "...", "reason": "..."}}
    ],
    "risk_assessment": {{
        "score": 0-10,
        "summary": "...",
        "critical_findings": ["..."],
        "attack_chains": ["..."]
    }},
    "remediation_priority": [
        {{"finding_id": "...", "action": "...", "effort": "low/medium/high"}}
    ],
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
        except ImportError:
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
        except ImportError:
            return "{}"
    
    def _parse_ai_response(self, response: str, findings: list[Finding]) -> dict:
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
    
    def _basic_summary(self, findings: list[Finding]) -> dict:
        by_severity = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "top_findings": [f.name for f in findings if f.severity in ["CRITICAL", "HIGH"]][:5]
        }
    
    def enrich_finding(self, finding: Finding) -> Finding:
        if not self.api_key:
            return finding
        
        prompt = f"""Enhance this vulnerability finding:

Name: {finding.name}
Description: {finding.description}
Severity: {finding.severity}

Provide:
1. More detailed description (2-3 sentences)
2. CVSS v3.1 score if applicable
3. Related CWE/CVE if known
4. Specific remediation steps (3-5 bullet points)

Respond in JSON format:
{{
    "enhanced_description": "...",
    "cvss_score": 0.0-10.0,
    "related_cwe": ["CWE-XXX"],
    "related_cve": ["CVE-XXXX-XXXXX"],
    "remediation_steps": ["step1", "step2", "step3"]
}}
"""
        try:
            if "claude" in self.model.lower():
                response = self._call_anthropic(prompt)
            else:
                response = self._call_openai(prompt)
            
            enhanced = json.loads(response)
            finding.description = enhanced.get("enhanced_description", finding.description)
            if enhanced.get("cvss_score"):
                finding.cvss = enhanced.get("cvss_score")
            if enhanced.get("remediation_steps"):
                finding.remediation = "\n".join(f"- {s}" for s in enhanced["remediation_steps"])
            if enhanced.get("related_cwe"):
                finding.cve = ", ".join(enhanced["related_cwe"])
        except:
            pass
        
        return finding


class AIGenerator:
    def __init__(self, api_key: str = "", provider: str = "anthropic"):
        self.api_key = api_key or config.OPENAI_API_KEY or config.ANTHROPIC_API_KEY
        self.provider = provider
        self.model = config.AI_MODEL
    
    def generate_executive_summary(self, findings: list[Finding], target: str, risk_score: float) -> str:
        if not self.api_key:
            return self._basic_summary(findings, target, risk_score)
        
        prompt = f"""Generate an executive summary for a vulnerability assessment report.

Target: {target}
Risk Score: {risk_score}/10
Total Findings: {len(findings)}

Provide a concise executive summary (3-4 paragraphs) covering:
1. Scope and methodology
2. Key findings
3. Business impact
4. Recommended next steps

Be professional and suitable for C-level executives.
"""
        try:
            if "claude" in self.model.lower():
                return self._call_anthropic(prompt)
            return self._call_openai(prompt)
        except:
            return self._basic_summary(findings, target, risk_score)
    
    def _call_anthropic(self, prompt: str) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    
    def _call_openai(self, prompt: str) -> str:
        import openai
        client = openai.OpenAI(api_key=self.api_key)
        response = client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    
    def _basic_summary(self, findings: list, target: str, risk_score: float) -> str:
        by_severity = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        return f"""Vulnerability Assessment Report
Target: {target}
Risk Score: {risk_score}/10

Summary:
- Total Findings: {len(findings)}
- Critical: {by_severity.get('CRITICAL', 0)}
- High: {by_severity.get('HIGH', 0)}
- Medium: {by_severity.get('MEDIUM', 0)}
- Low: {by_severity.get('LOW', 0)}
- Informational: {by_severity.get('INFO', 0)}

{'Immediate action required for critical and high severity findings.' if by_severity.get('CRITICAL', 0) or by_severity.get('HIGH', 0) else 'No critical vulnerabilities detected.'}
"""
