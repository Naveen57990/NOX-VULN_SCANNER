"""SQLMap SQL injection scanner."""

import json
import time
from urllib.parse import urlparse
from .base import BaseTool, ToolResult

class SqlmapTool(BaseTool):
    def run(self) -> ToolResult:
        start_time = time.time()
        findings = []
        metadata = {"vulnerable_params": [], "injection_types": []}
        
        parsed = urlparse(self.target)
        url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            url += f"?{parsed.query}"
        
        command = [
            "sqlmap", "-u", url,
            "--batch", "--random-agent",
            "--output-dir", "/tmp/sqlmap",
            "--smart",
            "--level=1", "--risk=1"
        ]
        
        stdout, stderr, returncode = self.execute(command)
        
        vulnerable_params = []
        injection_types = []
        
        if "Parameter:" in stdout and ("is vulnerable" in stdout.lower() or "vulnerable" in stdout.lower()):
            vuln_params = []
            for line in stdout.split("\n"):
                if "Parameter:" in line:
                    param = line.split("Parameter:")[-1].strip().split()[0] if line.split("Parameter:")[-1].strip() else ""
                    if param:
                        vuln_params.append(param)
            vulnerable_params.extend(vuln_params)
        
        injection_keywords = {
            "boolean-based blind": "BOOLEAN",
            "error-based": "ERROR",
            "stacked queries": "STACKED",
            "time-based blind": "TIME",
            "UNION query": "UNION"
        }
        
        for keyword, injection_type in injection_keywords.items():
            if keyword.lower() in stdout.lower():
                injection_types.append(injection_type)
        
        if vulnerable_params:
            for param in vulnerable_params:
                findings.append(self.create_finding(
                    name="SQL Injection Vulnerability",
                    description=f"Potential SQL injection vulnerability detected in parameter: {param}",
                    severity="CRITICAL",
                    url=self.target,
                    parameter=param,
                    evidence=f"Injection types: {', '.join(injection_types)}",
                    remediation="Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and sanitization.",
                    cve="CWE-89"
                ))
        elif "injection" in stdout.lower() and "vulnerable" in stdout.lower():
            findings.append(self.create_finding(
                name="SQL Injection Detected",
                description="SQLMap detected potential SQL injection vulnerability",
                severity="HIGH",
                url=self.target,
                evidence=stdout[:500],
                remediation="Review and fix SQL query construction using parameterized queries."
            ))
        
        metadata["vulnerable_params"] = vulnerable_params
        metadata["injection_types"] = injection_types
        metadata["raw_output"] = stdout[:3000]
        
        duration = time.time() - start_time
        
        return ToolResult(
            success=True,
            tool_name=self.tool_name,
            raw_output=stdout,
            findings=findings,
            metadata=metadata,
            duration=duration
        )

def get_vulnerable_endpoints(metadata: dict) -> list:
    return metadata.get("vulnerable_params", [])
