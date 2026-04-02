"""Nikto web server scanner."""

import json
import time
import re
from urllib.parse import urlparse
from .base import BaseTool, ToolResult

class NiktoTool(BaseTool):
    def run(self) -> ToolResult:
        start_time = time.time()
        findings = []
        metadata = {"vulnerabilities": [], "server_info": {}}
        
        parsed = urlparse(self.target)
        host = parsed.netloc or self.target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        command = [
            "nikto", "-h", host, "-p", str(port),
            "-Format", "txt",
            "-output", "/tmp/nikto.txt"
        ]
        
        if parsed.scheme == "https":
            command.append("-ssl")
        
        stdout, stderr, returncode = self.execute(command)
        
        metadata["raw_output"] = stdout[:5000]
        
        server_patterns = [
            (r"Server: (.+)", "server"),
            (r"+ OSVDB-\d+: (.+)", "osvdb"),
            (r"+ /[\w/]+: (.+)", "path_issue")
        ]
        
        for line in stdout.split("\n"):
            server_match = re.search(server_patterns[0][0], line)
            if server_match:
                metadata["server_info"]["server"] = server_match.group(1)
            
            osvdb_match = re.search(r"\+ OSVDB-(\d+): (.+)", line)
            if osvdb_match:
                metadata["vulnerabilities"].append({
                    "id": f"OSVDB-{osvdb_match.group(1)}",
                    "description": osvdb_match.group(2)
                })
        
        vuln_keywords = {
            "directory indexing": ("Directory Indexing Enabled", "MEDIUM", "Disable directory listing on the web server."),
            "apache": ("Apache Misconfiguration", "LOW", "Review Apache configuration for security best practices."),
            "nginx": ("Nginx Configuration Review Needed", "LOW", "Review Nginx configuration for security best practices."),
            "robots.txt": ("Robots.txt Exposes Sensitive Paths", "LOW", "Review robots.txt to ensure no sensitive paths are exposed."),
            "backup": ("Backup File Found", "MEDIUM", "Remove or secure backup files from web root."),
            "config": ("Configuration File Accessible", "HIGH", "Restrict access to configuration files."),
            "default": ("Default Page/Credentials", "HIGH", "Change default credentials and remove default pages."),
            "ssl": ("SSL/TLS Issue", "MEDIUM", "Configure SSL/TLS with strong ciphers and proper certificates.")
        }
        
        output_lower = stdout.lower()
        for keyword, (name, severity, remediation) in vuln_keywords.items():
            if keyword in output_lower:
                findings.append(self.create_finding(
                    name=name,
                    description=f"Nikto detected potential issue related to: {keyword}",
                    severity=severity,
                    url=self.target,
                    evidence=stdout[:1000],
                    remediation=remediation
                ))
        
        if "x-xss-protection" not in output_lower or "strict-transport-security" not in output_lower:
            findings.append(self.create_finding(
                name="Missing Security Headers",
                description="Web server is missing important security headers",
                severity="MEDIUM",
                url=self.target,
                remediation="Add security headers: X-XSS-Protection, HSTS, X-Frame-Options, Content-Security-Policy"
            ))
        
        duration = time.time() - start_time
        
        return ToolResult(
            success=True,
            tool_name=self.tool_name,
            raw_output=stdout,
            findings=findings,
            metadata=metadata,
            duration=duration
        )

def parse_nikto_output(output: str) -> dict:
    result = {"vulnerabilities": [], "server": ""}
    for line in output.split("\n"):
        if "Server:" in line:
            result["server"] = line.split("Server:")[-1].strip()
        if "OSVDB" in line:
            result["vulnerabilities"].append(line.strip())
    return result
