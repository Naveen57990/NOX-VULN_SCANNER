"""Subfinder subdomain enumeration tool."""

import shutil
import json
import time
from urllib.parse import urlparse
from .base import BaseTool, ToolResult

class SubfinderTool(BaseTool):
    def run(self) -> ToolResult:
        if not shutil.which("subfinder"):
            return ToolResult(
                success=True,
                tool_name="SUBFINDER",
                raw_output="Subfinder not installed - skipping",
                findings=[],
                metadata={"status": "skipped", "reason": "not installed"}
            )
        
        start_time = time.time()
        findings = []
        metadata = {"subdomains": [], "new_domains": []}
        
        parsed = urlparse(self.target)
        domain = parsed.netloc or self.target
        
        if ":" in domain:
            domain = domain.split(":")[0]
        
        if not domain:
            domain = self.target.replace(["http://", "https://"], "")
        
        command = [
            "subfinder",
            "-d", domain,
            "-silent",
            "-o", "/tmp/subdomains.txt"
        ]
        
        stdout, stderr, returncode = self.execute(command)
        
        subdomains = []
        for line in stdout.split("\n"):
            line = line.strip()
            if line and "." in line:
                subdomains.append(line)
                metadata["subdomains"].append(line)
        
        if len(subdomains) > 1:
            findings.append(self.create_finding(
                name="Multiple Subdomains Discovered",
                description=f"Found {len(subdomains)} subdomains for {domain}",
                severity="INFO",
                url=self.target,
                evidence="\n".join(subdomains[:10]),
                remediation="Ensure all subdomains are properly secured and monitored."
            ))
        
        metadata["total_subdomains"] = len(subdomains)
        metadata["domain"] = domain
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

def get_subdomains(metadata: dict) -> list:
    return metadata.get("subdomains", [])
