"""Gobuster directory and file scanner."""

import json
import time
from urllib.parse import urlparse
from .base import BaseTool, ToolResult
from ..config import config

class GobusterTool(BaseTool):
    def run(self) -> ToolResult:
        start_time = time.time()
        findings = []
        metadata = {"directories": [], "files": [], "sensitive_endpoints": []}
        
        parsed = urlparse(self.target)
        url = f"{parsed.scheme}://{parsed.netloc}"
        
        wordlist = config.WORDLISTS.get("directories", "/usr/share/wordlists/dirb/common.txt")
        
        command = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", "10",
            "-q",
            "-o", "/tmp/gobuster.txt"
        ]
        
        if parsed.scheme == "https":
            command.append("k")
        
        stdout, stderr, returncode = self.execute(command)
        
        sensitive_patterns = [
            ("admin", "Admin Panel Exposed", "HIGH"),
            ("login", "Login Page Found", "LOW"),
            ("config", "Configuration Directory", "MEDIUM"),
            ("backup", "Backup Directory", "MEDIUM"),
            (".git", "Git Repository Exposed", "HIGH"),
            (".env", "Environment File Exposed", "CRITICAL"),
            ("api", "API Endpoint Found", "INFO"),
            ("swagger", "API Documentation Exposed", "MEDIUM"),
            ("debug", "Debug Mode Detected", "HIGH"),
            ("phpmyadmin", "phpMyAdmin Detected", "HIGH")
        ]
        
        for line in stdout.split("\n"):
            if "/" in line and not line.startswith("gobuster"):
                parts = line.split()
                if len(parts) >= 2:
                    path = parts[0]
                    metadata["directories"].append(path)
                    
                    for pattern, name, severity in sensitive_patterns:
                        if pattern.lower() in path.lower():
                            findings.append(self.create_finding(
                                name=name,
                                description=f"Sensitive path discovered: {path}",
                                severity=severity,
                                url=f"{url}{path}",
                                evidence=line
                            ))
        
        metadata["total_found"] = len(metadata["directories"])
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

def get_discovered_paths(metadata: dict) -> list:
    return metadata.get("directories", [])
