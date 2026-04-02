"""Nmap port and service scanner."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import time
from urllib.parse import urlparse
from tools.base import BaseTool, ToolResult

class NmapTool(BaseTool):
    def run(self) -> ToolResult:
        start_time = time.time()
        findings = []
        metadata = {"open_ports": [], "services": {}, "os_detection": ""}
        
        parsed = urlparse(self.target)
        host = parsed.netloc or self.target
        
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]
        
        command = [
            "nmap", "-sV", "-sC", "-oX", "-",
            "-p", "21,22,23,25,80,443,445,3306,3389,5432,8080,8443",
            "--script", "http-title,http-headers,http-enum",
            host
        ]
        
        stdout, stderr, returncode = self.execute(command)
        metadata["raw_output"] = stdout[:5000]
        
        if returncode == 0 and stdout:
            port_pattern = r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)"
            for match in re.finditer(port_pattern, stdout):
                port_info = {
                    "port": match.group(1),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4)
                }
                metadata["open_ports"].append(port_info)
                metadata["services"][match.group(1)] = match.group(4)
            
            if "http" in stdout.lower():
                web_ports = [p for p, s in metadata["services"].items() 
                           if "http" in s.lower() or p in ["80", "443", "8080", "8443"]]
                if web_ports:
                    findings.append(self.create_finding(
                        name="Web Service Detected",
                        description=f"Web service(s) detected on port(s): {', '.join(web_ports)}",
                        severity="INFO",
                        evidence=f"Services: {metadata['services']}"
                    ))
            
            os_match = re.search(r"OS details: (.+)", stdout)
            if os_match:
                metadata["os_detection"] = os_match.group(1)
        
        duration = time.time() - start_time
        
        return ToolResult(
            success=returncode == 0,
            tool_name=self.tool_name,
            raw_output=stdout,
            findings=findings,
            metadata=metadata,
            duration=duration
        )

def get_open_ports(metadata: dict) -> list:
    return metadata.get("open_ports", [])

def has_web_service(metadata: dict) -> bool:
    services = metadata.get("services", {})
    web_ports = {"80", "443", "8080", "8443", "8000", "8888"}
    return any(port in web_ports for port in services.keys())

def has_database(metadata: dict) -> bool:
    services = metadata.get("services", {})
    db_ports = {"3306", "5432", "1433", "27017", "6379"}
    return any(port in db_ports for port in services.keys())
