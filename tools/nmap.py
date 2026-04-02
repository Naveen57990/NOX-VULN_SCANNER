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
        metadata = {"open_ports": [], "services": {}, "os_detection": "", "web_detected": False}
        
        parsed = urlparse(self.target)
        host = parsed.netloc or self.target
        
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]
        
        print(f"[*] Nmap: Scanning {host}")
        
        command = [
            "nmap", "-Pn", "-T4", "-F",
            "-oG", "-",
            host
        ]
        
        stdout, stderr, returncode = self.execute(command)
        metadata["raw_output"] = stdout[:5000]
        metadata["nmap_stderr"] = stderr[:1000]
        
        print(f"[*] Nmap: Return code = {returncode}")
        print(f"[*] Nmap output length: {len(stdout)}")
        
        if stdout:
            port_pattern = r"Ports: ([^\n]+)"
            port_match = re.search(port_pattern, stdout)
            if port_match:
                ports_str = port_match.group(1)
                port_items = ports_str.split(",")
                for item in port_items:
                    parts = item.strip().split("/")
                    if len(parts) >= 3:
                        port = parts[0].strip()
                        state = parts[1].strip()
                        service = parts[2].strip() if len(parts) > 2 else "unknown"
                        if state == "open":
                            metadata["open_ports"].append({"port": port, "state": state, "service": service})
                            metadata["services"][port] = service
                            if port in ["80", "443", "8080", "8443", "8000"]:
                                metadata["web_detected"] = True
                                print(f"[*] Nmap: Found open port {port} ({service})")
        
        if not metadata["web_detected"]:
            if parsed.scheme in ["http", "https"]:
                metadata["web_detected"] = True
                metadata["services"]["80"] = "http"
                metadata["services"]["443"] = "https"
                print(f"[*] Nmap: URL scheme indicates web service - forcing web detection")
        
        if metadata["web_detected"]:
            findings.append(self.create_finding(
                name="Web Service Detected",
                description=f"Web service detected on {host}",
                severity="INFO",
                evidence=f"Open ports: {list(metadata['services'].keys())}"
            ))
        
        duration = time.time() - start_time
        print(f"[*] Nmap: Completed in {duration:.1f}s, found {len(metadata['open_ports'])} open ports")
        
        return ToolResult(
            success=True,
            tool_name=self.tool_name,
            raw_output=stdout,
            findings=findings,
            metadata=metadata,
            duration=duration
        )

def get_open_ports(metadata: dict) -> list:
    return metadata.get("open_ports", [])

def has_web_service(metadata: dict) -> bool:
    return metadata.get("web_detected", False) or bool(metadata.get("services", {}))

def has_database(metadata: dict) -> bool:
    services = metadata.get("services", {})
    db_ports = {"3306", "5432", "1433", "27017", "6379"}
    return any(port in db_ports for port in services.keys())
