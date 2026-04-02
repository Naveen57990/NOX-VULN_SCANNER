"""OWASP ZAP web vulnerability scanner."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import time
import json
import requests
import subprocess
from urllib.parse import urlparse
from tools.base import BaseTool, ToolResult

class ZapTool(BaseTool):
    def __init__(self, target: str, timeout: int = 600):
        super().__init__(target, timeout)
        self.zap_port = 8080
        self.zap_api_key = ""
        self.zap_url = f"http://localhost:{self.zap_port}"
    
    def _api_call(self, endpoint: str, params: dict = None) -> dict:
        url = f"{self.zap_url}/{endpoint}"
        params = params or {}
        params["apikey"] = self.zap_api_key
        try:
            response = requests.get(url, params=params, timeout=30)
            return response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        except Exception:
            return {}
    
    def _start_zap(self) -> bool:
        if not shutil.which("zap.sh"):
            return False
        try:
            subprocess.Popen([
                "zap.sh", "-daemon", "-port", str(self.zap_port)
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(30):
                try:
                    if requests.get(f"{self.zap_url}/API/system/info", timeout=5).ok:
                        return True
                except:
                    pass
                time.sleep(2)
        except Exception:
            pass
        return False
    
    def run(self) -> ToolResult:
        if not shutil.which("zap.sh"):
            return ToolResult(
                success=True,
                tool_name="ZAP",
                raw_output="OWASP ZAP not installed - skipping",
                findings=[],
                metadata={"status": "skipped", "reason": "not installed"}
            )
        
        start_time = time.time()
        findings = []
        metadata = {"alerts": [], "urls_spidered": 0}
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        severity_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO"
        }
        
        metadata["total_alerts"] = 0
        metadata["status"] = "zap_not_available"
        
        duration = time.time() - start_time
        
        return ToolResult(
            success=True,
            tool_name=self.tool_name,
            raw_output="ZAP skipped - install ZAP manually for full functionality",
            findings=findings,
            metadata=metadata,
            duration=duration
        )

def parse_zap_report(report_path: str) -> list:
    findings = []
    try:
        with open(report_path) as f:
            report = json.load(f)
            for alert in report.get("site", [{}])[0].get("alerts", []):
                findings.append({
                    "name": alert.get("name"),
                    "severity": alert.get("risk"),
                    "url": alert.get("url"),
                    "description": alert.get("desc")
                })
    except:
        pass
    return findings
