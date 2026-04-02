"""OWASP ZAP web vulnerability scanner."""

import time
import json
import requests
import subprocess
from urllib.parse import urlparse
from .base import BaseTool, ToolResult
from ..config import config

class ZapTool(BaseTool):
    def __init__(self, target: str, timeout: int = 600):
        super().__init__(target, timeout)
        self.zap_port = config.ZAP_PORT
        self.zap_api_key = config.ZAP_API_KEY
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
        try:
            subprocess.Popen([
                "zap.sh", "-daemon", "-port", str(self.zap_port),
                "-config", f"api.key={self.zap_api_key}"
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
        start_time = time.time()
        findings = []
        metadata = {"alerts": [], "urls_spidered": 0}
        
        if not self._start_zap():
            command = [
                "docker", "run", "--rm", "-v", f"{config.OUTPUT_DIR}:/output",
                "owasp/zap2docker-stable",
                "zap-baseline.py", "-t", self.target, "-J", "zap_report.json", "-d"
            ]
            stdout, stderr, returncode = self.execute(command, check=False)
            
            if returncode == 0:
                try:
                    with open(config.OUTPUT_DIR / "zap_report.json") as f:
                        report = json.load(f)
                        metadata["alerts"] = report.get("site", [{}])[0].get("alerts", [])
                except:
                    pass
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        self._api_call("spider/action/scan", {"url": base_url, "maxChildren": 10})
        time.sleep(5)
        
        spider_results = self._api_call("spider/view/status", {})
        metadata["urls_spidered"] = spider_results.get("status", 0)
        
        self._api_call("ascan/action/scan", {"url": base_url, "recurse": "true"})
        time.sleep(10)
        
        alerts = self._api_call("core/view/alerts", {"baseurl": base_url}) or []
        if isinstance(alerts, dict):
            alerts = alerts.get("alerts", [])
        
        severity_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO"
        }
        
        for alert in alerts:
            risk = alert.get("risk", "Low")
            findings.append(self.create_finding(
                name=alert.get("name", "Unknown Vulnerability"),
                description=alert.get("desc", ""),
                severity=severity_map.get(risk, "LOW"),
                url=alert.get("url", self.target),
                parameter=alert.get("param", ""),
                evidence=alert.get("evidence", ""),
                remediation=alert.get("solution", ""),
                cve=alert.get("cweid", ""),
                cvss=float(alert.get("cvss", 0))
            ))
        
        metadata["total_alerts"] = len(findings)
        
        duration = time.time() - start_time
        
        return ToolResult(
            success=True,
            tool_name=self.tool_name,
            raw_output=json.dumps(metadata),
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
