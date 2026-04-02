"""Orchestrator module that coordinates all security tools."""

import time
from datetime import datetime
from typing import Optional
from ..config import config
from ..memory import GlobalMemory, ScanMetadata
from ..tools import (
    NmapTool, ZapTool, SqlmapTool, NiktoTool,
    GobusterTool, FfufTool, SubfinderTool,
    has_web_service, has_database, get_open_ports
)
from ..ai import AIAnalyzer, AIGenerator

class ScanOrchestrator:
    def __init__(self, target_url: str, scan_id: str = None):
        self.target_url = target_url
        self.scan_id = scan_id or f"scan_{int(time.time())}"
        self.memory = GlobalMemory.get_or_create(self.scan_id)
        self.results = {}
        self.start_time = datetime.utcnow().isoformat()
        self.ai_analyzer = AIAnalyzer()
        self.ai_generator = AIGenerator()
    
    def authorize_target(self) -> bool:
        if not config.AUTHORIZED_TARGETS or config.AUTHORIZED_TARGETS == [""]:
            return True
        return any(auth in self.target_url for auth in config.AUTHORIZED_TARGETS)
    
    def run_reconnaissance(self) -> dict:
        print(f"[+] Running reconnaissance on {self.target_url}")
        
        nmap_result = NmapTool(self.target_url, config.NMAP_TIMEOUT).run()
        self.results["nmap"] = nmap_result
        self._store_findings(nmap_result.findings)
        
        if has_web_service(nmap_result.metadata):
            print(f"[+] Web service detected - enabling web scanning")
            self.results["has_web"] = True
        else:
            print(f"[-] No web service detected")
            self.results["has_web"] = False
        
        if has_database(nmap_result.metadata):
            print(f"[+] Database service detected")
            self.results["has_db"] = True
        else:
            self.results["has_db"] = False
        
        return nmap_result.metadata
    
    def run_web_scanning(self) -> dict:
        if not self.results.get("has_web"):
            return {}
        
        print(f"[+] Running OWASP ZAP scan")
        zap_result = ZapTool(self.target_url, config.ZAP_TIMEOUT).run()
        self.results["zap"] = zap_result
        self._store_findings(zap_result.findings)
        
        print(f"[+] Running Nikto scan")
        nikto_result = NiktoTool(self.target_url, config.NIKTO_TIMEOUT).run()
        self.results["nikto"] = nikto_result
        self._store_findings(nikto_result.findings)
        
        return {"zap": zap_result.metadata, "nikto": nikto_result.metadata}
    
    def run_directory_discovery(self) -> dict:
        if not self.results.get("has_web"):
            return {}
        
        print(f"[+] Running directory discovery")
        
        gobuster_result = GobusterTool(self.target_url, config.GOBUSTER_TIMEOUT).run()
        self.results["gobuster"] = gobuster_result
        self._store_findings(gobuster_result.findings)
        
        return {"gobuster": gobuster_result.metadata}
    
    def run_fuzzing(self) -> dict:
        if not self.results.get("has_web"):
            return {}
        
        print(f"[+] Running fuzzing")
        
        ffuf_result = FfufTool(self.target_url, config.FFUF_TIMEOUT).run()
        self.results["ffuf"] = ffuf_result
        self._store_findings(ffuf_result.findings)
        
        return {"ffuf": ffuf_result.metadata}
    
    def run_subdomain_enumeration(self) -> dict:
        print(f"[+] Running subdomain enumeration")
        
        subfinder_result = SubfinderTool(self.target_url, config.SUBFINDER_TIMEOUT).run()
        self.results["subfinder"] = subfinder_result
        self._store_findings(subfinder_result.findings)
        
        return {"subfinder": subfinder_result.metadata}
    
    def run_exploitation_testing(self) -> dict:
        if not self.results.get("has_web"):
            return {}
        
        print(f"[+] Running SQL injection testing")
        
        sqlmap_result = SqlmapTool(self.target_url, config.SQLMAP_TIMEOUT).run()
        self.results["sqlmap"] = sqlmap_result
        self._store_findings(sqlmap_result.findings)
        
        return {"sqlmap": sqlmap_result.metadata}
    
    def _store_findings(self, findings: list):
        for finding in findings:
            self.memory.add_finding(finding)
    
    def run_full_scan(self) -> dict:
        if not self.authorize_target():
            return {"error": "Target not authorized"}
        
        metadata = ScanMetadata(
            scan_id=self.scan_id,
            target_url=self.target_url,
            start_time=self.start_time,
            status="running"
        )
        self.memory.save_metadata(metadata)
        
        print(f"[*] Starting scan {self.scan_id} on {self.target_url}")
        
        self.run_reconnaissance()
        
        if self.results.get("has_web"):
            self.run_web_scanning()
            self.run_directory_discovery()
        
        self.run_subdomain_enumeration()
        
        if self.results.get("has_web"):
            self.run_exploitation_testing()
        
        print(f"[+] Running AI analysis")
        all_findings = self.memory.get_findings()
        ai_analysis = self.ai_analyzer.analyze_findings(all_findings, self.target_url)
        
        suppressed = ai_analysis.get("suppressed_findings", [])
        if suppressed:
            print(f"[+] AI identified {len(suppressed)} potential false positives")
        
        end_time = datetime.utcnow().isoformat()
        metadata.status = "completed"
        metadata.end_time = end_time
        metadata.tools_executed = list(self.results.keys())
        metadata.total_findings = len(all_findings) - len(suppressed)
        self.memory.save_metadata(metadata)
        
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": "completed",
            "findings_count": metadata.total_findings,
            "ai_analysis": ai_analysis,
            "risk_score": self.memory.calculate_risk_score(),
            "metadata": metadata
        }
    
    def run_targeted_scan(self, scan_type: str) -> dict:
        if not self.authorize_target():
            return {"error": "Target not authorized"}
        
        scan_methods = {
            "recon": self.run_reconnaissance,
            "web": self.run_web_scanning,
            "directories": self.run_directory_discovery,
            "fuzzing": self.run_fuzzing,
            "subdomains": self.run_subdomain_enumeration,
            "exploitation": self.run_exploitation_testing,
            "full": self.run_full_scan
        }
        
        method = scan_methods.get(scan_type, self.run_full_scan)
        return method()


def create_orchestrator(target_url: str, scan_id: str = None) -> ScanOrchestrator:
    return ScanOrchestrator(target_url, scan_id)
