"""Memory storage for scan results and findings."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, asdict
from ..config import config

@dataclass
class Finding:
    id: str
    tool: str
    name: str
    description: str
    severity: str
    url: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ScanMetadata:
    scan_id: str
    target_url: str
    start_time: str
    end_time: Optional[str] = None
    status: str = "running"
    tools_executed: list = None
    total_findings: int = 0
    
    def __post_init__(self):
        if self.tools_executed is None:
            self.tools_executed = []

class Memory:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.db_path = config.OUTPUT_DIR / f"{scan_id}.db"
        self.findings: list[Finding] = []
        self.metadata: Optional[ScanMetadata] = None
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                tool TEXT,
                name TEXT,
                description TEXT,
                severity TEXT,
                url TEXT,
                parameter TEXT,
                evidence TEXT,
                remediation TEXT,
                cve TEXT,
                cvss REAL,
                timestamp TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT,
                tools_executed TEXT,
                total_findings INTEGER
            )
        """)
        conn.commit()
        conn.close()
    
    def save_metadata(self, metadata: ScanMetadata):
        self.metadata = metadata
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO metadata 
            (scan_id, target_url, start_time, end_time, status, tools_executed, total_findings)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata.scan_id,
            metadata.target_url,
            metadata.start_time,
            metadata.end_time,
            metadata.status,
            json.dumps(metadata.tools_executed),
            metadata.total_findings
        ))
        conn.commit()
        conn.close()
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings 
            (id, tool, name, description, severity, url, parameter, evidence, remediation, cve, cvss, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.id, finding.tool, finding.name, finding.description,
            finding.severity, finding.url, finding.parameter, finding.evidence,
            finding.remediation, finding.cve, finding.cvss, finding.timestamp
        ))
        conn.commit()
        conn.close()
    
    def get_findings(self, severity: Optional[str] = None) -> list[Finding]:
        if severity:
            return [f for f in self.findings if f.severity == severity]
        return self.findings
    
    def get_findings_by_tool(self, tool: str) -> list[Finding]:
        return [f for f in self.findings if f.tool == tool]
    
    def get_summary(self) -> dict:
        summary = {
            "total": len(self.findings),
            "by_severity": {},
            "by_tool": {}
        }
        for finding in self.findings:
            summary["by_severity"][finding.severity] = summary["by_severity"].get(finding.severity, 0) + 1
            summary["by_tool"][finding.tool] = summary["by_tool"].get(finding.tool, 0) + 1
        return summary
    
    def calculate_risk_score(self) -> float:
        if not self.findings:
            return 0.0
        total_score = 0
        for finding in self.findings:
            total_score += config.RISK_SCORES.get(finding.severity, 0)
        return min(10, total_score / max(len(self.findings), 1) * 2)
    
    def export_json(self, path: Path):
        data = {
            "metadata": asdict(self.metadata) if self.metadata else None,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.get_summary(),
            "risk_score": self.calculate_risk_score()
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    
    def close(self):
        if self.db_path.exists():
            pass

class GlobalMemory:
    _instances: dict[str, Memory] = {}
    
    @classmethod
    def get_or_create(cls, scan_id: str) -> Memory:
        if scan_id not in cls._instances:
            cls._instances[scan_id] = Memory(scan_id)
        return cls._instances[scan_id]
    
    @classmethod
    def get(cls, scan_id: str) -> Optional[Memory]:
        return cls._instances.get(scan_id)
    
    @classmethod
    def cleanup(cls):
        cls._instances.clear()
