"""Base tool interface for all security tools."""

from abc import ABC, abstractmethod
from typing import Optional
from dataclasses import dataclass
import subprocess
import json
from ..memory import Finding

@dataclass
class ToolResult:
    success: bool
    tool_name: str
    raw_output: str
    findings: list[Finding]
    metadata: dict
    error: Optional[str] = None
    duration: float = 0

class BaseTool(ABC):
    def __init__(self, target: str, timeout: int = 300):
        self.target = target
        self.timeout = timeout
        self.tool_name = self.__class__.__name__.replace("Tool", "").upper()
    
    @abstractmethod
    def run(self) -> ToolResult:
        pass
    
    def execute(self, command: list[str], check: bool = False) -> tuple[str, str, int]:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {self.timeout} seconds", -1
        except Exception as e:
            return "", str(e), -1
    
    def parse_json_output(self, output: str) -> dict:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {"raw": output}
    
    def create_finding(
        self,
        name: str,
        description: str,
        severity: str,
        url: str = "",
        parameter: str = "",
        evidence: str = "",
        remediation: str = "",
        cve: str = "",
        cvss: float = 0.0
    ) -> Finding:
        return Finding(
            id=f"{self.tool_name.lower()}_{name.lower().replace(' ', '_')}",
            tool=self.tool_name,
            name=name,
            description=description,
            severity=severity,
            url=url or self.target,
            parameter=parameter,
            evidence=evidence,
            remediation=remediation,
            cve=cve,
            cvss=cvss
        )
