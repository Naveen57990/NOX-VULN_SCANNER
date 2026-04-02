"""Ffuf fuzzing tool."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil
import json
import time
from urllib.parse import urlparse
from tools.base import BaseTool, ToolResult

class FfufTool(BaseTool):
    def run(self) -> ToolResult:
        if not shutil.which("ffuf"):
            return ToolResult(
                success=True,
                tool_name="FFUF",
                raw_output="Ffuf not installed - skipping",
                findings=[],
                metadata={"status": "skipped", "reason": "not installed"}
            )
        
        start_time = time.time()
        findings = []
        metadata = {"fuzzed_urls": [], "interesting_findings": []}
        
        parsed = urlparse(self.target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        wordlist = "/tmp/fuzz_wordlist.txt"
        
        command = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-t", "10",
            "-mc", "200,204,301,302,307,401,403,500",
            "-json"
        ]
        
        stdout, stderr, returncode = self.execute(command)
        
        try:
            for line in stdout.split("\n"):
                if line.strip().startswith("{"):
                    result = json.loads(line)
                    if result.get("result"):
                        url = result.get("url", "")
                        status = result.get("status", 0)
                        metadata["fuzzed_urls"].append({"url": url, "status": status})
                        
                        if status == 403:
                            findings.append(self.create_finding(
                                name="Access Forbidden",
                                description=f"Endpoint returned 403 Forbidden",
                                severity="MEDIUM",
                                url=url,
                                evidence=f"Status: {status}"
                            ))
                        elif status == 401:
                            findings.append(self.create_finding(
                                name="Authentication Required",
                                description="Endpoint requires authentication",
                                severity="LOW",
                                url=url,
                                evidence=f"Status: {status}"
                            ))
        except:
            pass
        
        metadata["total_requests"] = len(metadata["fuzzed_urls"])
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

def get_fuzzing_results(metadata: dict) -> list:
    return metadata.get("fuzzed_urls", [])
