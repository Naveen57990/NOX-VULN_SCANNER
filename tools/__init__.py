"""Tools module for security scanning."""

from tools.base import BaseTool, ToolResult
from tools.nmap import NmapTool, has_web_service, has_database, get_open_ports
from tools.zap import ZapTool, parse_zap_report
from tools.sqlmap import SqlmapTool, get_vulnerable_endpoints
from tools.nikto import NiktoTool, parse_nikto_output
from tools.gobuster import GobusterTool, get_discovered_paths
from tools.ffuf import FfufTool, get_fuzzing_results
from tools.subfinder import SubfinderTool, get_subdomains

__all__ = [
    "BaseTool", "ToolResult",
    "NmapTool", "has_web_service", "has_database", "get_open_ports",
    "ZapTool", "parse_zap_report",
    "SqlmapTool", "get_vulnerable_endpoints",
    "NiktoTool", "parse_nikto_output",
    "GobusterTool", "get_discovered_paths",
    "FfufTool", "get_fuzzing_results",
    "SubfinderTool", "get_subdomains"
]
