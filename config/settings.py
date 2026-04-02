"""Configuration settings for the vulnerability scanner."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

class Config:
    TARGET_URL: str = ""
    SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "3600"))
    NMAP_TIMEOUT: int = 300
    ZAP_TIMEOUT: int = 600
    SQLMAP_TIMEOUT: int = 900
    NIKTO_TIMEOUT: int = 600
    GOBUSTER_TIMEOUT: int = 300
    FFUF_TIMEOUT: int = 300
    SUBFINDER_TIMEOUT: int = 120
    
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    AI_MODEL: str = os.getenv("AI_MODEL", "claude-3-sonnet-20240229")
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "anthropic")
    
    AUTHORIZED_TARGETS: list = os.getenv("AUTHORIZED_TARGETS", "").split(",") if os.getenv("AUTHORIZED_TARGETS") else []
    HEADLESS_MODE: bool = True
    VERBOSE: bool = os.getenv("VERBOSE", "false").lower() == "true"
    
    ZAP_API_KEY: str = os.getenv("ZAP_API_KEY", "")
    ZAP_PORT: int = 8080
    
    WORDLISTS: dict = {
        "directories": "/usr/share/wordlists/dirb/common.txt",
        "subdomains": "/usr/share/wordlists/subdomains.txt",
        "fuzzing": "/usr/share/wordlists/fuzz.txt"
    }
    
    SEVERITY_LEVELS: list = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    RISK_SCORES: dict = {
        "CRITICAL": 10,
        "HIGH": 7.5,
        "MEDIUM": 5,
        "LOW": 2.5,
        "INFO": 0
    }

config = Config()
