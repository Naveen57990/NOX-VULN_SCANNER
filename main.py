"""AI-Powered Vulnerability Scanner

A production-ready vulnerability scanning system that integrates multiple security tools
and uses AI to analyze and prioritize findings.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
from datetime import datetime
from pathlib import Path

from config import config
from orchestrator import create_orchestrator
from memory import GlobalMemory
from reports import generate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-Powered Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--url", "-u", required=True, help="Target URL to scan")
    parser.add_argument("--scan-id", "-s", help="Custom scan ID (default: auto-generated)")
    parser.add_argument("--scan-type", "-t", default="full",
                        choices=["full", "recon", "web", "directories", "fuzzing", "subdomains", "exploitation"],
                        help="Type of scan to perform (default: full)")
    parser.add_argument("--output", "-o", default="/app/output", help="Output directory")
    parser.add_argument("--format", "-f", default="markdown,json,html",
                        help="Report formats: markdown, json, html (comma-separated)")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    print("=" * 60)
    print("  AI-Powered Vulnerability Scanner")
    print("=" * 60)
    print(f"\n[*] Target: {args.url}")
    print(f"[*] Scan Type: {args.scan_type}")
    print(f"[*] Output: {args.output}")
    print()
    
    config.VERBOSE = args.verbose
    
    if not args.url.startswith(("http://", "https://")):
        args.url = "https://" + args.url
    
    orchestrator = create_orchestrator(args.url, args.scan_id)
    
    if not orchestrator.authorize_target():
        print("[-] Target not authorized. Please add target to AUTHORIZED_TARGETS.")
        sys.exit(1)
    
    print(f"[*] Scan ID: {orchestrator.scan_id}")
    print("[*] Starting scan...\n")
    
    start_time = datetime.now()
    
    try:
        if args.scan_type == "full":
            result = orchestrator.run_full_scan()
        else:
            result = orchestrator.run_targeted_scan(args.scan_type)
        
        if "error" in result:
            print(f"[-] Error: {result['error']}")
            sys.exit(1)
        
        print(f"\n[+] Scan completed successfully")
        print(f"[+] Status: {result.get('status', 'unknown')}")
        print(f"[+] Findings: {result.get('findings_count', 0)}")
        print(f"[+] Risk Score: {result.get('risk_score', 0):.1f}/10")
        
        memory = GlobalMemory.get(orchestrator.scan_id)
        if memory:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            formats = [f.strip() for f in args.format.split(",")]
            reports = generate_report(memory, output_dir, formats)
            
            print(f"\n[+] Reports generated:")
            for fmt, path in reports.items():
                print(f"    - {fmt.upper()}: {path}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        print(f"\n[*] Total scan time: {duration:.1f} seconds")
        
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[-] Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("  Scan Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
