#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import sys

# Add backend to path so internal imports work
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
sys.path.append(backend_path)

from scanner import scan_code
from github_scanner import RepositoryScanner
from pdf_report import PDFGenerator

# Colors for CLI
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

async def scan_local_path(path):
    """Scan a local directory or file."""
    scanner = RepositoryScanner() # Reuse logic for walking/scanning
    
    if os.path.isfile(path):
        _, ext = os.path.splitext(path)
        with open(path, 'r') as f:
            code = f.read()
        lang = "python" if ext == ".py" else "javascript"
        result = await scan_code(code, lang)
        result["filename"] = os.path.basename(path)
        return scanner.aggregate_results([result])
    
    # It's a directory
    all_results = []
    for root, _, files in os.walk(path):
        if any(x in root for x in [".git", "node_modules", "venv", "__pycache__"]):
            continue
        for file in files:
            _, ext = os.path.splitext(file)
            if ext in [".py", ".js", ".ts"]:
                fpath = os.path.join(root, file)
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                lang = "python" if ext == ".py" else "javascript"
                res = await scan_code(code, lang)
                res["filename"] = os.path.relpath(fpath, path)
                all_results.append(res)
    
    return scanner.aggregate_results(all_results)

async def main():
    parser = argparse.ArgumentParser(description="OpenMythos CLI - AI Powered Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    scan_parser = subparsers.add_parser("scan", help="Scan code for vulnerabilities")
    scan_parser.add_argument("target", help="Path to local directory/file or GitHub URL")
    scan_parser.add_argument("--output", help="Output PDF report filename")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        print(f"{Colors.BOLD}{Colors.BLUE}OpenMythos{Colors.ENDC} - Scanning {args.target}...")
        
        try:
            if args.target.startswith("http"):
                scanner = RepositoryScanner()
                results = await scanner.scan_repo(args.target)
            else:
                results = await scan_local_path(args.target)
                
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                # Print summary to console
                print(f"\n{Colors.BOLD}--- Scan Summary ---{Colors.ENDC}")
                print(f"Risk Score: {results['risk_score']}/100 ({results['risk_level'].upper()})")
                print(f"Total Findings: {len(results['vulnerabilities'])}")
                
                print(f"\n{Colors.BOLD}Top 5 Findings:{Colors.ENDC}")
                for f in results.get('top_findings', []):
                    color = Colors.RED if f['severity'] == "critical" else Colors.YELLOW
                    print(f"- {color}{f['severity'].upper()}{Colors.ENDC}: {f['type']} in {f.get('filename')}:{f.get('line')}")

            if args.output:
                pdf_gen = PDFGenerator()
                pdf_content = pdf_gen.generate(results)
                with open(args.output, "wb") as f:
                    f.write(pdf_content)
                print(f"\n{Colors.GREEN}Report saved to {args.output}{Colors.ENDC}")
                
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.ENDC}")
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
