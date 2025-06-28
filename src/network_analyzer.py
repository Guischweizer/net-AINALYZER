#!/usr/bin/env python3

import nmap
import google.generativeai as genai
import os
from dotenv import load_dotenv
import json
from typing import Dict, Any
from tabulate import tabulate
from termcolor import colored
import requests
from .vuln_lookup import lookup_vulnerabilities

# Load environment variables
load_dotenv()

def print_ascii_art():
    # Adjusted to look for resources/ at project root, not inside src/
    art_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'resources', 'ascii_art.txt')
    try:
        with open(art_path, 'r') as f:
            art = f.read()
        print(art)
    except Exception as e:
        print("[!] Could not load ASCII art:", e)

class NetworkAnalyzer:
    def __init__(self):
        # Initialize Gemini API
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        model_name = os.getenv('GEMINI_MODEL', 'gemini-1.5-flash')
        self.model = genai.GenerativeModel(model_name)
        self.nm = nmap.PortScanner()

    def scan_network(self, target: str, arguments: str = '-sV -sS -T4') -> Dict[str, Any]:
        """
        Perform a network scan using nmap with improved accuracy, safety, and error handling.
        Args:
            target: IP address or hostname to scan
            arguments: nmap arguments to use (validated)
        Returns:
            Dict containing scan results or error info
        """
        import shlex
        safe_args = arguments.strip()
        forbidden = [';', '|', '&', '`', '$', '>', '<']
        if not target:
            print("[!] Error: Target cannot be empty.")
            return {"error": "Target cannot be empty."}
        if any(char in safe_args for char in forbidden):
            print("[!] Error: Unsafe characters detected in nmap arguments.")
            return {"error": "Unsafe nmap arguments."}
        try:
            print(f"Starting scan of {target} with arguments: {safe_args} ...")
            self.nm.scan(hosts=target, arguments=safe_args)
            if not self.nm.all_hosts():
                print("[!] No hosts found. The scan may have failed or the target is unreachable.")
                return {"error": "No hosts found. Scan may have failed or target is unreachable."}
            return self.nm.analyse_nmap_xml_scan()
        except nmap.PortScannerError as nmap_err:
            print(f"[!] Nmap error: {nmap_err}")
            return {"error": f"Nmap error: {nmap_err}"}
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user (Ctrl+C). Exiting gracefully.")
            return {"error": "Scan interrupted by user."}
        except Exception as e:
            print(f"[!] Unexpected error during scan: {e}")
            return {"error": f"Unexpected error: {e}"}

    def format_nmap_table(self, scan_results: Dict[str, Any], max_rows: int = 30) -> str:
        """
        Format nmap scan results as a colored table. Dynamically adapts to the scan content and limits output size.
        Shows detailed info: port, state, service, reason, version, product, extra info, OS, CPE, etc.
        Args:
            scan_results: The dictionary with nmap results.
            max_rows: Maximum number of rows to display in the table.
        Returns:
            str: Formatted table as a string.
        """
        if not scan_results or 'error' in scan_results:
            return f"[!] Error: {scan_results.get('error', 'Unknown error.') if scan_results else 'No scan results.'}"
        table = []
        headers = ["Host", "Port", "State", "Service", "Reason", "Version", "Product", "Extra Info", "Vulnerabilities"]
        row_count = 0
        for host, host_data in scan_results.get('scan', {}).items():
            tcp_ports = host_data.get('tcp', {})
            for port, port_data in tcp_ports.items():
                state = port_data.get('state', '-')
                service = port_data.get('name', '-')
                reason = port_data.get('reason', '-')
                version = port_data.get('version', '-')
                product = port_data.get('product', '-')
                extrainfo = port_data.get('extrainfo', '-')
                # Colorize state
                if state == 'open':
                    state_colored = colored(state, 'green')
                elif state == 'closed':
                    state_colored = colored(state, 'red')
                else:
                    state_colored = colored(state, 'yellow')
                # Vulnerability lookup
                vulns = lookup_vulnerabilities(product, version)
                vulns_str = "\n".join(vulns) if vulns else "-"
                table.append([
                    host,
                    f"{port}/tcp",
                    state_colored,
                    service,
                    reason,
                    version,
                    product,
                    extrainfo,
                    vulns_str
                ])
                row_count += 1
                if row_count >= max_rows:
                    break
            if row_count >= max_rows:
                break
        if not table:
            return "No open ports found."
        table_str = tabulate(table, headers, tablefmt="fancy_grid")
        # Service Info (OS, CPE, etc)
        service_info = []
        for host, host_data in scan_results.get('scan', {}).items():
            os_info = host_data.get('osmatch', [])
            if os_info:
                service_info.append(f"OS Guess: {os_info[0].get('name', '-')}")
            cpe = host_data.get('osclass', [{}])[0].get('cpe', '-') if host_data.get('osclass') else '-'
            if cpe != '-':
                service_info.append(f"CPE: {cpe}")
            # Sometimes service info is in hostscript
            if 'hostscript' in host_data:
                for script in host_data['hostscript']:
                    service_info.append(f"{script.get('id', '-')}: {script.get('output', '-')}")
        if service_info:
            table_str += "\nService Info: " + "; ".join(service_info)
        total_rows = sum(len(host_data.get('tcp', {})) for host_data in scan_results.get('scan', {}).values())
        if total_rows > max_rows:
            table_str += f"\n... Output truncated. Showing first {max_rows} of {total_rows} results. ..."
        return table_str

    def analyze_results(self, scan_results: Dict[str, Any]) -> str:
        """
        Analyze scan results using Gemini AI
        
        Args:
            scan_results: Dictionary containing nmap scan results
        
        Returns:
            str: AI analysis of the scan results
        """
        if not scan_results or 'error' in scan_results:
            return f"[!] Error: {scan_results.get('error', 'No scan results to analyze.')}"
        prompt = f"""
        Analyze the following network scan results and provide a detailed security assessment:
        - Identify potential vulnerabilities
        - List open ports and services
        - Suggest security improvements
        - Rate the overall security posture (1-10)

        Scan Results:
        {json.dumps(scan_results, indent=2)}
        """

        try:
            nmap_table = self.format_nmap_table(scan_results, max_rows=30)
            response = self.model.generate_content(prompt)
            return f"{nmap_table}\n\n{response.text}"
        except Exception as e:
            return f"Error analyzing results: {e}"

async def main():
    print_ascii_art()
    analyzer = NetworkAnalyzer()
    try:
        target = input("Enter target IP address or hostname to scan: ")
        arguments = input("Enter nmap arguments (default: -sV -sS -T4): ") or '-sV -sS -T4'
        scan_results = analyzer.scan_network(target, arguments)
        analysis = analyzer.analyze_results(scan_results)
        print("\n=== AI Analysis ===")
        print(analysis)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting.")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
