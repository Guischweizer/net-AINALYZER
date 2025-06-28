#!/usr/bin/env python3

import nmap
import google.generativeai as genai
import os
from dotenv import load_dotenv
import json
from typing import Dict, Any
from tabulate import tabulate
from termcolor import colored

# Load environment variables
load_dotenv()

def print_ascii_art():
    art_path = os.path.join(os.path.dirname(__file__), 'resources', 'ascii_art.txt')
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
        self.model = genai.GenerativeModel('gemini-1.5-flash')
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
        # Basic validation: disallow dangerous shell metacharacters
        forbidden = [';', '|', '&', '`', '$', '>', '<']
        if any(char in safe_args for char in forbidden):
            print("Error: Unsafe characters detected in nmap arguments.")
            return {"error": "Unsafe nmap arguments."}
        try:
            print(f"Starting scan of {target} with arguments: {safe_args} ...")
            self.nm.scan(hosts=target, arguments=safe_args)
            return self.nm.analyse_nmap_xml_scan()
        except KeyboardInterrupt:
            print("\nScan interrupted by user (Ctrl+C). Exiting gracefully.")
            return {"error": "Scan interrupted by user."}
        except Exception as e:
            print(f"Error during scan: {e}")
            return {"error": str(e)}

    def format_nmap_table(self, scan_results: Dict[str, Any]) -> str:
        """
        Format nmap scan results as a colored table.
        """
        table = []
        headers = ["Host", "Port", "State", "Service"]
        for host, host_data in scan_results.get('scan', {}).items():
            for proto in host_data.get('tcp', {}):
                port_data = host_data['tcp'][proto]
                port = proto
                state = port_data.get('state', '-')
                service = port_data.get('name', '-')
                # Colorize state
                if state == 'open':
                    state_colored = colored(state, 'green')
                elif state == 'closed':
                    state_colored = colored(state, 'red')
                else:
                    state_colored = colored(state, 'yellow')
                table.append([host, port, state_colored, service])
        if not table:
            return "No open ports found."
        return tabulate(table, headers, tablefmt="fancy_grid")

    def analyze_results(self, scan_results: Dict[str, Any]) -> str:
        """
        Analyze scan results using Gemini AI
        
        Args:
            scan_results: Dictionary containing nmap scan results
        
        Returns:
            str: AI analysis of the scan results
        """
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
            nmap_table = self.format_nmap_table(scan_results)
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
