#!/usr/bin/env python3

import nmap
import google.generativeai as genai
import os
from dotenv import load_dotenv
import json
from typing import Dict, Any

# Load environment variables
load_dotenv()

class NetworkAnalyzer:
    def __init__(self):
        # Initialize Gemini API
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        self.model = genai.GenerativeModel('models/gemini-2.5-pro')
        self.nm = nmap.PortScanner()

    def scan_network(self, target: str, arguments: str = '-sV -sS -T4') -> Dict[str, Any]:
        """
        Perform a network scan using nmap
        
        Args:
            target: IP address or hostname to scan
            arguments: nmap arguments to use
        
        Returns:
            Dict containing scan results
        """
        try:
            print(f"Starting scan of {target}...")
            self.nm.scan(target, arguments=arguments)
            return self.nm.analyse_nmap_xml_scan()
        except Exception as e:
            print(f"Error during scan: {e}")
            return {}

    async def analyze_results(self, scan_results: Dict[str, Any]) -> str:
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
            response = await self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error analyzing results: {e}"

async def main():
    analyzer = NetworkAnalyzer()
    
    # Get target from user
    target = input("Enter target IP address or hostname to scan: ")
    
    # Perform scan
    scan_results = analyzer.scan_network(target)
    
    # Analyze results with Gemini
    analysis = await analyzer.analyze_results(scan_results)
    
    print("\n=== AI Analysis ===")
    print(analysis)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
