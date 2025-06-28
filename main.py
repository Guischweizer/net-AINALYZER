from src.network_analyzer import NetworkAnalyzer, print_ascii_art
import asyncio

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
    asyncio.run(main())
