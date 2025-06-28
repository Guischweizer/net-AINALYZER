# Network Analyzer

A tool to analyze network configurations and provide insights.

## How to Run

1. (Recommended) Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure you have nmap installed on your system:
   ```bash
   sudo apt-get install nmap  # Debian/Ubuntu
   # or
   sudo dnf install nmap      # Fedora
   # or
   sudo pacman -S nmap        # Arch
   ```

4. Add your Gemini API key to a `.env` file in the project root:
   ```
   GEMINI_API_KEY=your_api_key_here
   ```

5. Run the script:
   ```bash
   python network_analyzer.py
   ```