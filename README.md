---

⚠️ **Legal Notice**

This project is intended exclusively for educational, laboratory, and CTF (Capture The Flag) purposes. Using this software to scan networks or systems without explicit authorization is strictly prohibited and may be illegal.

The author is not responsible for any misuse of this tool. Use it only in controlled environments, on systems you own, or with explicit permission from the system owner.

---

![Screenshot_2025-06-28_02-02-24](https://github.com/user-attachments/assets/347cc686-483c-4987-bed0-1214201417e4)

---

# Network Analyzer


A tool to analyze network configurations and provide insights.
![image](https://github.com/user-attachments/assets/5759e0e0-e62b-4504-81cb-dfb5f1cf8c9e)


## Project Structure

- `main.py` — Entry point. Runs the analyzer.
- `src/network_analyzer.py` — Main logic for scanning and analysis.
- `src/vuln_lookup.py` — Looks up vulnerabilities for detected services.
- `resources/` — Contains ASCII art and other static resources.

## Features

- Nmap-based network scanning (custom arguments supported)
- AI-powered security analysis (Google Gemini)
- Dynamic, detailed, and colored scan result tables
- Automatic vulnerability lookup for detected services (via Vulners API)
- Graceful error and interruption handling

## How to Run

1. (Recommended) Create and activate a virtual environment:
   ```zsh
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```zsh
   pip install -r requirements.txt
   ```

3. Ensure you have nmap installed on your system:
   ```zsh
   sudo apt-get install nmap  # Debian/Ubuntu
   # or
   sudo dnf install nmap      # Fedora
   # or
   sudo pacman -S nmap        # Arch
   ```

4. Add your Gemini API key to a `.env` file in the project root:
   - Go to https://aistudio.google.com/app/apikey and log in with your Google account.
   - Click "Create API key" and follow the instructions.
   - Copy your API key and add it to a `.env` file as shown below:
   ```
   GEMINI_API_KEY=your_api_key_here
   ```

5. Run the tool:
   ```zsh
   python main.py
   ```