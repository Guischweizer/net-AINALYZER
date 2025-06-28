---

⚠️ **Legal Notice**

This project is intended exclusively for educational, laboratory, and CTF (Capture The Flag) purposes. Using this software to scan networks or systems without explicit authorization is strictly prohibited and may be illegal.

The author is not responsible for any misuse of this tool. Use it only in controlled environments, on systems you own, or with explicit permission from the system owner.

---

# Network Analyzer

A tool to analyze network configurations and provide insights.
![preview-nmap-tunado](https://github.com/user-attachments/assets/d835df6a-bbba-4fe2-9011-835cb813ea05)


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
   ```
   GEMINI_API_KEY=your_api_key_here
   ```

5. Run the script:
   ```zsh
   python network_analyzer.py
   ```
