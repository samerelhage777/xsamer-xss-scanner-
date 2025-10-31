# xsamer-xss-scanner-

# xsamer-xss-scanner-



\# XSAMER - Advanced XSS Scanner 🔍



!\[XSAMER Banner](https://img.shields.io/badge/XSS-Scanner-red)

!\[Python](https://img.shields.io/badge/Python-3.6+-blue)

!\[License](https://img.shields.io/badge/License-MIT-green)



A powerful and customizable XSS vulnerability scanner written in Python. XSAMER helps security researchers and penetration testers identify Cross-Site Scripting vulnerabilities efficiently.



\## 🚀 Features



\- \*\*Multiple Payload Support\*\*: Load payloads from text files

\- \*\*Batch URL Scanning\*\*: Scan multiple URLs from a file

\- \*\*Smart Payload Combinations\*\*: Use predefined payload combinations

\- \*\*Verbose Mode\*\*: Real-time status code monitoring

\- \*\*Vulnerability-Focused Results\*\*: Save only vulnerable findings

\- \*\*Customizable Parameters\*\*: Test specific parameters and methods

\- \*\*Color-coded Output\*\*: Easy-to-read status indicators



\## 📦 Installation



\### Quick Install


cpoy and paste  all above  

```bash

git clone https://github.com/yourusername/xsamer-xss-scanner.git

cd xsamer-xss-scanner

chmod +x install.sh

./install.sh

chmod +x xsamer.py

python xsamer.py

 python xsamer.py

██╗  ██╗███████╗ █████╗ ███╗   ███╗███████╗██████╗
╚██╗██╔╝██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████║██╔████╔██║█████╗  ██████╔╝
 ██╔██╗ ╚════██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗
██╔╝ ██╗███████║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝

   --------------   Welcome to XSAMER  BY Samer EL HAGE -----------
👋 Welcome to XSS Scanner by Samer EL HAGE
==================================================
Usage: xsamer [OPTIONS]

Quick Start:
  xsamer -u https://example.com        # Scan single URL
  xsamer -l urls.txt                   # Scan URLs from file
  xsamer -u https://example.com -xss   # Use XSS Combo
  xsamer -u https://example.com -v     # Verbose mode (shows status codes)
  xsamer --show                        # Show all payloads

Use 'xsamer -h' for full help
