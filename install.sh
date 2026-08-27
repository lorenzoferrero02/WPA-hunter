#!/bin/bash

echo "========================================="
echo "  WPA Hunter - Installation Script"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Install system dependencies
echo "[*] Installing system dependencies..."
apt update
apt install -y aircrack-ng tcpdump hcxtools hashcat wireless-tools iw python3-pip

if [ $? -ne 0 ]; then
    echo "[✗] Failed to install system dependencies"
    exit 1
fi

# Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[✗] Failed to install Python dependencies"
    exit 1
fi

# Make script executable
chmod +x wpa-hunter.py

# Create output directory
mkdir -p captures

echo ""
echo "[✓] Installation complete!"
echo ""
echo "Usage: sudo ./wpa-hunter.py"
echo "       sudo ./wpa-hunter.py --help for options"