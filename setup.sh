#!/bin/bash

# OMNI-SCAN v2.0 - Quick Start Script
# Run this in the omni_scan_complete directory

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           OMNI-SCAN v2.0 - Quick Start Setup              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check Python version
python3_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "[*] Python version: $python3_version"

if [[ ! "$python3_version" =~ ^3.10|^3.11|^3.12 ]]; then
    echo "[!] Warning: Python 3.10+ recommended"
fi

# Create virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv venv

# Activate venv
echo "[*] Activating virtual environment..."
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Check system dependencies
echo "[*] Checking system dependencies..."

if command -v nmap &> /dev/null; then
    echo "    ✓ nmap installed ($(nmap --version | head -1))"
else
    echo "    ! nmap not found (optional, for OS fingerprinting)"
    echo "      Ubuntu/Debian: sudo apt-get install nmap"
    echo "      macOS: brew install nmap"
fi

if command -v tcpdump &> /dev/null; then
    echo "    ✓ tcpdump installed"
else
    echo "    ! tcpdump not found (optional, for packet sniffing)"
fi

# Create database directory
echo "[*] Initializing database..."
touch omni_scan.db

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║            Setup Complete - Ready to Run!                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "To launch OMNI-SCAN:"
echo "  1. Activate venv (if not already):"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run Streamlit app:"
echo "     streamlit run app.py"
echo ""
echo "  3. Open browser:"
echo "     http://localhost:8501"
echo ""
echo "For more information, see README.md"
echo ""
