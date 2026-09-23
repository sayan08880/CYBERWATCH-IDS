#!/usr/bin/env bash
# ============================================
#  Network IDS - one-click setup and run (Linux/macOS)
#  Run with sudo for packet capture + firewall blocking:
#     sudo ./run.sh
# ============================================
cd "$(dirname "$0")"

if [ ! -d venv ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate

echo "[*] Installing/updating dependencies..."
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Starting Network IDS on http://localhost:5000"
echo "[*] Default login: admin / password123"
python app.py
