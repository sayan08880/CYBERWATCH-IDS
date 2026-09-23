@echo off
REM ============================================
REM  Network IDS - one-click setup and run (Windows)
REM  Right-click -> "Run as administrator" for
REM  packet capture and firewall blocking.
REM ============================================
cd /d "%~dp0"

if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [*] Installing/updating dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

echo [*] Starting Network IDS on http://localhost:5000
echo [*] Default login: admin / password123
python app.py

pause
