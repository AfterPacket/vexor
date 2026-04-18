#!/usr/bin/env bash
set -e

echo "================================================"
echo " Vexor v2.0"
echo " Offensive LLM Security Testing Platform"
echo " OWASP GenAI Top 10"
echo "================================================"
echo

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[!] Python 3 not found. Install Python 3.10+."
    exit 1
fi

# Create venv if missing
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "[*] Checking dependencies..."
pip install -q -r requirements.txt

# Check Ollama
if curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo "[+] Ollama running - local models available"
else
    echo "[-] Ollama not detected on localhost:11434 (local models unavailable)"
fi

echo
echo "[*] Starting server on http://localhost:8080"
echo "    Swagger UI : http://localhost:8080/docs"
echo "    Web UI     : http://localhost:8080/"
echo

uvicorn main:app --reload --host 127.0.0.1 --port 8080
