#!/usr/bin/env bash
# Local launcher. Uses only the venv interpreter after bootstrap.
set -euo pipefail
cd "$(dirname "$0")"

VEXOR_VERSION="2.7.3"
VENV_DIR="${VENV_DIR:-venv}"
NO_INSTALL=0
RELOAD=1
for arg in "$@"; do
  case "$arg" in
    --no-install) NO_INSTALL=1 ;;
    --no-reload) RELOAD=0 ;;
    --restart|--no-restart) echo "[!] $arg is only supported by run_toolkit.bat; ignored." ;;
  esac
done

echo "================================================"
echo " Vexor v${VEXOR_VERSION}"
echo " LLM Security Testing Platform"
echo " Local Web UI and API"
echo "================================================"
echo

PYTHON_EXE="${VEXOR_PYTHON:-python3}"
if ! command -v "$PYTHON_EXE" >/dev/null 2>&1 && [[ ! -x "$PYTHON_EXE" ]]; then
  echo "[!] Python was not found: $PYTHON_EXE"
  echo "    Install Python 3.10+ or set VEXOR_PYTHON to a working interpreter."
  exit 1
fi
if ! "$PYTHON_EXE" -c 'import sys, enum, venv, ensurepip; assert sys.version_info >= (3, 10)' >/dev/null 2>&1; then
  echo "[!] Python must be 3.10+ and provide enum, venv, and ensurepip."
  echo "    Repair/install Python or set VEXOR_PYTHON to a complete interpreter."
  exit 1
fi

VENV_PYTHON="$VENV_DIR/bin/python"
if [[ -d "$VENV_DIR" && ! -x "$VENV_PYTHON" ]]; then
  echo "[!] Existing venv is incomplete; rebuilding it..."
  rm -rf "$VENV_DIR"
fi
if [[ -x "$VENV_PYTHON" ]] && ! "$VENV_PYTHON" -c 'import enum, venv' >/dev/null 2>&1; then
  echo "[!] Existing venv uses a broken interpreter; rebuilding it..."
  rm -rf "$VENV_DIR"
fi
if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "[*] Creating virtual environment..."
  "$PYTHON_EXE" -m venv "$VENV_DIR"
fi

if ! "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
  echo "[!] pip is unavailable inside $VENV_DIR. Server was not started."
  exit 1
fi
if [[ "$NO_INSTALL" -eq 0 ]]; then
  echo "[*] Installing/updating dependencies in venv..."
  "$VENV_PYTHON" -m pip install --disable-pip-version-check -r requirements.txt
else
  echo "[*] Dependency installation skipped by --no-install"
fi
"$VENV_PYTHON" -c 'import fastapi, uvicorn'

mkdir -p data/scans exploits
if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "[+] Ollama running - local models available"
else
  echo "[-] Ollama not detected on localhost:11434 (local models unavailable)"
fi

echo
echo "[*] Starting server on http://localhost:8080"
echo "    Swagger UI : http://localhost:8080/docs"
echo "    Web UI     : http://localhost:8080/"

( for _ in $(seq 1 60); do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
      xdg-open http://localhost:8080 >/dev/null 2>&1 || open http://localhost:8080 >/dev/null 2>&1 || true
      break
    fi
    sleep 1
  done ) &

if [[ "$RELOAD" -eq 1 ]]; then
  echo "[*] Development mode: auto-reload enabled (use --no-reload for long scans)"
  exec "$VENV_PYTHON" -m uvicorn main:app --reload --host 127.0.0.1 --port 8080
else
  echo "[*] Stable mode: auto-reload disabled"
  exec "$VENV_PYTHON" -m uvicorn main:app --host 127.0.0.1 --port 8080
fi
