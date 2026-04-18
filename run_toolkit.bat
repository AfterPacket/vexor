@echo off
REM Always run from the directory this .bat file lives in
cd /d "%~dp0"

echo ================================================
echo  Vexor v2.0
echo  Offensive LLM Security Testing Platform
echo  OWASP GenAI Top 10
echo ================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Install Python 3.10+ and add to PATH.
    pause & exit /b 1
)

REM Create venv if missing
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 ( echo [!] venv creation failed & pause & exit /b 1 )
)

REM Activate venv
call venv\Scripts\activate.bat

REM Install / upgrade dependencies
echo [*] Checking dependencies...
pip install -q -r requirements.txt

REM Check Ollama (informational)
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo [-] Ollama not detected on localhost:11434 (local models unavailable)
) else (
    echo [+] Ollama running - local models available
)

echo.
echo [*] Starting server on http://localhost:8080
echo     Swagger UI : http://localhost:8080/docs
echo     Web UI     : http://localhost:8080/
echo.

REM Open browser after a short delay
start "" /b timeout /t 2 /nobreak >nul & start http://localhost:8080/

REM Use --no-reload when running long scans so file changes don't kill the server.
REM Default: reload enabled (dev mode). Pass --no-reload as first argument to disable.
if "%~1"=="--no-reload" (
    echo [*] Running in stable mode (auto-reload disabled)
    uvicorn main:app --host 127.0.0.1 --port 8080
) else (
    echo [*] Running in dev mode (auto-reload enabled - don't edit files during scans)
    uvicorn main:app --reload --host 127.0.0.1 --port 8080
)

pause
