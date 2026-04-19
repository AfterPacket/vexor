@echo off
REM Always run from the directory this .bat file lives in
cd /d "%~dp0"

echo ================================================
echo  Vexor v2.3
echo  Offensive LLM Security Testing Platform
echo  OWASP GenAI Top 10
echo ================================================
echo.

REM ── Python check ─────────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found. Install Python 3.10+ and add to PATH.
    pause ^& exit /b 1
)

REM ── Create venv if missing ────────────────────────────────────────────────────
if not exist "venv" (
    echo [*] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 ( echo [!] venv creation failed ^& pause ^& exit /b 1 )
)

REM ── Activate venv ────────────────────────────────────────────────────────────
call venv\Scripts\activate.bat

REM ── Install / upgrade dependencies only when requirements.txt changes ─────────
echo [*] Checking dependencies...
set REQ_HASH_FILE=venv\.req_hash
for /f "delims=" %%H in (\'certutil -hashfile requirements.txt MD5 ^| findstr /v ":" \') do set CUR_HASH=%%H
set NEED_INSTALL=1
if exist "%REQ_HASH_FILE%" (
    set /p OLD_HASH=<"%REQ_HASH_FILE%"
    if "%CUR_HASH%"=="%OLD_HASH%" set NEED_INSTALL=0
)
if "%NEED_INSTALL%"=="1" (
    echo [*] Installing/updating dependencies...
    pip install -q -r requirements.txt
    echo %CUR_HASH%>"%REQ_HASH_FILE%"
) else (
    echo [+] Dependencies up to date - skipping install
)

REM ── Ensure persistence directories exist ─────────────────────────────────────
if not exist "data" mkdir data
if not exist "data\scans" mkdir data\scans
if not exist "exploits" mkdir exploits
echo [+] Persistence directories ready

REM ── Check Ollama (informational) ─────────────────────────────────────────────
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo [-] Ollama not detected on localhost:11434 ^(local models unavailable^)
) else (
    echo [+] Ollama running - local models available
)

echo.
echo [*] Starting server on http://localhost:8080
echo     Swagger UI : http://localhost:8080/docs
echo     Web UI     : http://localhost:8080/
echo.

REM ── Open browser once server is ready (polls /health up to 60s) ──────────────
start "" powershell -NoProfile -Command "for($i=0;$i-lt60;$i++){try{$r=Invoke-WebRequest -Uri 'http://localhost:8080/health' -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop;if($r.StatusCode-eq 200){Start-Process 'http://localhost:8080/';break}}catch{};Start-Sleep 1}"

REM ── Launch options ────────────────────────────────────────────────────────────
REM   (default)       dev mode  - auto-reload on file change
REM   --no-reload     stable    - no auto-reload, best for long scans
REM   --no-restart    single    - do not auto-restart on crash
REM   --no-reload --no-restart  - stable single-run

set UVICORN_CMD=uvicorn main:app --host 127.0.0.1 --port 8080
if "%~1"=="--no-reload" set UVICORN_CMD=uvicorn main:app --host 127.0.0.1 --port 8080
if NOT "%~1"=="--no-reload" set UVICORN_CMD=uvicorn main:app --reload --host 127.0.0.1 --port 8080

REM Check for --no-restart flag (either arg position)
set AUTO_RESTART=1
if "%~1"=="--no-restart" set AUTO_RESTART=0
if "%~2"=="--no-restart" set AUTO_RESTART=0

if "%~1"=="--no-reload" (
    echo [*] Running in stable mode ^(auto-reload disabled^)
) else (
    echo [*] Running in dev mode ^(auto-reload on file change - use --no-reload for long scans^)
)
if "%AUTO_RESTART%"=="1" (
    echo [*] Auto-restart enabled ^(use --no-restart to disable^)
) else (
    echo [*] Auto-restart disabled - single run
)
echo.

REM ── Server loop ───────────────────────────────────────────────────────────────
:server_loop
%UVICORN_CMD%

if "%AUTO_RESTART%"=="0" goto done

echo.
echo [!] Server stopped or crashed. Restarting in 3 seconds...
echo     ^(Close this window or press Ctrl+C to exit^)
echo.
timeout /t 3 /nobreak >nul
goto server_loop

:done
echo.
echo [*] Vexor stopped.
pause
