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
REM   (default)       dev mode  - auto-reload on file change, no auto-restart
REM   --no-reload     stable    - no auto-reload, best for long scans
REM   --restart       resilient - relaunch automatically if the server CRASHES
REM   Flags may be given in any order.  --no-restart is accepted for
REM   backwards compatibility and is now the default.

REM Auto-restart is opt-in: a restart loop cannot fix a hung server, it only
REM scrolls the real error off screen and makes Ctrl+C respawn the process.
set RELOAD_FLAG=--reload
set AUTO_RESTART=0

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--no-reload"  set RELOAD_FLAG=
if /i "%~1"=="--restart"    set AUTO_RESTART=1
if /i "%~1"=="--no-restart" set AUTO_RESTART=0
shift
goto parse_args
:args_done

set UVICORN_CMD=uvicorn main:app %RELOAD_FLAG% --host 127.0.0.1 --port 8080

if defined RELOAD_FLAG (
    echo [*] Running in dev mode ^(auto-reload on file change - use --no-reload for long scans^)
) else (
    echo [*] Running in stable mode ^(auto-reload disabled^)
)
if "%AUTO_RESTART%"=="1" (
    echo [*] Auto-restart enabled - will relaunch on crash ^(max 5 times^)
) else (
    echo [*] Auto-restart disabled - single run ^(use --restart to enable^)
)
echo.

REM ── Server loop ───────────────────────────────────────────────────────────────
set RESTARTS=0

:server_loop
%UVICORN_CMD%
set EXIT_CODE=%ERRORLEVEL%

REM Exit code 0 means a clean shutdown (Ctrl+C, SIGTERM).  Never relaunch
REM after one -- that is what made Ctrl+C respawn the server forever.
if "%EXIT_CODE%"=="0"    goto done
if "%AUTO_RESTART%"=="0" goto done

set /a RESTARTS+=1
if %RESTARTS% GEQ 5 goto give_up

echo.
echo [!] Server crashed ^(exit code %EXIT_CODE%^). Restart %RESTARTS% of 5 in 3 seconds...
echo     ^(Press Ctrl+C now to stop^)
echo.
timeout /t 3 /nobreak >nul
goto server_loop

:give_up
echo.
echo [!] Server crashed 5 times in a row - giving up so the error stays visible.
echo     Scroll up for the traceback, or rerun with --no-reload for long scans.
goto done

:done
echo.
if "%EXIT_CODE%"=="0" (
    echo [*] Vexor stopped cleanly.
) else (
    echo [*] Vexor stopped ^(exit code %EXIT_CODE%^).
)
pause
