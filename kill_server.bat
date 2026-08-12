@echo off
cd /d "%~dp0"
echo [*] Stopping Vexor server...

REM Kill any python process listening on port 8080
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8080 "') do (
    if not "%%a"=="0" (
        echo [*] Killing PID %%a
        taskkill /F /PID %%a >nul 2>&1
    )
)

REM Also kill any lingering uvicorn/python processes from this directory
for /f "tokens=2" %%a in ('tasklist /FI "IMAGENAME eq python.exe" /FO CSV /NH 2^>nul') do (
    set pid=%%~a
)

echo [+] Server stopped. Port 8080 is free.
echo [*] Close the run_toolkit.bat window to prevent auto-restart.
echo.
pause
