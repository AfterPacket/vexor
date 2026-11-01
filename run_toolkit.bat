@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

set "VEXOR_VERSION=2.7.3"
set "VENV_DIR=%CD%\venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "RELOAD_FLAG=--reload"
set "AUTO_RESTART=0"
set "NO_INSTALL=0"

REM Parse once, before any setup. Unknown arguments are intentionally ignored so
REM old shortcuts keep working; recognized flags are listed below.
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--no-reload" set "RELOAD_FLAG="
if /i "%~1"=="--restart" set "AUTO_RESTART=1"
if /i "%~1"=="--no-restart" set "AUTO_RESTART=0"
if /i "%~1"=="--no-install" set "NO_INSTALL=1"
shift
goto :parse_args
:args_done

echo ================================================
echo  Vexor v%VEXOR_VERSION%
echo  LLM Security Testing Platform
echo  Local Web UI and API
echo ================================================
echo.

REM Optional: set VEXOR_PYTHON to an absolute working Python 3.10+ path.
REM It must include standard-library enum, venv, and ensurepip modules.
call :find_python
if errorlevel 1 goto :python_error

"%PYTHON_EXE%" %PYTHON_ARGS% -c "import sys, enum, venv, ensurepip; assert sys.version_info >= (3,10); print('.'.join(map(str, sys.version_info[:3])))" > "%TEMP%\vexor_python_version.tmp" 2>nul
if errorlevel 1 goto :python_error
set /p PYTHON_VERSION=<"%TEMP%\vexor_python_version.tmp"
del /q "%TEMP%\vexor_python_version.tmp" >nul 2>&1

echo [+] Using Python %PYTHON_VERSION%
echo     %PYTHON_EXE% %PYTHON_ARGS%

REM Rebuild only a venv that cannot run its own interpreter. Never use a global
REM pip/uvicorn fallback: launcher stubs can target deleted Python installations.
if exist "%VENV_DIR%" if not exist "%VENV_PYTHON%" (
    echo [!] Existing venv is incomplete; removing it...
    rmdir /s /q "%VENV_DIR%"
)
if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" -c "import sys, enum, venv; assert sys.version_info >= (3,10)" >nul 2>&1
    if errorlevel 1 (
        echo [!] Existing venv uses a broken or unsupported interpreter; rebuilding it...
        rmdir /s /q "%VENV_DIR%"
    )
)
if not exist "%VENV_PYTHON%" (
    echo [*] Creating virtual environment...
    "%PYTHON_EXE%" %PYTHON_ARGS% -m venv "%VENV_DIR%"
    if errorlevel 1 goto :venv_error
)

"%VENV_PYTHON%" -m pip --version >nul 2>&1
if errorlevel 1 goto :pip_error

if "%NO_INSTALL%"=="0" (
    echo [*] Installing/updating dependencies in venv...
    "%VENV_PYTHON%" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto :install_error
) else (
    echo [*] Dependency installation skipped by --no-install
)

"%VENV_PYTHON%" -c "import fastapi, uvicorn" >nul 2>&1
if errorlevel 1 goto :dependency_error

if not exist "data" mkdir data
if not exist "data\scans" mkdir data\scans
if not exist "exploits" mkdir exploits
echo [+] Persistence directories ready

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

start "" powershell -NoProfile -Command "for($i=0;$i-lt60;$i++){try{$r=Invoke-WebRequest -Uri 'http://localhost:8080/health' -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop;if($r.StatusCode-eq 200){Start-Process 'http://localhost:8080/';break}}catch{};Start-Sleep 1}"

if defined RELOAD_FLAG (
    echo [*] Development mode: auto-reload enabled ^(use --no-reload for long scans^)
) else (
    echo [*] Stable mode: auto-reload disabled
)
if "%AUTO_RESTART%"=="1" (
    echo [*] Auto-restart enabled ^(maximum 5 crashes^)
) else (
    echo [*] Auto-restart disabled
)

set "RESTARTS=0"
:server_loop
"%VENV_PYTHON%" -m uvicorn main:app %RELOAD_FLAG% --host 127.0.0.1 --port 8080
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" goto :done
if not "%AUTO_RESTART%"=="1" goto :done
set /a RESTARTS+=1
if %RESTARTS% GEQ 5 goto :give_up
echo [!] Server exited with %EXIT_CODE%. Restart %RESTARTS% of 5 in 3 seconds...
timeout /t 3 /nobreak >nul
goto :server_loop

:done
echo.
echo [*] Vexor stopped (exit code %EXIT_CODE%).
pause
exit /b %EXIT_CODE%

:find_python
if defined VEXOR_PYTHON (
    if not exist "%VEXOR_PYTHON%" exit /b 1
    set "PYTHON_EXE=%VEXOR_PYTHON%"
    set "PYTHON_ARGS="
    exit /b 0
)
call :try_python py -3.13
if not errorlevel 1 exit /b 0
call :try_python py -3.12
if not errorlevel 1 exit /b 0
call :try_python py -3.11
if not errorlevel 1 exit /b 0
call :try_python py -3.10
if not errorlevel 1 exit /b 0
call :try_python python
if not errorlevel 1 exit /b 0
exit /b 1

:try_python
set "CANDIDATE_EXE=%~1"
set "CANDIDATE_ARGS=%~2"
"%CANDIDATE_EXE%" %CANDIDATE_ARGS% -c "import sys, enum, venv, ensurepip; assert sys.version_info >= (3,10)" >nul 2>&1
if errorlevel 1 exit /b 1
set "PYTHON_EXE=%CANDIDATE_EXE%"
set "PYTHON_ARGS=%CANDIDATE_ARGS%"
exit /b 0

:python_error
echo.
echo [!] No usable Python 3.10+ interpreter was found.
echo     The current Python cannot import standard-library enum, venv, or ensurepip.
echo     Repair or reinstall Python from https://www.python.org/downloads/.
echo     Or set a known-good interpreter for this Command Prompt, for example:
echo       set "VEXOR_PYTHON=C:\Path\To\python.exe"
echo       run_toolkit.bat
pause
exit /b 1

:venv_error
echo [!] Virtual environment creation failed. The server was not started.
pause
exit /b 1

:pip_error
echo [!] pip is unavailable inside the virtual environment. The server was not started.
pause
exit /b 1

:install_error
echo [!] Dependency installation failed. The server was not started.
pause
exit /b 1

:dependency_error
echo [!] FastAPI or Uvicorn is missing from the virtual environment. The server was not started.
echo     Re-run without --no-install after resolving installation errors.
pause
exit /b 1

:give_up
echo [!] Server crashed five times; stopping so the last error remains visible.
goto :done
