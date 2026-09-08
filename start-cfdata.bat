@echo off
setlocal

set "PROJECT_DIR=%~dp0"
set "APP_DIR=%PROJECT_DIR%combined_refactor"

if not exist "%APP_DIR%\go.mod" (
    echo [ERROR] combined_refactor\go.mod was not found.
    pause
    exit /b 1
)

where powershell >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PowerShell was not found in PATH.
    pause
    exit /b 1
)

where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go was not found in PATH.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PROJECT_DIR%watch-cfdata.ps1" -AppDir "%APP_DIR%" -ExtraArgs "%*"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo CFData-WEB exited with code %EXIT_CODE%.
    pause
)

endlocal & exit /b %EXIT_CODE%
