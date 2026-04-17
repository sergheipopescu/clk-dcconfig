@echo off

REM Resolve the directory where this BAT file lives
set SCRIPT_DIR=%~dp0

REM Find the newest dcconfig script (with or without version)
for /f "delims=" %%F in ('dir /b /o:-d "%SCRIPT_DIR%dcconfig*.ps1" 2^>nul') do (
    set PS_SCRIPT=%%F
    goto :found
)
echo Error: Could not find dcconfig*.ps1 in %SCRIPT_DIR%
exit /b 1

:found
REM Relaunch as admin if not already elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -NoProfile -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

REM We are now running elevated
echo Running PowerShell script as Administrator...
echo Executing: %PS_SCRIPT%
echo.

powershell.exe ^
    -NoProfile ^
    -ExecutionPolicy Bypass ^
    -File "%SCRIPT_DIR%%PS_SCRIPT%"

echo.
echo Script execution finished.
pause