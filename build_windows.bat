@echo off
REM ==========================================================================
REM  Build Minecraft-JAR-Analyzer.exe on Windows.
REM
REM  Requirements on the BUILD machine only: 64-bit Python 3.11+ from
REM  python.org (with the "py" launcher). The finished .exe needs nothing.
REM
REM  Usage: double-click this file, or run  build_windows.bat  in a terminal
REM  from the project folder.
REM ==========================================================================
setlocal
cd /d "%~dp0"

echo.
echo [1/5] Locating Python...
where py >nul 2>nul
if %errorlevel%==0 (
    set "PYLAUNCH=py -3"
) else (
    where python >nul 2>nul || (
        echo ERROR: Python was not found. Install 64-bit Python 3.11+ from https://www.python.org/
        goto :fail
    )
    set "PYLAUNCH=python"
)
%PYLAUNCH% -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11+ required'; print('Using Python', sys.version.split()[0])" || goto :fail

echo.
echo [2/5] Creating/using virtual environment in .venv ...
if not exist ".venv\Scripts\python.exe" (
    %PYLAUNCH% -m venv .venv || goto :fail
)
set "VPY=.venv\Scripts\python.exe"

echo.
echo [3/5] Installing dependencies...
"%VPY%" -m pip install --upgrade pip || goto :fail
"%VPY%" -m pip install -r requirements-dev.txt || goto :fail

echo.
echo [4/5] Running automated tests (the build stops if any test fails)...
"%VPY%" -m pytest -q || (
    echo ERROR: Tests failed. The executable was NOT built.
    goto :fail
)

echo.
echo [5/5] Building the executable with PyInstaller...
"%VPY%" -m PyInstaller --noconfirm --clean --distpath dist --workpath build\pyinstaller packaging\Minecraft-JAR-Analyzer.spec || goto :fail

if not exist "dist\Minecraft-JAR-Analyzer.exe" (
    echo ERROR: dist\Minecraft-JAR-Analyzer.exe was not created.
    goto :fail
)

echo.
echo ==========================================================================
echo  SUCCESS: dist\Minecraft-JAR-Analyzer.exe
echo  SHA-256 of the build (record this for your release notes):
certutil -hashfile "dist\Minecraft-JAR-Analyzer.exe" SHA256 | findstr /v "hash CertUtil"
echo ==========================================================================
echo  Before distributing, test it on Windows using the checklist in README.md.
echo.
endlocal
pause
exit /b 0

:fail
echo.
echo BUILD FAILED.
endlocal
pause
exit /b 1
