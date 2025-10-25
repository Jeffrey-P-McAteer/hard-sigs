@echo off
setlocal enabledelayedexpansion

echo Building hard-sigs for Windows...
echo.

REM Check for Visual Studio Build Tools or Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSTOOLS_FOUND=0"
set "VSINSTALLDIR="

REM Try vswhere first
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do (
        set "VSINSTALLDIR=%%i"
        set "VSTOOLS_FOUND=1"
    )
)

REM If vswhere didn't work, try common installation paths
if !VSTOOLS_FOUND! == 0 (
    for %%p in (
        "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise"
        "%ProgramFiles%\Microsoft Visual Studio\2022\Professional"
        "%ProgramFiles%\Microsoft Visual Studio\2022\Community"
        "%ProgramFiles%\Microsoft Visual Studio\2019\Enterprise"
        "%ProgramFiles%\Microsoft Visual Studio\2019\Professional"
        "%ProgramFiles%\Microsoft Visual Studio\2019\Community"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional"
        "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community"
    ) do (
        if exist "%%~p\VC\Auxiliary\Build\vcvarsall.bat" (
            set "VSINSTALLDIR=%%~p"
            set "VSTOOLS_FOUND=1"
            goto :found_vs
        )
    )
)
:found_vs

REM Check if cl.exe is already in PATH (Developer Command Prompt)
if !VSTOOLS_FOUND! == 0 (
    where cl >nul 2>&1
    if not errorlevel 1 (
        set "VSTOOLS_FOUND=1"
        set "VSINSTALLDIR=Already in PATH"
    )
)

if !VSTOOLS_FOUND! == 0 (
    echo ERROR: Visual Studio Build Tools not found.
    echo Please install one of the following:
    echo   - Visual Studio 2019 or later with C++ build tools
    echo   - Visual Studio Build Tools 2019 or later
    echo   - Or run this script from a "Developer Command Prompt"
    echo.
    echo Download from: https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

echo Found Visual Studio at: !VSINSTALLDIR!

REM Set up build environment - try multiple vcvars locations
set "VCVARS_FOUND=0"

REM Check if cl.exe is already available (Developer Command Prompt case)
where cl >nul 2>&1
if not errorlevel 1 (
    set "VCVARS_FOUND=1"
    echo   [OK] cl.exe already available in PATH
) else (
    REM Try vcvars64.bat first
    if "!VSINSTALLDIR!" neq "Already in PATH" (
        if exist "!VSINSTALLDIR!\VC\Auxiliary\Build\vcvars64.bat" (
            call "!VSINSTALLDIR!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
            if not errorlevel 1 (
                set "VCVARS_FOUND=1"
                echo   [OK] Visual Studio 64-bit environment set up
            )
        )
    )

    REM If vcvars64 failed, try vcvarsall.bat x64
    if !VCVARS_FOUND! == 0 (
        if "!VSINSTALLDIR!" neq "Already in PATH" (
            if exist "!VSINSTALLDIR!\VC\Auxiliary\Build\vcvarsall.bat" (
                call "!VSINSTALLDIR!\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
                if not errorlevel 1 (
                    set "VCVARS_FOUND=1"
                    echo   [OK] Visual Studio environment set up via vcvarsall.bat
                )
            )
        )
    )
)

if !VCVARS_FOUND! == 0 (
    echo ERROR: Failed to set up Visual Studio environment
    echo.
    echo Troubleshooting steps:
    echo 1. Make sure Visual Studio 2019 or later is installed with C++ tools
    echo 2. Try running this script from a "Developer Command Prompt"
    echo 3. Or manually run vcvarsall.bat before running this script
    echo.
    pause
    exit /b 1
)

REM Check for required headers
echo Checking for required dependencies...

REM Check for Windows SDK (should be available with VS)
set "SDK_FOUND=0"
if exist "%WindowsSdkDir%Include" (
    set "SDK_FOUND=1"
    echo   [OK] Windows SDK found
) else (
    echo   [ERROR] Windows SDK not found
)

REM Check for TPM Base Services
set "TBS_FOUND=0"
REM Try common Windows SDK version paths for tbs.h
if defined WindowsSdkDir (
    for /d %%d in ("%WindowsSdkDir%Include\*") do (
        if exist "%%d\um\tbs.h" (
            set "TBS_FOUND=1"
            goto :tbs_found
        )
    )
)
:tbs_found

REM Fallback: assume TBS is available if we found Windows SDK
if !TBS_FOUND! == 0 (
    if !SDK_FOUND! == 1 (
        set "TBS_FOUND=1"
        echo   [INFO] Assuming TBS headers are available with Windows SDK
    )
)

if !TBS_FOUND! == 1 (
    echo   [OK] TPM Base Services headers found
) else (
    echo   [WARN] TPM Base Services headers not found
)

if !SDK_FOUND! == 0 (
    echo.
    echo ERROR: Windows SDK is required for compilation.
    echo Please install Windows 10/11 SDK via Visual Studio Installer.
    pause
    exit /b 1
)

if !TBS_FOUND! == 0 (
    echo.
    echo WARNING: TPM Base Services headers not found.
    echo TPM functionality may not work properly.
    echo Consider installing a newer Windows SDK.
    echo.
)

REM Check if source file exists
if not exist "hard-sigs.c" (
    echo ERROR: Source file 'hard-sigs.c' not found in current directory.
    pause
    exit /b 1
)

echo.
echo Compiling hard-sigs.c...

REM Compile the program
cl /nologo /W3 /O2 /D_CRT_SECURE_NO_WARNINGS /DHAVE_SMARTCARD hard-sigs.c /Fe:hard-sigs.exe ^
   kernel32.lib user32.lib advapi32.lib tbs.lib crypt32.lib winscard.lib

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed.
    echo.
    echo Common issues:
    echo   - Missing Windows SDK components
    echo   - Incompatible Visual Studio version
    echo   - Missing TPM libraries (tbs.lib)
    echo.
    echo Try installing the latest Windows SDK or updating Visual Studio.
    pause
    exit /b 1
)

REM Clean up object files
if exist "hard-sigs.obj" del "hard-sigs.obj"

echo.
echo [SUCCESS] Compilation successful!
echo Created: hard-sigs.exe

REM Test the executable
if exist "hard-sigs.exe" (
    echo.
    echo Testing executable...
    hard-sigs.exe --help >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Executable test failed. Program may have runtime dependencies.
    ) else (
        echo [OK] Executable test passed
    )
)

echo.
echo Build complete. You can now run: hard-sigs.exe --help
pause