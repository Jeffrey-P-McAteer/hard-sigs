@echo off
setlocal enabledelayedexpansion

echo Building hard-sigs for Windows...
echo.

REM Check for Visual Studio Build Tools or Visual Studio
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSTOOLS_FOUND=0"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VSINSTALLDIR=%%i"
        set "VSTOOLS_FOUND=1"
    )
)

if !VSTOOLS_FOUND! == 0 (
    echo ERROR: Visual Studio Build Tools not found.
    echo Please install one of the following:
    echo   - Visual Studio 2019 or later with C++ build tools
    echo   - Visual Studio Build Tools 2019 or later
    echo   - Windows SDK
    echo.
    echo Download from: https://visualstudio.microsoft.com/downloads/
    pause
    exit /b 1
)

echo Found Visual Studio at: !VSINSTALLDIR!

REM Set up build environment
call "!VSINSTALLDIR!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo ERROR: Failed to set up Visual Studio environment
    pause
    exit /b 1
)

REM Check for required headers
echo Checking for required dependencies...

REM Check for Windows SDK (should be available with VS)
set "SDK_FOUND=0"
if exist "%WindowsSdkDir%Include" (
    set "SDK_FOUND=1"
    echo   ✓ Windows SDK found
) else (
    echo   ✗ Windows SDK not found
)

REM Check for TPM Base Services
set "TBS_FOUND=0"
if exist "%WindowsSdkDir%Include\*\um\tbs.h" (
    set "TBS_FOUND=1"
    echo   ✓ TPM Base Services (TBS) headers found
) else (
    echo   ✗ TPM Base Services headers not found
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
echo ✓ Compilation successful!
echo Created: hard-sigs.exe

REM Test the executable
if exist "hard-sigs.exe" (
    echo.
    echo Testing executable...
    hard-sigs.exe --help >nul 2>&1
    if errorlevel 1 (
        echo WARNING: Executable test failed. Program may have runtime dependencies.
    ) else (
        echo ✓ Executable test passed
    )
)

echo.
echo Build complete. You can now run: hard-sigs.exe --help
pause