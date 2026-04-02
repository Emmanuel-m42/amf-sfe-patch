@echo off
REM Build AMF SFE Patcher tools
REM Run from a Visual Studio Developer Command Prompt, or use MinGW

where cl >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Building with MSVC...
    cl /O2 /W4 amf-sfe-patch.c /Fe:amf-sfe-patch.exe
    cl /O2 /W4 amf-sfe-launch.c /Fe:amf-sfe-launch.exe advapi32.lib psapi.lib
) else (
    where gcc >nul 2>&1
    if %ERRORLEVEL% == 0 (
        echo Building with MinGW...
        gcc -O2 -Wall -o amf-sfe-patch.exe amf-sfe-patch.c
        gcc -O2 -Wall -o amf-sfe-launch.exe amf-sfe-launch.c -lpsapi
    ) else (
        echo Error: No compiler found. Install MSVC or MinGW.
        exit /b 1
    )
)

echo Done.
