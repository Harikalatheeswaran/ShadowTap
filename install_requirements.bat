@echo off
REM =============================================
REM ShadowTap Setup Script
REM =============================================
REM This batch file will install all required Python modules for ShadowTap.
REM Run this file by double-clicking or from the command prompt.
REM Make sure you have Python and pip installed and available in PATH.

REM Install required modules
pip install scapy rich keyboard

REM Optional: Add more modules below if needed
REM pip install <other-module>

REM =============================================
REM Setup complete!
REM =============================================
echo.
echo All required Python modules for ShadowTap have been installed.
echo If you see errors, please check your Python and pip installation.
pause
