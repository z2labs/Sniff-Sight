@echo off
rem One-click launcher: scripts\start.bat [--demo] [sniff_sight options...]
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
