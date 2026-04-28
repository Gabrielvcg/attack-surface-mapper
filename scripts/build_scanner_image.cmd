@echo off
setlocal

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_scanner_image.ps1" %*

if errorlevel 1 exit /b %errorlevel%
