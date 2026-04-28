@echo off
setlocal

set "IMAGE_NAME=attack-surface-mapper-scanner"
set "WORKSPACE=%~dp0.."
set "DOCKER_EXE=C:\Program Files\Docker\Docker\resources\bin\docker.exe"

if not exist "%DOCKER_EXE%" (
  set "DOCKER_EXE=docker"
)

"%DOCKER_EXE%" run --rm -v "%WORKSPACE%:/workspace" -w /workspace %IMAGE_NAME% python main.py %*

if errorlevel 1 exit /b %errorlevel%
