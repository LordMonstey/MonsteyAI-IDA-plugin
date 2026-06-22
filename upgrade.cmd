@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0upgrade.ps1" %*
