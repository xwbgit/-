@echo off
chcp 65001 >nul
title DAS-SentinelAgent
echo ======================================================================
echo DAS-SentinelAgent
echo ======================================================================
echo.
echo [1/2] Checking Python dependencies...
python -m pip install -r requirements.txt -q

echo.
echo [2/2] Starting DAS-SentinelAgent (real-target mode)...
echo Web Dashboard: http://127.0.0.1:8000
echo Built-in Lab:  disabled by default (set ENABLE_BUILTIN_LAB=true for local regression)
echo.
python run.py
pause
