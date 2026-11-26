@echo off
title CyberScan AI
cd /d "%~dp0"
where node >nul 2>nul || (echo Installez Node.js depuis https://nodejs.org puis relancez. & pause & exit /b 1)
if not exist node_modules (
  echo Installation des dependances...
  call npm install || (pause & exit /b 1)
)
start "" http://localhost:8080
call npm run dev -- --port 8080
pause
