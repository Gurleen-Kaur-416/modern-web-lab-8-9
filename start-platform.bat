@echo off

echo ==========================================
echo Insurance Platform Startup
echo ==========================================
echo.

REM --- CHECK NODE ---
where node >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Node.js is not installed or not in PATH
    pause
    exit /b
)

echo Node.js detected.
echo.

REM --- START BACKEND ---
echo Starting Backend API...
cd backend-api

IF NOT EXIST node_modules (
    echo Installing backend dependencies...
    call npm install
)

echo Launching backend (HTTPS)...
start cmd /k "npm run dev"

cd ..

REM --- START FRONTEND ---
echo Starting Frontend Web...
cd frontend-web

IF NOT EXIST node_modules (
    echo Installing frontend dependencies...
    call npm install
)

echo Launching frontend...
start cmd /k "npm run dev"

cd ..

echo.
echo ==========================================
echo Platform is starting...
echo Backend:  https://localhost:5001
echo Frontend: http://localhost:3000
echo ==========================================
echo.

pause