@echo off

echo ==========================================
echo Insurance Platform - Database Seeding
echo ==========================================

echo.

REM Navigate to backend
cd backend-api

IF NOT EXIST node_modules (
    echo Installing dependencies...
    call npm install
)

echo.
echo Step 1: Seeding Roles...
node src/seed/roles.seed.js

IF %ERRORLEVEL% NEQ 0 (
    echo Roles seeding failed
    pause
    exit /b
)

echo.
echo Step 2: Seeding Users...
node src/seed/users.seed.js

IF %ERRORLEVEL% NEQ 0 (
    echo Users seeding failed
    pause
    exit /b
)

echo.
echo ==========================================
echo Seeding completed successfully
echo ==========================================

pause