#!/bin/bash

echo "=========================================="
echo " Insurance Platform Startup"
echo "=========================================="
echo ""

# --- CHECK NODE ---
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: Node.js is not installed or not in PATH"
  exit 1
fi

echo "Node.js detected."
echo ""

# --- START BACKEND ---
echo "Starting Backend API..."
cd backend-api || exit

if [ ! -d "node_modules" ]; then
  echo "Installing backend dependencies..."
  npm install
fi

echo "Launching backend (HTTPS)..."
npm run dev &
BACKEND_PID=$!

cd ..

# --- START FRONTEND ---
echo "Starting Frontend Web..."
cd frontend-web || exit

if [ ! -d "node_modules" ]; then
  echo "Installing frontend dependencies..."
  npm install
fi

echo "Launching frontend..."
npm run dev &
FRONTEND_PID=$!

cd ..

echo ""
echo "=========================================="
echo " Platform is starting..."
echo " Backend:  https://localhost:5001"
echo " Frontend: http://localhost:3000"
echo "=========================================="
echo ""

# --- HANDLE CTRL+C CLEANUP ---
trap "echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID; exit" INT

# Wait for processes
wait