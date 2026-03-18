@echo off
title CyberGuard ML - Cyber Attack Prediction System

echo ============================================================
echo   CyberGuard ML - Malware Detection System
echo   Full Stack: React + Flask + Random Forest + SQLite
echo ============================================================
echo.

REM Step 1: Train model if not already trained
if not exist "ml_model\random_forest_model.pkl" (
    echo [1/3] Training Random Forest model...
    cd ml_model
    pip install scikit-learn numpy pandas -q
    python train_model.py
    cd ..
    echo.
) else (
    echo [1/3] ML model already trained. Skipping...
)

REM Step 2: Start Flask backend
echo [2/3] Starting Flask backend on http://localhost:5000 ...
cd backend
pip install flask flask-cors scikit-learn numpy pandas -q
start "Flask Backend" cmd /k "python app.py"
cd ..
echo.
timeout /t 3 /nobreak >nul

REM Step 3: Start React frontend
echo [3/3] Starting React frontend on http://localhost:3000 ...
cd frontend
call npm install --silent
start "React Frontend" cmd /k "npm start"
cd ..

echo.
echo ============================================================
echo   System is starting up...
echo   Frontend : http://localhost:3000
echo   Backend  : http://localhost:5000
echo   Login    : admin / admin123
echo ============================================================
pause
