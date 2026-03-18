@echo off
echo ============================================
echo  CyberGuard ML - Setup Script (Windows)
echo ============================================

echo.
echo [1/3] Training ML Model...
cd ml_model
pip install scikit-learn numpy pandas
python train_model.py
cd ..

echo.
echo [2/3] Installing Backend dependencies...
cd backend
pip install flask flask-cors scikit-learn numpy pandas
cd ..

echo.
echo [3/3] Installing Frontend dependencies...
cd frontend
npm install
cd ..

echo.
echo ============================================
echo  Setup Complete!
echo  Run: run_backend.bat  (in one terminal)
echo  Run: run_frontend.bat (in another terminal)
echo  Open: http://localhost:3000
echo  Login: admin / admin123
echo ============================================
pause
