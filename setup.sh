#!/bin/bash
echo "============================================"
echo " CyberGuard ML - Setup Script (Linux/Mac)"
echo "============================================"

echo ""
echo "[1/3] Training ML Model..."
cd ml_model
pip3 install scikit-learn numpy pandas
python3 train_model.py
cd ..

echo ""
echo "[2/3] Installing Backend dependencies..."
cd backend
pip3 install flask flask-cors scikit-learn numpy pandas
cd ..

echo ""
echo "[3/3] Installing Frontend dependencies..."
cd frontend
npm install
cd ..

echo ""
echo "============================================"
echo " Setup Complete!"
echo " Run: ./run_backend.sh   (terminal 1)"
echo " Run: ./run_frontend.sh  (terminal 2)"
echo " Open: http://localhost:3000"
echo " Login: admin / admin123"
echo "============================================"
