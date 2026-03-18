#!/bin/bash
set -e

echo "============================================================"
echo "  CyberGuard ML - Malware Detection System"
echo "  Full Stack: React + Flask + Random Forest + SQLite"
echo "============================================================"
echo ""

# Step 1: Train model if not trained
if [ ! -f "ml_model/random_forest_model.pkl" ]; then
    echo "[1/3] Training Random Forest model..."
    cd ml_model
    pip install scikit-learn numpy pandas -q
    python train_model.py
    cd ..
    echo ""
else
    echo "[1/3] ML model already trained. Skipping..."
fi

# Step 2: Install backend deps & start Flask
echo "[2/3] Starting Flask backend on http://localhost:5000 ..."
cd backend
pip install flask flask-cors scikit-learn numpy pandas -q
python app.py &
FLASK_PID=$!
cd ..
echo "      Flask PID: $FLASK_PID"
sleep 2

# Step 3: Install frontend deps & start React
echo "[3/3] Starting React frontend on http://localhost:3000 ..."
cd frontend
npm install --silent
npm start &
REACT_PID=$!
cd ..

echo ""
echo "============================================================"
echo "  ✅ System running!"
echo "  Frontend : http://localhost:3000"
echo "  Backend  : http://localhost:5000"
echo "  Login    : admin / admin123"
echo "  Press Ctrl+C to stop all services"
echo "============================================================"

# Wait and cleanup on exit
trap "kill $FLASK_PID $REACT_PID 2>/dev/null; echo 'Services stopped.'" EXIT
wait
